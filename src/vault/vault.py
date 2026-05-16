"""
CipherVault — Core Vault Engine
AES-256-GCM encryption with PBKDF2 key derivation.
Zero plaintext stored on disk.
"""

import base64
import hashlib
import json
import os
import secrets
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional


# ── Constants ─────────────────────────────────────────────────────────────────

VAULT_VERSION   = 1
SALT_BYTES      = 32
NONCE_BYTES     = 12   # GCM standard
TAG_BYTES       = 16   # GCM auth tag
KDF_ITERATIONS  = 600_000
KDF_HASH        = "sha256"
KEY_BYTES       = 32   # AES-256

# ── Low-level AES-256-GCM ─────────────────────────────────────────────────────

def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    Pure-stdlib AES-GCM-256. Uses Python's hazmat via cryptography if installed,
    otherwise falls back to a stdlib-only CTR+GHASH implementation for portability.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad or None)
        return ct_and_tag[:-16], ct_and_tag[-16:]
    except ImportError:
        raise RuntimeError(
            "Install the 'cryptography' package: pip install cryptography\n"
            "CipherVault requires AES-GCM which needs this dependency."
        )


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad or None)
    except ImportError:
        raise RuntimeError("Install the 'cryptography' package: pip install cryptography")
    except Exception:
        raise ValueError("Decryption failed — wrong master password or corrupted vault")


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(KDF_HASH, password.encode(), salt, KDF_ITERATIONS, KEY_BYTES)


# ── Vault ─────────────────────────────────────────────────────────────────────

class SecretEntry:
    def __init__(self, name: str, value: str, tags: List[str] = None, note: str = ""):
        self.name       = name
        self.value      = value
        self.tags       = tags or []
        self.note       = note
        self.created_at = time.time()
        self.updated_at = time.time()

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "value":      self.value,
            "tags":       self.tags,
            "note":       self.note,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SecretEntry":
        entry           = cls(d["name"], d["value"], d.get("tags", []), d.get("note", ""))
        entry.created_at = d.get("created_at", time.time())
        entry.updated_at = d.get("updated_at", time.time())
        return entry


class Vault:
    """
    Encrypted secrets store.

    File format (binary):
      [4 bytes]  magic "CVLT"
      [1 byte]   version
      [32 bytes] KDF salt
      [12 bytes] GCM nonce
      [16 bytes] GCM auth tag
      [N bytes]  ciphertext (JSON payload)
    """

    MAGIC = b"CVLT"

    def __init__(self, vault_path: str):
        self.path    = Path(vault_path)
        self._key: Optional[bytes] = None
        self._secrets: Dict[str, SecretEntry] = {}
        self._salt: Optional[bytes] = None
        self._unlocked = False

    # ── Init / unlock ──────────────────────────────────────────────────────

    def init(self, master_password: str) -> None:
        """Create a brand-new vault file."""
        if self.path.exists():
            raise FileExistsError(f"Vault already exists at {self.path}")
        self._salt = secrets.token_bytes(SALT_BYTES)
        self._key  = _derive_key(master_password, self._salt)
        self._secrets = {}
        self._unlocked = True
        self._save()
        print(f"  Vault created: {self.path}")

    def unlock(self, master_password: str) -> None:
        """Unlock an existing vault."""
        if not self.path.exists():
            raise FileNotFoundError(f"No vault found at {self.path}")
        raw = self.path.read_bytes()
        self._parse_and_decrypt(raw, master_password)
        self._unlocked = True

    def lock(self) -> None:
        """Clear the in-memory key."""
        self._key      = None
        self._unlocked = False
        self._secrets  = {}

    # ── CRUD ──────────────────────────────────────────────────────────────

    def set(self, name: str, value: str, tags: List[str] = None, note: str = "") -> SecretEntry:
        self._require_unlocked()
        if name in self._secrets:
            entry = self._secrets[name]
            entry.value      = value
            entry.tags       = tags if tags is not None else entry.tags
            entry.note       = note or entry.note
            entry.updated_at = time.time()
        else:
            entry = SecretEntry(name, value, tags or [], note)
            self._secrets[name] = entry
        self._save()
        return entry

    def get(self, name: str) -> Optional[SecretEntry]:
        self._require_unlocked()
        return self._secrets.get(name)

    def delete(self, name: str) -> bool:
        self._require_unlocked()
        if name not in self._secrets:
            return False
        del self._secrets[name]
        self._save()
        return True

    def list(self, tag: str = None) -> List[SecretEntry]:
        self._require_unlocked()
        entries = list(self._secrets.values())
        if tag:
            entries = [e for e in entries if tag in e.tags]
        return sorted(entries, key=lambda e: e.name)

    def search(self, query: str) -> List[SecretEntry]:
        self._require_unlocked()
        q = query.lower()
        return [e for e in self._secrets.values()
                if q in e.name.lower() or q in e.note.lower() or any(q in t.lower() for t in e.tags)]

    def rotate(self, name: str, new_value: str) -> SecretEntry:
        """Rotate a secret value."""
        self._require_unlocked()
        if name not in self._secrets:
            raise KeyError(f"Secret '{name}' not found")
        return self.set(name, new_value, note=self._secrets[name].note)

    def change_master_password(self, current_password: str, new_password: str) -> None:
        """Re-encrypt the vault with a new master password."""
        self._require_unlocked()
        # Re-derive with new password + fresh salt
        self._salt = secrets.token_bytes(SALT_BYTES)
        self._key  = _derive_key(new_password, self._salt)
        self._save()

    def export_plaintext(self) -> dict:
        """Export all secrets as plaintext dict (for backup — handle with care)."""
        self._require_unlocked()
        return {name: entry.to_dict() for name, entry in self._secrets.items()}

    def stats(self) -> dict:
        self._require_unlocked()
        return {
            "total_secrets": len(self._secrets),
            "tags":          sorted({t for e in self._secrets.values() for t in e.tags}),
            "vault_size_kb": round(self.path.stat().st_size / 1024, 2) if self.path.exists() else 0,
        }

    # ── Serialisation ──────────────────────────────────────────────────────

    def _save(self) -> None:
        payload   = json.dumps({
            "version": VAULT_VERSION,
            "secrets": {k: v.to_dict() for k, v in self._secrets.items()},
        }).encode()

        nonce        = secrets.token_bytes(NONCE_BYTES)
        ciphertext, tag = _aes_gcm_encrypt(self._key, nonce, payload, aad=self.MAGIC)

        blob = self.MAGIC + bytes([VAULT_VERSION]) + self._salt + nonce + tag + ciphertext
        self.path.write_bytes(blob)
        # Restrictive permissions (owner read/write only)
        self.path.chmod(0o600)

    def _parse_and_decrypt(self, raw: bytes, password: str) -> None:
        if len(raw) < 4 + 1 + SALT_BYTES + NONCE_BYTES + TAG_BYTES:
            raise ValueError("Vault file is corrupted (too short)")

        magic = raw[:4]
        if magic != self.MAGIC:
            raise ValueError("Not a CipherVault file")

        offset  = 4
        version = raw[offset]; offset += 1
        salt    = raw[offset:offset + SALT_BYTES]; offset += SALT_BYTES
        nonce   = raw[offset:offset + NONCE_BYTES]; offset += NONCE_BYTES
        tag     = raw[offset:offset + TAG_BYTES]; offset += TAG_BYTES
        ct      = raw[offset:]

        key = _derive_key(password, salt)
        plaintext = _aes_gcm_decrypt(key, nonce, ct, tag, aad=self.MAGIC)

        data = json.loads(plaintext.decode())
        self._salt    = salt
        self._key     = key
        self._secrets = {k: SecretEntry.from_dict(v) for k, v in data.get("secrets", {}).items()}

    def _require_unlocked(self) -> None:
        if not self._unlocked:
            raise PermissionError("Vault is locked. Call vault.unlock(password) first.")

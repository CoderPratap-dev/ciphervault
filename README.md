# CipherVault

> End-to-end encrypted secrets manager with AES-256-GCM, PBKDF2 key derivation, and a zero-knowledge design. No plaintext ever touches disk.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square)
![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-encrypted-00f5ff?style=flat-square)
![Zero Knowledge](https://img.shields.io/badge/design-zero--knowledge-ff00aa?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Features

- **AES-256-GCM encryption** — authenticated encryption with tamper detection
- **PBKDF2 key derivation** — 600,000 iterations, random 32-byte salt per vault
- **Zero-knowledge** — master password never stored; wrong password = decryption failure
- **CLI-first** — full-featured terminal interface with colour output
- **Secret rotation** — generate new values and overwrite in one command
- **Tagging + search** — organise and find secrets by name, tag, or note
- **Pipe-friendly** — `--raw` flag outputs value only, perfect for scripts

---

## Installation

```bash
git clone https://github.com/CoderPratap-dev/ciphervault.git
cd ciphervault
pip install -r requirements.txt
```

---

## Quick Start

```bash
# 1. Create your vault
python cli.py init

# 2. Store a secret
python cli.py set db/prod/password
# (prompted securely — no shell history)

# 3. Retrieve it
python cli.py get db/prod/password

# 4. List all secrets
python cli.py list

# 5. Generate and store a random password
python cli.py set api/stripe --generate --length 32

# 6. Rotate a secret
python cli.py rotate db/prod/password
```

---

## All Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new encrypted vault |
| `set <name> [value]` | Store or update a secret |
| `get <name>` | Retrieve a secret |
| `delete <name>` | Delete a secret |
| `list [--tag TAG]` | List all secrets, optionally filtered by tag |
| `search <query>` | Search by name, note, or tag |
| `rotate <name>` | Replace value with a generated password |
| `stats` | Show vault statistics |
| `generate` | Generate a password without storing it |

### Flags for `set`

| Flag | Description |
|------|-------------|
| `--generate` / `-g` | Auto-generate a random value |
| `--length N` / `-l N` | Length of generated value (default: 24) |
| `--no-symbols` | Alphanumeric only |
| `--tags TAG1,TAG2` | Comma-separated tags |
| `--note TEXT` | Optional note |

---

## Scripting / Piping

```bash
# Pipe the value directly into another command
DB_PASS=$(python cli.py get db/prod/password --raw)
psql "postgresql://admin:${DB_PASS}@localhost/mydb"

# Use a custom vault path
python cli.py --vault /path/to/team.cvlt list
```

---

## Vault File Format

```
[4 bytes]   Magic: "CVLT"
[1 byte]    Version
[32 bytes]  PBKDF2 salt  (random, unique per vault)
[12 bytes]  AES-GCM nonce (random per save)
[16 bytes]  AES-GCM auth tag
[N bytes]   Ciphertext (JSON payload)
```

The master password is **never** stored. A wrong password produces a GCM authentication failure before any plaintext is returned.

---

## Run Tests

```bash
python tests/test_vault.py
```

Expected output:
```
test_change_master_password ... ok
test_delete ... ok
test_delete_nonexistent ... ok
test_init_creates_file ... ok
...
Ran 12 tests in 3.4s — OK
```

---

## Project Structure

```
ciphervault/
├── src/
│   └── vault/
│       └── vault.py       # Core encryption engine
├── tests/
│   └── test_vault.py      # Full test suite
├── cli.py                 # Command-line interface
├── requirements.txt
└── README.md
```

---

## Security Notes

- The vault file is set to `chmod 600` (owner read/write only) on creation
- Master password is read via `getpass` — never echoed or stored in shell history
- All encryption uses authenticated AES-256-GCM — ciphertext tampering is detected
- PBKDF2 with 600,000 iterations makes brute-force attacks computationally expensive
- **There is no password recovery.** Keep your master password safe.

---

## License

MIT

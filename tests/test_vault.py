"""
CipherVault — Test Suite
Run: python tests/test_vault.py
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.vault.vault import Vault

MASTER_PW = "SuperSecretMasterPassword123!"


class TestVault(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path   = os.path.join(self.tmpdir, "test.cvlt")
        self.vault  = Vault(self.path)
        self.vault.init(MASTER_PW)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_init_creates_file(self):
        self.assertTrue(Path(self.path).exists())

    def test_unlock_correct_password(self):
        v = Vault(self.path)
        v.unlock(MASTER_PW)  # Should not raise

    def test_unlock_wrong_password(self):
        v = Vault(self.path)
        with self.assertRaises(ValueError):
            v.unlock("wrong-password")

    def test_set_and_get(self):
        self.vault.set("db/password", "hunter2", tags=["db", "prod"])
        entry = self.vault.get("db/password")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.value, "hunter2")
        self.assertIn("db", entry.tags)

    def test_persist_across_unlock(self):
        self.vault.set("api/key", "sk-secret-123")
        self.vault.lock()

        v2 = Vault(self.path)
        v2.unlock(MASTER_PW)
        entry = v2.get("api/key")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.value, "sk-secret-123")

    def test_delete(self):
        self.vault.set("temp/token", "abc")
        self.assertTrue(self.vault.delete("temp/token"))
        self.assertIsNone(self.vault.get("temp/token"))

    def test_delete_nonexistent(self):
        self.assertFalse(self.vault.delete("does/not/exist"))

    def test_list(self):
        self.vault.set("a", "1", tags=["prod"])
        self.vault.set("b", "2", tags=["dev"])
        self.vault.set("c", "3", tags=["prod"])

        all_entries = self.vault.list()
        self.assertEqual(len(all_entries), 3)

        prod = self.vault.list(tag="prod")
        self.assertEqual(len(prod), 2)

    def test_search(self):
        self.vault.set("db/prod/password", "secret", note="main db")
        self.vault.set("api/stripe", "sk_live_xxx")
        results = self.vault.search("db")
        self.assertEqual(len(results), 1)

    def test_rotate(self):
        self.vault.set("service/token", "old-value")
        self.vault.rotate("service/token", "new-value")
        entry = self.vault.get("service/token")
        self.assertEqual(entry.value, "new-value")

    def test_stats(self):
        self.vault.set("x", "1")
        self.vault.set("y", "2", tags=["test"])
        s = self.vault.stats()
        self.assertEqual(s["total_secrets"], 2)
        self.assertIn("test", s["tags"])

    def test_locked_raises(self):
        self.vault.lock()
        with self.assertRaises(PermissionError):
            self.vault.get("anything")

    def test_change_master_password(self):
        self.vault.set("key", "value")
        self.vault.change_master_password(MASTER_PW, "NewPassword456!")
        self.vault.lock()

        v2 = Vault(self.path)
        with self.assertRaises(ValueError):
            v2.unlock(MASTER_PW)  # old password should fail

        v3 = Vault(self.path)
        v3.unlock("NewPassword456!")
        self.assertEqual(v3.get("key").value, "value")


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Pure-source/Windows refusal plus real Linux temp-directory durability cases.

Run directly with python3 -B; never imports the AP engine or production ROOT.
Windows cannot qualify POSIX fsync/flock and explicitly skips those cases.
"""
import ast
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "runtime/native_files.py"
spec = importlib.util.spec_from_file_location("public_beta_native_files", SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
LINUX = sys.platform == "linux" and os.name == "posix"


class SourceBoundary(unittest.TestCase):
    def test_fixed_constructor_has_no_paths_or_implicit_initialize(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        owner = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                     and n.name == "NativeFiles")
        constructor = next(n for n in owner.body if isinstance(n, ast.FunctionDef)
                           and n.name == "__init__")
        self.assertEqual([a.arg for a in constructor.args.args], ["self"])
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                             and n.func.attr == "initialize" for n in ast.walk(constructor)))
        self.assertEqual(native.ROOT, Path("/home/container/.amz"))
        self.assertEqual((native.JOURNAL, native.CONTROL, native.ACK, native.LOCK),
                         ("public-gateway-journal.json", "public-gateway-control.json",
                          "public-gateway-ack.json", "public-gateway-native.lock"))

    def test_actual_platform_refusal_precedes_filesystem_access(self):
        if LINUX:
            self.skipTest("Windows-only refusal is not a Linux durability check")
        with patch.object(native.os, "open", side_effect=AssertionError("must not touch files")):
            with self.assertRaisesRegex(native.NativeFilesError, "linux_required"):
                native.NativeFiles()

    def test_canonical_parser_rejects_duplicate_trailing_noncanonical_and_unsafe_values(self):
        self.assertEqual(native._decode(b'{"a":1,"b":"ok"}', 1024), {"a": 1, "b": "ok"})
        for raw in (b'{"a":1,"a":2}', b'{}{}', b'{ "a":1}', b'{"a":NaN}',
                    b'{"a":1.0}', b'{"a":9007199254740992}', b'[]', b'\xef\xbb\xbf{}'):
            with self.subTest(raw=raw), self.assertRaises(native.NativeFilesError):
                native._decode(raw, 1024)


@unittest.skipUnless(LINUX, "requires actual Linux/POSIX fsync, no Windows emulation")
class LinuxFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="amz-native-files-source-")
        self.root = Path(self.temporary.name) / ".amz"
        self.root.mkdir(mode=0o700)
        self.root_patch = patch.object(native, "ROOT", self.root)
        self.root_patch.start()
        self.files = None

    def tearDown(self):
        if self.files and not self.files._closed:
            try:
                self.files.close()
            except (native.NativeFilesError, OSError):
                pass
        self.root_patch.stop()
        self.temporary.cleanup()

    def owner(self, initialized=True):
        self.files = native.NativeFiles()
        if initialized:
            self.files.initialize({"revision": 1})
        return self.files

    def put(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def test_constructor_never_bootstraps_missing_journal(self):
        files = self.owner(False)
        self.assertFalse((self.root / native.JOURNAL).exists())
        with self.assertRaisesRegex(native.NativeFilesError, "journal_missing"):
            files.load_journal()
        with self.assertRaisesRegex(native.NativeFilesError, "journal_missing"):
            files.commit_journal({"revision": 2})
        files.close()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_explicit_initialize_and_restart_requires_new_durable_commit_before_ack(self):
        files = self.owner()
        self.assertEqual(files.load_journal(), {"revision": 1})
        files.publish_ack({"accepted": True})
        files.close()
        files = self.owner(False)
        self.assertEqual(files.load_journal(), {"revision": 1})
        with self.assertRaisesRegex(native.NativeFilesError, "commit_required"):
            files.publish_ack({"accepted": True})
        files.commit_journal({"revision": 2})
        files.publish_ack({"accepted": True, "revision": 2})
        self.assertEqual((self.root / native.ACK).read_bytes(), b'{"accepted":true,"revision":2}')
        for name in (native.JOURNAL, native.ACK, native.LOCK):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)

    def test_control_optional_then_strict_and_bounded(self):
        files = self.owner()
        self.assertIsNone(files.read_control())
        self.put(native.CONTROL, b'{"command":"hold"}')
        self.assertEqual(files.read_control(), {"command": "hold"})
        for raw in (b'{"x":1,"x":2}', b'{}\n', b'{}{}', b'{"x":NaN}', b'x' * 65537):
            self.put(native.CONTROL, raw)
            with self.subTest(size=len(raw)), self.assertRaises(native.NativeFilesError):
                files.read_control()

    def test_symlink_hardlink_and_wrong_mode_are_refused_without_replacing_target(self):
        files = self.owner()
        target = self.put("foreign.json", b'{}')
        control = self.root / native.CONTROL
        control.symlink_to(target)
        with self.assertRaises(native.NativeFilesError):
            files.read_control()
        control.unlink()
        os.link(target, control)
        with self.assertRaises(native.NativeFilesError):
            files.read_control()
        control.unlink()
        control.write_bytes(b'{}')
        control.chmod(0o644)
        with self.assertRaises(native.NativeFilesError):
            files.read_control()
        self.assertEqual(target.read_bytes(), b'{}')

    def test_existing_lock_and_pending_files_are_preserved(self):
        lock = self.put(native.LOCK, b'foreign-lock')
        with self.assertRaises(FileExistsError):
            self.owner(False)
        self.assertEqual(lock.read_bytes(), b'foreign-lock')
        lock.unlink()
        pending = self.put("." + native.JOURNAL + ".pending-owned-or-unknown", b'partial')
        with self.assertRaisesRegex(native.NativeFilesError, "pending_reconciliation"):
            self.owner(False)
        self.assertEqual(pending.read_bytes(), b'partial')
        self.assertFalse(lock.exists())

    def test_second_owner_cannot_acquire_live_lock(self):
        files = self.owner()
        with self.assertRaises(FileExistsError):
            native.NativeFiles()
        self.assertEqual(files.load_journal(), {"revision": 1})

    def test_replaced_lock_is_never_unlinked_by_close(self):
        files = self.owner()
        lock = self.root / native.LOCK
        lock.unlink()
        self.put(native.LOCK, b'foreign replacement')
        with self.assertRaisesRegex(native.NativeFilesError, "owner_changed"):
            files.close()
        self.assertEqual(lock.read_bytes(), b'foreign replacement')

    def test_wrong_root_permissions_and_symlink_root_are_refused(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(native.NativeFilesError, "root_permissions"):
            self.owner(False)
        self.root.chmod(0o700)
        alias = self.root.parent / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.object(native, "ROOT", alias), self.assertRaises(OSError):
            native.NativeFiles()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_existing_journal_cannot_be_overwritten_or_acknowledged(self):
        files = self.owner()
        self.put(native.JOURNAL, b'{broken')
        with self.assertRaises(native.NativeFilesError):
            files.commit_journal({"revision": 2})
        with self.assertRaises(native.NativeFilesError):
            files.publish_ack({"accepted": True})
        self.assertEqual((self.root / native.JOURNAL).read_bytes(), b'{broken')
        self.assertFalse((self.root / native.ACK).exists())

    def test_actual_growth_read_is_bounded_and_not_only_stat_size(self):
        files = self.owner()
        control = self.put(native.CONTROL, b'{}')
        real_read = os.read
        seen = []
        def growing_read(fd, count):
            if not seen:
                with control.open("ab") as writer:
                    writer.write(b'x' * (native.MESSAGE_LIMIT + 1))
            seen.append(count)
            return real_read(fd, count)
        with patch.object(native.os, "read", side_effect=growing_read):
            with self.assertRaisesRegex(native.NativeFilesError, "file_limit"):
                files.read_control()
        self.assertEqual(sum(seen), native.MESSAGE_LIMIT + 1)

    def test_same_fd_metadata_change_during_read_is_refused(self):
        files = self.owner()
        control = self.put(native.CONTROL, b'{}')
        real_read = os.read
        changed = []
        def changed_read(fd, count):
            result = real_read(fd, count)
            if not changed:
                changed.append(True)
                info = control.stat()
                os.utime(control, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000))
            return result
        with patch.object(native.os, "read", side_effect=changed_read):
            with self.assertRaisesRegex(native.NativeFilesError, "file_changed"):
                files.read_control()

    def test_journal_file_and_directory_sync_finish_before_ack_rename(self):
        files = self.owner()
        real_sync, real_replace = os.fsync, os.replace
        events = []
        def sync(fd):
            events.append("directory-sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file-sync")
            return real_sync(fd)
        def replace(source, destination, **options):
            events.append(destination)
            return real_replace(source, destination, **options)
        with patch.object(native.os, "fsync", side_effect=sync), patch.object(native.os, "replace", side_effect=replace):
            files.commit_journal({"revision": 2})
            files.publish_ack({"accepted": True})
        self.assertEqual(events, ["file-sync", native.JOURNAL, "directory-sync",
                                  "file-sync", native.ACK, "directory-sync"])

    def test_failed_journal_sync_preserves_old_journal_pending_and_crash_lock(self):
        files = self.owner()
        real_sync = os.fsync
        def fail_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("synthetic fsync refusal")
            return real_sync(fd)
        with patch.object(native.os, "fsync", side_effect=fail_file):
            with self.assertRaises(OSError):
                files.commit_journal({"revision": 2})
        self.assertEqual((self.root / native.JOURNAL).read_bytes(), b'{"revision":1}')
        self.assertTrue(any(p.name.startswith("." + native.JOURNAL + ".pending-") for p in self.root.iterdir()))
        with self.assertRaises(native.NativeFilesError):
            files.publish_ack({"accepted": True})
        with self.assertRaises(native.NativeFilesError):
            files.close()
        self.assertTrue((self.root / native.LOCK).exists())

    def test_failed_ack_directory_sync_is_uncertain_not_success(self):
        files = self.owner()
        real_sync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("synthetic directory fsync refusal")
            return real_sync(fd)
        with patch.object(native.os, "fsync", side_effect=fail_directory):
            with self.assertRaises(OSError):
                files.publish_ack({"accepted": True})
        with self.assertRaises(native.NativeFilesError):
            files.read_control()
        with self.assertRaises(native.NativeFilesError):
            files.close()
        self.assertTrue((self.root / native.LOCK).exists())

    def test_explicit_initialize_refuses_existing_control_and_journal(self):
        files = self.owner(False)
        self.put(native.CONTROL, b'{}')
        with self.assertRaisesRegex(native.NativeFilesError, "initialize_conflict"):
            files.initialize({"revision": 1})
        self.assertFalse((self.root / native.JOURNAL).exists())
        (self.root / native.CONTROL).unlink()
        files.initialize({"revision": 1})
        with self.assertRaisesRegex(native.NativeFilesError, "initialize_conflict"):
            files.initialize({"revision": 2})


if __name__ == "__main__":
    unittest.main(verbosity=2)

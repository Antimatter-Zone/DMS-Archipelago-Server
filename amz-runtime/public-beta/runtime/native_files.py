"""Fixed private native gateway files; no engine imports or startup side effects.

The protected container UID/private directory is a required writer boundary.
The owner lock serializes cooperating native processes; it does not claim to
exclude arbitrary code already running as that UID. Crash locks and pending
files require protected reconciliation and are never automatically removed.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

ROOT = Path("/home/container/.amz")
JOURNAL = "public-gateway-journal.json"
CONTROL = "public-gateway-control.json"
ACK = "public-gateway-ack.json"
LOCK = "public-gateway-native.lock"
JOURNAL_LIMIT = 2 * 1024 * 1024
MESSAGE_LIMIT = 64 * 1024
_SAFE_INTEGER = 9007199254740991


class NativeFilesError(RuntimeError):
    """Sanitized refusal; callers must not turn it into a native proof."""


def _fail(code):
    raise NativeFilesError(code)


def _tree(value, depth=0):
    if depth > 64:
        _fail("native_json_depth")
    if value is None or type(value) in (bool, str):
        return
    if type(value) is int and abs(value) <= _SAFE_INTEGER:
        return
    if type(value) is list:
        for item in value:
            _tree(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _tree(item, depth + 1)
        return
    _fail("native_json_value")


def _canonical(value, maximum):
    if type(value) is not dict:
        _fail("native_json_object")
    _tree(value)
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False,
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        _fail("native_json_encoding")
    if not raw or len(raw) > maximum:
        _fail("native_file_limit")
    return raw


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("native_json_duplicate")
        result[key] = value
    return result


def _decode(raw, maximum):
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail("native_json_value"))
    except (ValueError, UnicodeError, RecursionError):
        _fail("native_json_encoding")
    if _canonical(value, maximum) != raw:
        _fail("native_json_noncanonical")
    return value


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class NativeFiles:
    """Linux-only durable fixed-file owner. Construction never creates a journal.

    initialize is a separate protected operation, never a constructor fallback.
    Every ACK requires this instance's successful journal commit. On uncertain
    writes, close preserves the owner lock and all pending evidence.
    """

    def __init__(self):
        if (sys.platform != "linux" or os.name != "posix" or fcntl is None
                or not all(hasattr(os, name) for name in
                           ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"))):
            _fail("native_files_linux_required")
        self._mutex = threading.RLock()
        self._root = Path(ROOT)
        self._directory = None
        self._lock = None
        self._lock_identity = None
        self._lock_bytes = None
        self._durable = None
        self._closed = False
        self._uncertain = False
        try:
            self._directory = self._open_root()
            self._reject_pending()
            self._lock = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                 dir_fd=self._directory)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_bytes = _canonical({"owner": uuid.uuid4().hex,
                                           "pid": os.getpid(),
                                           "schema": "amz.ap.public-beta.native-owner.v1"},
                                          MESSAGE_LIMIT)
            self._write_all(self._lock, self._lock_bytes)
            os.fsync(self._lock)
            self._lock_identity = self._regular(os.fstat(self._lock))
            os.fsync(self._directory)
            self._check_directory()
        except BaseException:
            # Even a partially written owner lock is evidence, not stale debris.
            if self._lock is not None:
                os.close(self._lock)
            if self._directory is not None:
                os.close(self._directory)
            self._closed = True
            raise

    def _open_root(self):
        if not self._root.is_absolute() or ".." in self._root.parts:
            _fail("native_root_rejected")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in self._root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                _fail("native_root_permissions")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _check_directory(self):
        current = self._open_root()
        try:
            a, b = os.fstat(current), os.fstat(self._directory)
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                _fail("native_root_changed")
        finally:
            os.close(current)

    def _regular(self, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            _fail("native_file_permissions")
        return _identity(info)

    def _entry(self, name):
        try:
            return os.stat(name, dir_fd=self._directory, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _reject_pending(self):
        prefixes = tuple("." + name + ".pending-" for name in (JOURNAL, ACK))
        with os.scandir(self._directory) as entries:
            for count, entry in enumerate(entries):
                if count >= 1024 or entry.name.startswith(prefixes):
                    _fail("native_pending_reconciliation_required")

    def _active(self):
        if self._closed or self._uncertain:
            _fail("native_files_closed_or_uncertain")
        self._check_directory()
        info = self._entry(LOCK)
        if info is None or self._regular(info) != self._lock_identity:
            _fail("native_owner_changed")
        if self._regular(os.fstat(self._lock)) != self._lock_identity:
            _fail("native_owner_changed")

    def _read(self, name, maximum, optional=False):
        before = self._entry(name)
        if before is None:
            if optional:
                return None
            _fail("native_journal_missing")
        before_identity = self._regular(before)
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                     | os.O_CLOEXEC, dir_fd=self._directory)
        try:
            if self._regular(os.fstat(fd)) != before_identity:
                _fail("native_file_changed")
            # Bound the actual read, not merely the attacker-changeable st_size.
            if before.st_size <= 0 or before.st_size > maximum:
                _fail("native_file_limit")
            raw = bytearray()
            while len(raw) <= maximum:
                part = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            if not raw or len(raw) > maximum:
                _fail("native_file_limit")
            after = self._entry(name)
            if (after is None or self._regular(after) != before_identity
                    or self._regular(os.fstat(fd)) != before_identity
                    or len(raw) != before.st_size):
                _fail("native_file_changed")
            self._check_directory()
            data = bytes(raw)
            return (_decode(data, maximum), before_identity,
                    hashlib.sha256(data).digest())
        finally:
            os.close(fd)

    @staticmethod
    def _write_all(fd, raw):
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if type(count) is not int or count <= 0 or count > len(view):
                _fail("native_write_incomplete")
            view = view[count:]

    def _replace(self, name, raw, maximum, expected):
        temporary = "." + name + ".pending-" + uuid.uuid4().hex
        fd = None
        try:
            self._active()
            current = self._read(name, maximum, optional=True)
            if current != expected:
                _fail("native_file_changed")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=self._directory)
            self._write_all(fd, raw)
            os.fsync(fd)
            pending_identity = self._regular(os.fstat(fd))
            self._active()
            if (self._regular(self._entry(temporary)) != pending_identity
                    or self._read(name, maximum, optional=True) != expected):
                _fail("native_file_changed")
            os.replace(temporary, name, src_dir_fd=self._directory,
                       dst_dir_fd=self._directory)
            # This directory fsync is required before any ACK publication.
            os.fsync(self._directory)
            self._active()
            result = self._read(name, maximum)
            if (result[1] != self._regular(os.fstat(fd))
                    or result[2] != hashlib.sha256(raw).digest()):
                _fail("native_file_changed")
            return result
        except BaseException:
            self._uncertain = True
            self._durable = None
            # Preserve exact pending/renamed state and owner lock for recovery.
            raise
        finally:
            if fd is not None:
                os.close(fd)

    def load_journal(self):
        with self._mutex:
            self._active()
            return self._read(JOURNAL, JOURNAL_LIMIT)[0]

    def initialize(self, state):
        raw = _canonical(state, JOURNAL_LIMIT)
        with self._mutex:
            self._active()
            if any(self._entry(name) is not None for name in (JOURNAL, CONTROL, ACK)):
                _fail("native_initialize_conflict")
            self._durable = self._replace(JOURNAL, raw, JOURNAL_LIMIT, None)

    def commit_journal(self, state):
        raw = _canonical(state, JOURNAL_LIMIT)
        with self._mutex:
            self._active()
            previous = self._read(JOURNAL, JOURNAL_LIMIT)
            self._durable = self._replace(JOURNAL, raw, JOURNAL_LIMIT, previous)

    def read_control(self):
        with self._mutex:
            self._active()
            result = self._read(CONTROL, MESSAGE_LIMIT, optional=True)
            return None if result is None else result[0]

    def publish_ack(self, acknowledgement):
        raw = _canonical(acknowledgement, MESSAGE_LIMIT)
        with self._mutex:
            self._active()
            if self._durable is None:
                _fail("native_journal_commit_required")
            if self._read(JOURNAL, JOURNAL_LIMIT) != self._durable:
                self._durable = None
                _fail("native_journal_changed")
            previous = self._read(ACK, MESSAGE_LIMIT, optional=True)
            self._replace(ACK, raw, MESSAGE_LIMIT, previous)

    def close(self):
        with self._mutex:
            if self._closed:
                return
            try:
                self._active()
                os.unlink(LOCK, dir_fd=self._directory)
                os.fsync(self._directory)
            finally:
                # On refusal/uncertainty the lock remains; no stale-lock cleanup.
                self._closed = True
                os.close(self._lock)
                os.close(self._directory)

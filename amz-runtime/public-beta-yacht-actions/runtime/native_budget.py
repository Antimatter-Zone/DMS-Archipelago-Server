"""Fixed native plaintext workspace budget, not an encrypted/physical permit.

All native publications reserve the entire new pending payload before opening
it, while old target bytes still count. Unknown state holds the native owner.
"""
import os
from pathlib import Path
import stat

AGGREGATE = 3 * 1024 * 1024
METADATA = 256 * 1024
SAVE = 'public-seed.apsave'
STATUS = 'public-runtime-status.json'
LOCK = 'public-gateway-native.lock'
EXTERNAL = frozenset(('public-gateway-control.json', 'public-yacht-effects-control.json', 'public-yacht-observation-control.json'))
CAPS = {'public-runtime.json': 16384, 'public-yacht-keys.json': 4096, 'public-seed.archipelago': 524288,
        SAVE: 524288, LOCK: 1024, 'public-gateway-journal.json': 524288, 'public-yacht-effects-journal.json': 524288,
        'public-yacht-observation-ack.json': 524288, 'public-gateway-ack.json': 65536, 'public-yacht-effects-ack.json': 65536,
        STATUS: 16384, **{name: 65536 for name in EXTERNAL}}
PUBLISH = frozenset(CAPS) - EXTERNAL - {'public-runtime.json', 'public-yacht-keys.json', 'public-seed.archipelago', LOCK}
# External cooperating writers must obey fixed64KiB payloads. Reserve their
# full current+pending maximum even when absent, not a racy instantaneous size.
EXTERNAL_RESERVE = sum(2 * CAPS[name] for name in EXTERNAL)


class BudgetRefused(RuntimeError):
    pass


def need(value):
    if not value: raise BudgetRefused('native_budget_held')


def plan(sizes, name, length, *, lock=False):
    """Pure arithmetic only. This result is not an admission/ownership proof."""
    need(type(sizes) is dict and all(k in CAPS and type(v) is int and 0 < v <= CAPS[k] for k, v in sizes.items()))
    need(name == LOCK if lock else name in PUBLISH)
    need(type(length) is int and 0 < length <= CAPS[name])
    current = sum(value for key, value in sizes.items() if key not in EXTERNAL)
    headroom = 0 if name == SAVE else CAPS[SAVE]
    total = METADATA + EXTERNAL_RESERVE + current + length + headroom
    need(total <= AGGREGATE)
    return total


class NativeBudget:
    """FD-root audit; binding publications additionally requires real NativeFiles.

    Non-Linux audit fixtures cannot bind a writer. No IO/platform callback can
    replace the Linux descriptor and exact owner type checks below.
    """
    def __init__(self, root):
        self.root, self.fd, self.owner = Path(root), None, None
        need(self.root.is_absolute() and self.root.resolve() == self.root)
        for parent in (self.root, *self.root.parents):
            info = parent.lstat(); need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
        info = self.root.stat(); self.identity = (info.st_dev, info.st_ino)
        try:
            if os.name == 'posix':
                need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
                self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                need(self.identity == (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino))
            self.audit()
        except BaseException:
            self.close(); raise

    def audit(self):
        info = self.root.lstat(); need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.identity)
        if self.fd is not None: need((os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino) == self.identity)
        sizes = {}
        with os.scandir(self.fd if self.fd is not None else self.root) as entries:
            for count, entry in enumerate(entries):
                need(count < len(CAPS) and entry.name in CAPS)
                # Windows DirEntry's cached stat omits link-count identity;
                # use full lstat there. Production Linux stays FD-relative.
                value = os.stat(entry.name, dir_fd=self.fd, follow_symlinks=False) if self.fd is not None else (self.root / entry.name).lstat()
                need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and 0 < value.st_size <= CAPS[entry.name])
                if self.fd is not None: need(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o600)
                sizes[entry.name] = value.st_size
        need(METADATA + EXTERNAL_RESERVE + sum(v for k, v in sizes.items() if k not in EXTERNAL) <= AGGREGATE)
        return sizes

    def reserve_lock(self):
        sizes = self.audit(); need(LOCK not in sizes)
        # Captured NativeFiles constructor writes only UUID/PID/fixed schema,
        # bounded here by1KiB, before any other publication is enabled.
        return plan(sizes, LOCK, CAPS[LOCK], lock=True)

    def held(self):
        if self.owner is not None:
            self.owner._uncertain, self.owner._durable = True, None

    def install(self, owner):
        from native_files import NativeFiles
        need(os.name == 'posix' and self.fd is not None and type(owner) is NativeFiles and self.owner is None)
        need((os.fstat(owner._directory).st_dev, os.fstat(owner._directory).st_ino) == self.identity)
        self.owner = owner
        try: self.audit(); owner._active()
        except BaseException: self.held(); raise
        original = owner._replace
        def replace(name, raw, maximum, expected):
            with owner._mutex:
                try:
                    owner._active(); need(type(raw) is bytes and name != SAVE)
                    plan(self.audit(), name, len(raw))  # BEFORE original's temp open.
                    result = original(name, raw, min(maximum, CAPS[name]), expected)
                    self.audit(); return result
                except BaseException: self.held(); raise
        owner._replace = replace

    def bind_save(self, save_files):
        owner = self.owner; need(owner is not None and save_files.owner is owner)
        original = save_files.write
        def write(raw):
            with owner._mutex:
                try:
                    owner._active(); need(type(raw) is bytes)
                    plan(self.audit(), SAVE, len(raw))  # Old save+new full temp.
                    result = original(raw)
                    self.audit(); return result
                except BaseException: self.held(); raise
        save_files.write = write

    def publish_status(self, value, canonical):
        owner = self.owner; need(owner is not None)
        with owner._mutex:
            try:
                owner._active(); raw = canonical(value)
                previous = owner._read(STATUS, CAPS[STATUS], optional=True)
                return owner._replace(STATUS, raw, CAPS[STATUS], previous)
            except BaseException: self.held(); raise

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None

"""Deterministic, unsigned two-source command package. No runtime/image changes.

Only exact reviewed Git blobs are inputs. Preparation requires the package
producer itself to be committed and a new external Linux output path.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
import weakref

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
PRODUCER_PATH = 'amz-runtime/public-beta-publication/package.py'
PROFILE_PATH = 'amz-runtime/public-beta-publication/command-package-profile.v1.json'
PROFILE_SHA256 = '105397453285ce331476293be3a13ac7fda9a033623390e5413b5e65ee6eed02'
COMPONENT_COMMIT = '230ca06351e410bb300a719672a9ed1d45062015'
ARCHIVE_NAME = 'publication-command.v1.tar'
ARCHIVE_LIMIT = 262144
_CAPTURED = weakref.WeakKeyDictionary()


def _need(value):
    if not value: raise ValueError('publication_command_package_refused')


def _sha(raw): return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _identity(s):
    # Windows names infer .exe execute bits that a held FD does not report.
    # No Windows permission/ACL authority is inferred; preparation is Linux-only.
    mode = s.st_mode & ~0o111 if sys.platform == 'win32' else s.st_mode
    return (s.st_dev, s.st_ino, mode, s.st_nlink, s.st_size, s.st_mtime_ns,
            s.st_birthtime_ns if sys.platform == 'win32' else s.st_ctime_ns)


def _regular(path, maximum, links=(1,)):
    _need(path.is_absolute() and path.resolve() == path)
    for parent in path.parents:
        info = parent.lstat(); _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) |
                 getattr(os, 'O_BINARY', 0))
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink in links and 0 < before.st_size <= maximum)
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part: break
            raw.extend(part)
        _need(_identity(before) == _identity(os.fstat(fd)) == _identity(path.lstat()) and len(raw) == before.st_size)
        return bytes(raw)
    finally: os.close(fd)


def _measure_tool(path):
    initial = path.lstat()
    _need(stat.S_ISREG(initial.st_mode) and initial.st_nlink > 0)
    raw = _regular(path, 33554432, (initial.st_nlink,))
    _need(_identity(path.lstat()) == _identity(initial))
    return _sha(raw), initial.st_nlink


class _Git:
    """Fixed read-only Git commands, sanitized environment, bounded pipes/time."""
    def __init__(self):
        self.deadline = time.monotonic() + 30
        executable = shutil.which('git')
        _need(executable is not None)
        self.executable = Path(executable).absolute().resolve()
        self.tool_sha256, self.tool_links = _measure_tool(self.executable)
        self.environment = {'PATH': str(self.executable.parent) + os.pathsep + os.defpath,
                            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                            'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_NO_REPLACE_OBJECTS': '1',
                            'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0',
                            'GIT_ATTR_NOSYSTEM': '1', 'GIT_NO_LAZY_FETCH': '1',
                            'GIT_ALLOW_PROTOCOL': '', 'GIT_PROTOCOL_FROM_USER': '0',
                            'LANG': 'C', 'LC_ALL': 'C'}
        if sys.platform == 'win32': self.environment['SystemRoot'] = 'C:\\Windows'

    def current(self):
        _need(time.monotonic() < self.deadline)
        digest = _sha(_regular(self.executable, 33554432, (self.tool_links,)))
        _need(time.monotonic() < self.deadline and digest == self.tool_sha256)

    def run(self, arguments, maximum):
        self.current()
        process = subprocess.Popen([str(self.executable), '--no-pager', '--no-optional-locks',
                                    '-c', 'core.hooksPath=/nonexistent-amz-hooks',
                                    '-c', 'core.fsmonitor=false', '-c', 'safe.directory=' + str(REPOSITORY),
                                    *arguments], cwd=REPOSITORY, env=self.environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        output, errors, overflow = bytearray(), bytearray(), threading.Event()
        def drain(stream, target, limit):
            try:
                while True:
                    part = stream.read(8192)
                    if not part: break
                    if len(target) + len(part) > limit:
                        overflow.set()
                        try: process.kill()
                        except OSError: pass
                        break
                    target.extend(part)
            except BaseException: overflow.set()
            finally: stream.close()
        readers = [threading.Thread(target=drain, args=(process.stdout, output, maximum), daemon=True),
                   threading.Thread(target=drain, args=(process.stderr, errors, 4096), daemon=True)]
        for reader in readers: reader.start()
        try:
            process.wait(timeout=max(.001, min(5, self.deadline - time.monotonic())))
        except BaseException:
            try: process.kill()
            except OSError: pass
            process.wait(timeout=5)
            raise ValueError('publication_command_package_refused') from None
        finally:
            for reader in readers: reader.join(timeout=5)
        _need(not any(reader.is_alive() for reader in readers) and not overflow.is_set() and process.returncode == 0)
        self.current()
        return bytes(output)

    def head(self):
        raw = self.run(['rev-parse', '--verify', 'HEAD^{commit}'], 41)
        _need(re.fullmatch(b'[a-f0-9]{40}\n', raw))
        return raw.decode().strip()

    def blob(self, commit, path, maximum):
        _need(re.fullmatch('[a-f0-9]{40}', commit) and path in
              (PRODUCER_PATH, PROFILE_PATH, 'LICENSE',
               'amz-runtime/public-beta-publication/runtime/command.py',
               'amz-runtime/public-beta-publication/runtime/publication.py'))
        # Resolve the literal path in the current tree, including regular-file
        # mode. A symlink blob or unrelated admitted loose object is not a source.
        entry = self.run(['ls-tree', '-z', commit, '--', path], 256)
        _need(re.fullmatch(b'100644 blob [a-f0-9]{40}\t' + re.escape(path.encode()) + b'\0', entry))
        object_id = entry[12:52].decode()
        _need(self.run(['cat-file', '-t', object_id], 5) == b'blob\n')
        size = self.run(['cat-file', '-s', object_id], 16)
        _need(re.fullmatch(b'[1-9][0-9]{0,8}\n', size) and int(size) <= maximum)
        raw = self.run(['cat-file', 'blob', object_id], maximum)
        _need(len(raw) == int(size) and
              hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == object_id)
        return raw, object_id


def _profile(raw):
    _need(type(raw) is bytes and len(raw) <= 8192 and _sha(raw) == PROFILE_SHA256)
    value = json.loads(raw)
    _need(_canonical(value) + b'\n' == raw and value['component']['commit'] == COMPONENT_COMMIT and
          value['schema'] == 'amz.ap.public-beta.publication-command-package-profile.v1' and value['version'] == 1)
    return value


def _component(git, profile, producer_commit):
    admitted = {}
    for row in [*profile['component']['files'], profile['component']['license']]:
        # The reviewed profile vouches for the original component230/path/OID
        # mapping. Even a shallow producer must contain that SAME OID at the
        # exact current committed path. A dangling blob is never sufficient.
        raw, oid = git.blob(producer_commit, row['path'], 65536)
        _need(oid == row['gitBlob'] and len(raw) == row['bytes'] and _sha(raw) == row['sha256'])
        admitted[row['path']] = raw
    return admitted


class CapturedCommandPackage:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs): raise ValueError('publication_command_package_brand')


def capture_package_sources():
    """Capture committed producer/profile and both immutable component blobs."""
    git = _Git(); producer_commit = git.head()
    producer, producer_oid = git.blob(producer_commit, PRODUCER_PATH, 65536)
    # The running admitted source must itself be the committed producer, rather
    # than a modified working-tree program that merely reports a known commit.
    _need(_regular(Path(__file__).absolute(), 65536) == producer)
    profile_raw, profile_oid = git.blob(producer_commit, PROFILE_PATH, 8192)
    profile = _profile(profile_raw)
    components = _component(git, profile, producer_commit)
    _need(git.head() == producer_commit)
    value = {'git': git, 'profile': profile, 'components': components,
             'producer': {'commit': producer_commit, 'path': PRODUCER_PATH, 'gitBlob': producer_oid,
                          'sha256': _sha(producer), 'profilePath': PROFILE_PATH,
                          'profileGitBlob': profile_oid, 'profileSha256': PROFILE_SHA256},
             'pid': os.getpid()}
    captured = object.__new__(CapturedCommandPackage); _CAPTURED[captured] = value
    return captured


def _captured(captured):
    _need(type(captured) is CapturedCommandPackage and captured in _CAPTURED)
    value = _CAPTURED[captured]
    _need(value['pid'] == os.getpid())
    return value


def _archive(profile, components, producer):
    """Pure deterministic encoding of already admitted bytes; no execution."""
    files = profile['component']['files']
    expected = [*files, profile['component']['license']]
    _need(type(components) is dict and set(components) == {row['path'] for row in expected})
    for row in expected:
        raw = components[row['path']]
        _need(type(raw) is bytes and len(raw) == row['bytes'] and _sha(raw) == row['sha256'])
    notice = ('AMZ Public publication command — unsigned source package\n'
              'Component: Antimatter-Zone/DMS-Archipelago-Server ' + COMPONENT_COMMIT + '\n'
              'Only command.py and publication.py are executable sources.\n'
              'The exact component repository MIT LICENSE is included unchanged.\n'
              'No Python interpreter, Archipelago engine, key, configuration or game data is included.\n'
              'No signing, installation, target enrollment or qualification is asserted.\n').encode('utf-8')
    owned = [(profile['archive']['entryOrder'][0], components[files[0]['path']]),
             (profile['archive']['entryOrder'][1], components[files[1]['path']]),
             (profile['archive']['entryOrder'][3], notice),
             (profile['archive']['entryOrder'][4], components['LICENSE'])]
    manifest = {'schema': 'amz.ap.public-beta.publication-command-artifact.v1', 'version': 1,
                'component': profile['component'], 'producer': producer,
                'componentProvenance': 'reviewed-profile-pins-and-current-producer-tree',
                'invocation': profile['invocation'],
                'contents': [{'path': name, 'sha256': _sha(raw), 'bytes': len(raw)} for name, raw in owned],
                'sourceOnly': True, 'signed': False, 'installed': False, 'activation': False,
                'qualification': False, 'targetAuthority': False, 'resourceReleaseAuthorized': False}
    metadata = _canonical(manifest)
    _need(len(metadata) <= 16384 and len(notice) <= 8192)
    entries = [(profile['archive']['entryOrder'][0], components[files[0]['path']]),
               (profile['archive']['entryOrder'][1], components[files[1]['path']]),
               (profile['archive']['entryOrder'][2], metadata),
               (profile['archive']['entryOrder'][3], notice),
               (profile['archive']['entryOrder'][4], components['LICENSE'])]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in entries:
            header = tarfile.TarInfo(name)
            header.type, header.size, header.mode = tarfile.REGTYPE, len(raw), 0o444
            header.uid = header.gid = header.mtime = 0
            header.uname = header.gname = header.linkname = ''
            header.pax_headers = {}
            archive.addfile(header, io.BytesIO(raw))
    raw = output.getvalue(); _need(0 < len(raw) <= ARCHIVE_LIMIT)
    return raw


def package_bytes(captured):
    value = _captured(captured)
    return _archive(value['profile'], value['components'], value['producer'])


def _directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _named_ancestry(path):
    rows = []
    for parent in [path, *path.parents]:
        info = parent.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
        rows.append((parent, (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)))
    return rows


def _named_current(rows):
    for path, expected in rows:
        info = path.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
              (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) == expected)


def prepare(output):
    """Exclusive Linux FD-relative output; no partial cleanup or overwrite."""
    _need(sys.platform == 'linux' and os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'))
    captured = capture_package_sources(); value = _captured(captured)
    raw = package_bytes(captured)
    _need(type(output) is type(REPOSITORY) and output.is_absolute() and output.name == ARCHIVE_NAME and
          output.parent.resolve() == output.parent and not output.is_relative_to(REPOSITORY))
    ancestry = _named_ancestry(output.parent)
    directory = _directory(output.parent)
    fd = None
    try:
        identity = os.fstat(directory)
        # Recheck the exact producer/tool after all capture/render/path IO and
        # before the sole output creation. Source/metadata were all captured.
        _need(value['git'].head() == value['producer']['commit'] and
              _sha(_regular(Path(__file__).absolute(), 65536)) == value['producer']['sha256'])
        _named_current(ancestry)
        _need(ancestry[0][1][:2] == (identity.st_dev, identity.st_ino))
        fd = os.open(output.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        rest = memoryview(raw)
        while rest:
            count = os.write(fd, rest); _need(count > 0); rest = rest[count:]
        os.fsync(fd); os.fsync(directory)
        before = os.fstat(fd); os.lseek(fd, 0, os.SEEK_SET)
        readback = bytearray()
        while len(readback) <= ARCHIVE_LIMIT:
            part = os.read(fd, min(65536, ARCHIVE_LIMIT + 1 - len(readback)))
            if not part: break
            readback.extend(part)
        named = os.stat(output.name, dir_fd=directory, follow_symlinks=False)
        _need(bytes(readback) == raw and before.st_nlink == 1 and stat.S_ISREG(before.st_mode) and
              _identity(before) == _identity(os.fstat(fd)) == _identity(named))
        _need(value['git'].head() == value['producer']['commit'])
        _named_current(ancestry)
        _need(_identity(before) == _identity(os.fstat(fd)) ==
              _identity(os.stat(output.name, dir_fd=directory, follow_symlinks=False)))
        closing, fd = fd, None; os.close(closing)
    finally:
        if fd is not None: os.close(fd)
        os.close(directory)
    _named_current(ancestry)
    _need(_identity(output.lstat()) == _identity(before))
    return {'schema': 'amz.ap.public-beta.publication-command-package-receipt.v1',
            'componentCommit': COMPONENT_COMMIT, 'producerCommit': value['producer']['commit'],
            'profileSha256': PROFILE_SHA256, 'artifactSha256': _sha(raw), 'bytes': len(raw),
            'gitToolSha256': value['git'].tool_sha256, 'gitToolLinkCount': value['git'].tool_links,
            'sourceOnly': True, 'signed': False,
            'installed': False, 'activation': False, 'qualification': False, 'resourceReleaseAuthorized': False}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        _need(len(argv) == 3 and argv[:2] == ['--prepare', '--output'])
        receipt = prepare(Path(argv[2]))
        print(_canonical(receipt).decode('utf-8'))
        return 0
    except BaseException:
        # No Git stderr, raw source, private path or exception dump.
        return 1


if __name__ == '__main__': raise SystemExit(main())

"""Fresh-only bootstrap worker. Node owns Ed25519 verification, never this module.

One inherited private channel, real Linux FDs and an exact captured native
loader. No listener, approval callback, engine import or startup on import.
"""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import stat
import struct
import sys
import time
import types
import uuid
import weakref

OWNED = Path('/opt/amz-ap-production-bootstrap')
PARENT = Path('/opt/amz-ap-public')
NATIVE = Path('/home/container/.amz')
BOOT = Path('/home/container/.amz-bootstrap')
PROFILE_SHA = '646ed63b88192e51106b619b1a7a174eb4d29f2d6f55fdd8ea14622cede7422c'
CHANNEL = 'amz.ap.public-beta.production-bootstrap-channel.v1'
COMPOSITION_SHA = '9883a419994438fe60c0e561b250480c60de2a1ee1aa932989c97b67e2565124'
PUBLICATION_SHA = 'f7cf95840762e7e28194b5a589014ceb88fbe95cde05b6b1737aadc8f0be2ce2'
NATIVE_LOADER_SHA = '9fdcfab688d6563c766cd6bb178cba6903dd9e4eb1f4ff1a23d3320e74804c22'
BOOT_CAPS = {'challenge.json': 4096, '.challenge.json.pending': 4096,
             'seal.json': 16384, '.seal.json.pending': 16384,
             'consumed.json': 4096, '.consumed.json.pending': 4096}
_APPROVALS = weakref.WeakKeyDictionary()
_SNAPSHOTS = weakref.WeakKeyDictionary()
FAILURE_SCHEMA = 'amz.ap.public-beta.production-bootstrap-worker-failure.v1'
FAILURE_STAGES = frozenset(('capture_inputs', 'challenge', 'seal_verify', 'snapshot', 'handoff',
                            'native_inputs', 'native_init', 'native_loop', 'cleanup'))
_DIAGNOSTIC_STAGE = 'capture_inputs'


def diagnostic_stage(value):
    global _DIAGNOSTIC_STAGE
    need(type(value) is str and value in FAILURE_STAGES)
    _DIAGNOSTIC_STAGE = value


def failure_marker():
    # Never inspect an exception, traceback, argument, path or native value.
    stage = _DIAGNOSTIC_STAGE if type(_DIAGNOSTIC_STAGE) is str and _DIAGNOSTIC_STAGE in FAILURE_STAGES else 'capture_inputs'
    return canonical({'schema': FAILURE_SCHEMA, 'stage': stage, 'code': 'bootstrap_refused'}) + b'\n'


def need(value):
    if not value: raise RuntimeError('bootstrap_runtime_refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def pairs(values):
    result = {}
    for key, value in values:
        need(key not in result); result[key] = value
    return result


def decode(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=lambda _: need(False))
    need(type(value) is dict and canonical(value) == raw)
    return value


def instant(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', value))
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') == value)
    return int(parsed.timestamp() * 1000)


def iso(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class Budget:
    def __init__(self, milliseconds, *, parent=None, issued=None, expires=None, anchor=None):
        self.mono, self.wall = anchor if anchor is not None else (time.monotonic_ns(), time.time_ns() // 1000000)
        self.deadline = self.mono + milliseconds * 1000000
        self.expiry = self.wall + milliseconds
        if issued is not None:
            start, end = instant(issued), instant(expires)
            need(start <= self.wall < end and 0 < end - start <= milliseconds)
            self.expiry = end; self.deadline = self.mono + (end - self.wall) * 1000000
        if parent is not None:
            parent.current(); self.deadline = min(self.deadline, parent.deadline); self.expiry = min(self.expiry, parent.expiry)
        self.pid = os.getpid()

    def current(self):
        mono, wall = time.monotonic_ns(), time.time_ns() // 1000000
        need(self.pid == os.getpid() and self.mono <= mono < self.deadline and self.wall <= wall < self.expiry)
        self.mono, self.wall = mono, wall
        return wall

    def seconds(self):
        self.current(); return max(0, (self.deadline - time.monotonic_ns()) / 1000000000)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def private(info, maximum, *, empty=False):
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 65532 and info.st_gid == 65532 and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
         (0 if empty else 1) <= info.st_size <= maximum)
    return identity(info)


def directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            previous, fd = fd, next_fd; os.close(previous)
        return fd
    except BaseException:
        os.close(fd); raise


def root_info(info):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 65532 and info.st_gid == 65532 and
         stat.S_IMODE(info.st_mode) == 0o700)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def root(path, *, create=False):
    if create:
        parent = directory(path.parent)
        try:
            try: os.mkdir(path.name, 0o700, dir_fd=parent); os.fsync(parent)
            except FileExistsError: pass
        finally: os.close(parent)
    fd = directory(path)
    try:
        info = os.fstat(fd); named = path.lstat()
        need(root_info(info) == root_info(named) and not stat.S_ISLNK(named.st_mode))
        return fd
    except BaseException: os.close(fd); raise


def boot_root_current(fd):
    """The held bootstrap directory must still be the fixed named namespace."""
    expected = root_info(os.fstat(fd))
    named_fd = directory(BOOT)
    try:
        need(root_info(os.fstat(named_fd)) == expected and
             root_info(BOOT.lstat()) == expected and root_info(os.fstat(fd)) == expected)
    finally: os.close(named_fd)


def read_at(directory_fd, name, maximum, *, keep=False):
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False); expected = private(before, maximum)
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        need(private(os.fstat(fd), maximum) == expected)
        raw = os.pread(fd, maximum + 1, 0)
        need(len(raw) == before.st_size and private(os.fstat(fd), maximum) == expected and
             private(os.stat(name, dir_fd=directory_fd, follow_symlinks=False), maximum) == expected)
        if keep:
            result, fd = fd, None; return raw, expected, result
        return raw, expected
    finally:
        if fd is not None: os.close(fd)


def image_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0 and
             before.st_gid == 0 and not before.st_mode & 0o022 and 0 < before.st_size <= maximum)
        raw = os.pread(fd, maximum + 1, 0)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()))
        return raw
    finally: os.close(fd)


def audit_boot(fd, budget, *, sealed=False):
    budget.current(); boot_root_current(fd)
    # Reserve every fixed current/pending maximum before any publication. Never
    # infer free credit from absent/sparse metadata or directory allocation.
    need(max(os.fstat(fd).st_size, os.fstat(fd).st_blocks * 512) <= 4096)
    total = 4096 + sum(BOOT_CAPS.values()); need(total <= 65536)
    names = os.listdir(fd); need(len(names) <= len(BOOT_CAPS) and set(names) <= set(BOOT_CAPS))
    for name in names:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        private(info, BOOT_CAPS[name], empty=not sealed)
        need(max(info.st_size, info.st_blocks * 512) <= BOOT_CAPS[name])
    need(total <= 65536 and (not sealed or not any(name.startswith('.') for name in names)))
    boot_root_current(fd); budget.current()


def publish_metadata(fd, name, raw, budget):
    need(name in ('challenge.json', 'consumed.json') and 0 < len(raw) <= BOOT_CAPS[name])
    audit_boot(fd, budget); pending = '.' + name + '.pending'
    handle = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            budget.current(); count = os.write(handle, remaining); need(count > 0); remaining = remaining[count:]
        os.fsync(handle); budget.current()
        staged = private(os.fstat(handle), BOOT_CAPS[name])
        check_raw, check_identity = read_at(fd, pending, BOOT_CAPS[name])
        need(check_raw == raw and check_identity == staged)
        # linkat publishes exclusively; an uncertain earlier final is never overwritten.
        os.link(pending, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
        left = os.stat(pending, dir_fd=fd, follow_symlinks=False)
        right = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(left.st_dev == right.st_dev == os.fstat(handle).st_dev and
             left.st_ino == right.st_ino == os.fstat(handle).st_ino and left.st_nlink == right.st_nlink == 2)
        budget.current(); os.unlink(pending, dir_fd=fd); os.fsync(fd)
        need(read_at(fd, name, BOOT_CAPS[name])[0] == raw); audit_boot(fd, budget)
    finally:
        closing, handle = handle, None; os.close(closing)


def process_start(pid):
    with open('/proc/' + str(pid) + '/stat', 'rb') as stream: raw = stream.read(4097)
    need(0 < len(raw) <= 4096 and raw.startswith(str(pid).encode() + b' ('))
    fields = raw[raw.rindex(b')') + 2:].split()
    value = fields[19].decode('ascii'); need(re.fullmatch('[0-9]{1,20}', value)); return value


def parent_startup(startup):
    """Fixed initial parent bound, before source/private-root IO; never renews."""
    need(stat.S_ISFIFO(os.fstat(4).st_mode) or stat.S_ISSOCK(os.fstat(4).st_mode))
    os.set_blocking(4, False)
    def exact_read(size):
        result = bytearray()
        while len(result) < size:
            need(select.select([4], [], [], startup.seconds())[0])
            try: raw = os.read(4, size - len(result))
            except BlockingIOError: continue
            need(raw); result.extend(raw); startup.current()
        return bytes(result)
    size = struct.unpack('>I', exact_read(4))[0]; need(0 < size <= 1024)
    frame = decode(exact_read(size), 1024)
    need(set(frame) == {'schema', 'direction', 'sequence', 'kind', 'body'} and
         frame['schema'] == CHANNEL and frame['direction'] == 'parent-to-worker' and
         type(frame['sequence']) is int and frame['sequence'] == -1 and frame['kind'] == 'startup-bound' and
         type(frame['body']) is dict and set(frame['body']) == {'issuedAt', 'expiresAt'})
    return Budget(30000, parent=startup, issued=frame['body']['issuedAt'], expires=frame['body']['expiresAt'])


class VerifiedSeal:
    __slots__ = ('__weakref__',)
    def __new__(cls, *args, **kwargs): raise RuntimeError('bootstrap_seal_brand')


class PrivateChannel:
    def __init__(self, challenge, startup, signer_sha):
        need(all(stat.S_ISFIFO(os.fstat(fd).st_mode) or stat.S_ISSOCK(os.fstat(fd).st_mode) for fd in (3, 4)))
        self.challenge, self.startup, self.closed = challenge, startup, False
        need(type(signer_sha) is str and re.fullmatch('[a-f0-9]{64}', signer_sha)); self.signer_sha = signer_sha
        self.sequence = 0
        os.set_blocking(3, False); os.set_blocking(4, False)

    def send(self, kind, body, budget):
        need(not self.closed)
        raw = canonical({'schema': CHANNEL, 'direction': 'worker-to-parent', 'sequence': self.sequence,
                         'kind': kind, 'body': body})
        need(0 < len(raw) <= 32768)
        remaining = memoryview(struct.pack('>I', len(raw)) + raw)
        while remaining:
            need(select.select([], [3], [], budget.seconds())[1]); budget.current()
            try: count = os.write(3, remaining[:4096])
            except BlockingIOError: continue
            need(count > 0); remaining = remaining[count:]; budget.current()

    def receive(self, kind, budget):
        def exact_read(size):
            output = bytearray()
            while len(output) < size:
                need(select.select([4], [], [], budget.seconds())[0]); budget.current()
                try: raw = os.read(4, size - len(output))
                except BlockingIOError: continue
                need(raw); output.extend(raw); budget.current()
            return bytes(output)
        size = struct.unpack('>I', exact_read(4))[0]; need(0 < size <= 4096)
        frame = decode(exact_read(size), 4096)
        need(set(frame) == {'schema', 'direction', 'sequence', 'kind', 'body'} and frame['schema'] == CHANNEL and
             frame['direction'] == 'parent-to-worker' and type(frame['sequence']) is int and
             frame['sequence'] == self.sequence and frame['kind'] == kind)
        self.sequence += 1
        return frame['body']

    def register(self):
        self.send('challenge', self.challenge, self.startup)
        value = self.receive('challenge-accepted', self.startup)
        need(value == {'nonce': self.challenge['nonce'], 'challengeSha256': sha(canonical(self.challenge))})

    def verify(self, raw, budget):
        envelope = decode(raw, 16384)
        need(set(envelope) == {'schema', 'body', 'signature'})
        request_id = str(uuid.uuid4())
        self.send('verify-seal', {'requestId': request_id, 'nonce': self.challenge['nonce'],
                                  'sealBase64': base64.b64encode(raw).decode('ascii')}, budget)
        reply = self.receive('seal-verified', budget); body = envelope['body']
        need(set(reply) == {'requestId', 'nonce', 'sealSha256', 'bodySha256', 'signerSpkiSha256'} and
             reply['requestId'] == request_id and reply['nonce'] == self.challenge['nonce'] and
             reply['sealSha256'] == sha(raw) and reply['bodySha256'] == sha(canonical(body)) and
             reply['signerSpkiSha256'] == self.signer_sha)
        budget.current()
        proof = object.__new__(VerifiedSeal)
        _APPROVALS[proof] = {'body': body, 'raw': raw, 'pid': os.getpid(), 'channel': self,
                             'budget': budget, 'nonce': self.challenge['nonce'], 'consumed': False}
        return proof

    def initialized(self, proof, journal_sha):
        value = approval(proof, self)
        self.send('initialized', {'nonce': value['nonce'], 'sealSha256': sha(value['raw']),
                                  'firstJournalSha256': journal_sha}, self.startup)
        reply = self.receive('initialized-accepted', self.startup)
        need(reply == {'nonce': value['nonce'], 'sealSha256': sha(value['raw'])})
        self.close()

    def close(self):
        need(not self.closed); self.closed = True
        first = None
        for fd in (3, 4):
            try: os.close(fd)
            except OSError as error:
                if first is None: first = error
        if first is not None: raise first


def approval(proof, channel):
    need(type(proof) is VerifiedSeal and proof in _APPROVALS)
    value = _APPROVALS[proof]
    need(value['pid'] == os.getpid() and value['channel'] is channel and value['nonce'] == channel.challenge['nonce'])
    if not value['consumed']: value['budget'].current()
    return value


class SealedSnapshot:
    __slots__ = ('__weakref__',)
    def __new__(cls, *args, **kwargs): raise RuntimeError('bootstrap_snapshot_brand')


def capture_snapshot(proof, channel, native_code):
    admitted = approval(proof, channel); admitted['budget'].current()
    need(not admitted['consumed'] and type(native_code) is dict and sha(native_code['publication.py']) == PUBLICATION_SHA)
    pub = types.ModuleType('verified_bootstrap_publication_snapshot')
    exec(compile(native_code['publication.py'], '<verified:' + PUBLICATION_SHA + '>', 'exec'), pub.__dict__)
    body, budget = admitted['body'], admitted['budget']
    rows = {row['name']: row for row in body['files']}
    window = pub.capture_window(body['issuedAt'], body['expiresAt'])
    pub._window_state(window)['deadline'] = min(pub._window_state(window)['deadline'], budget.deadline)
    scope = lock = None; directory_fd = None; files = {}
    try:
        scope = pub.capture_runtime_scope(rows['public-publication-scope.json']['sha256'], window)
        lock = pub.PublicationLock(scope, window)
        with lock.hold(window):
            current = pub._scope_current(scope, window); directory_fd = os.dup(current['directory'])
            need(set(os.listdir(directory_fd)) == set(rows))
            need(current['enrollment']['identity'] == body['identity'] and
                 current['enrollment']['containerId'] == body['provider']['containerId'] and
                 current['enrollment']['serverUuid'] == body['provider']['serverUuid'] and
                 current['enrollment']['imageId'] == body['provider']['imageId'])
            for name, row in rows.items():
                budget.current(); raw, metadata, fd = read_at(directory_fd, name, row['bytes'], keep=True)
                files[name] = {'fd': fd, 'raw': raw, 'identity': metadata, 'maximum': row['bytes']}
                info = os.fstat(fd)
                need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and
                     row['device'] == str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)) and
                     row['inode'] == str(info.st_ino) and row['uid'] == info.st_uid and row['gid'] == info.st_gid and
                     row['mode'] == stat.S_IMODE(info.st_mode))
            budget.current()
        closing, lock = lock, None; closing.close()
        closing, scope = scope, None; closing.close()
        budget.current()
        snapshot = object.__new__(SealedSnapshot)
        _SNAPSHOTS[snapshot] = {'proof': proof, 'channel': channel, 'directory': directory_fd,
                                'rootIdentity': identity(os.fstat(directory_fd))[:2], 'files': files,
                                'code': types.MappingProxyType(dict(native_code)),
                                'pid': os.getpid(), 'closed': False, 'bound': False}
        directory_fd = None; files = {}
        return snapshot
    finally:
        # Every reference is local and closed once. Unknown close outcomes are
        # fatal to this worker; no guessed numeric descriptor is retried.
        first = None
        handles = []
        if lock is not None: handles.append(lock.close); lock = None
        if scope is not None: handles.append(scope.close); scope = None
        for value in files.values():
            descriptor, value['fd'] = value['fd'], None
            handles.append(lambda descriptor=descriptor: os.close(descriptor))
        if directory_fd is not None:
            descriptor, directory_fd = directory_fd, None
            handles.append(lambda: os.close(descriptor))
        for close in handles:
            try: close()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


def snapshot_state(snapshot):
    need(type(snapshot) is SealedSnapshot and snapshot in _SNAPSHOTS)
    value = _SNAPSHOTS[snapshot]; need(value['pid'] == os.getpid() and not value['closed']); return value


def snapshot_current(snapshot, *, startup=True):
    value = snapshot_state(snapshot); channel = value['channel']; admitted = approval(value['proof'], channel)
    if startup: channel.startup.current()
    need(identity(os.fstat(value['directory']))[:2] == value['rootIdentity'] and
         (NATIVE.lstat().st_dev, NATIVE.lstat().st_ino) == value['rootIdentity'] and not NATIVE.is_symlink())
    for name, item in value['files'].items():
        need(private(os.fstat(item['fd']), item['maximum']) == item['identity'] and
             private(os.stat(name, dir_fd=value['directory'], follow_symlinks=False), item['maximum']) == item['identity'] and
             os.pread(item['fd'], item['maximum'] + 1, 0) == item['raw'])
    if not admitted['consumed']: admitted['budget'].current()
    elif startup: channel.startup.current()
    return value


def close_snapshot(snapshot):
    value = snapshot_state(snapshot); value['closed'] = True
    descriptors = [item['fd'] for item in value['files'].values()] + [value['directory']]
    value['files'], value['directory'] = {}, None
    first = None
    for fd in descriptors:
        try: os.close(fd)
        except OSError as error:
            if first is None: first = error
    if first is not None: raise first


def run_native_loader(snapshot):
    """Capture the real loader internally; no caller module/callback is admitted."""
    diagnostic_stage('native_inputs')
    state = snapshot_state(snapshot); admitted = approval(state['proof'], state['channel'])
    native_code = dict(state['code'])
    need(admitted['consumed'] and sha(native_code['loader.py']) == NATIVE_LOADER_SHA)
    parent = types.ModuleType('verified_sealed_parent_loader')
    parent.__file__ = str(PARENT / 'loader.py')
    exec(compile(native_code['loader.py'], '<verified:' + NATIVE_LOADER_SHA + '>', 'exec'), parent.__dict__)
    original_verify, original_capture, original_install = parent.verify_inputs, parent.captured_module, parent.install_control_guards
    attached = {'guard': None, 'initialized': False, 'journalSha256': None, 'composition': None}

    def verify_inputs(base):
        diagnostic_stage('native_inputs')
        snapshot_current(snapshot)
        result = original_verify(base)  # ACTUAL original FD reads and validation.
        snapshot_current(snapshot)
        need(type(result) is tuple and len(result) == 9)
        _, code, _, seed, _, key_raw, config_raw, scope_raw, _ = result
        need(code == native_code)
        actual = {'public-runtime.json': config_raw, 'public-yacht-keys.json': key_raw,
                  'public-seed.archipelago': seed, 'public-publication-scope.json': scope_raw}
        need(all(type(raw) is bytes and raw == state['files'][name]['raw'] for name, raw in actual.items()))
        return result

    def captured_module(name, raw, expected):
        module = original_capture(name, raw, expected)  # Original hash-before-exec.
        if name != 'publication_composition':
            need(name == 'publication_packet_policy'); return module
        need(expected == COMPOSITION_SHA and sha(raw) == COMPOSITION_SHA and attached['composition'] is None)
        attached['composition'] = module
        original_open = module.open_native_composition
        def open_native(sources, scope_sha, issued, expires):
            snapshot_current(snapshot)
            need(scope_sha == sha(state['files']['public-publication-scope.json']['raw']))
            guard = original_open(sources, scope_sha, issued, expires)
            attached['guard'] = guard
            try:
                with guard.transaction():
                    snapshot_current(snapshot)
                    genuine = module._COMPOSITIONS.get(guard)
                    need(genuine and genuine['owner'] is guard.files and
                         type(guard.files) is genuine['modules']['native_files'].NativeFiles)
                    original_initialize = guard.files.initialize
                    def initialize(value):
                        diagnostic_stage('native_init')
                        with guard.transaction():
                            need(not attached['initialized']); snapshot_current(snapshot)
                            pub = genuine['modules']['publication']; lock = genuine['lock']
                            lock_state = pub._LOCKS.get(lock)
                            need(lock_state and lock_state['raw'] == state['files']['public-control-publication.lock']['raw'])
                            original_initialize(value)  # Genuine budgeted full write/readback.
                            snapshot_current(snapshot)
                            attached['journalSha256'] = sha(canonical(guard.files.load_journal()))
                            state['channel'].startup.current()
                            close_snapshot(snapshot)
                            state['channel'].startup.current()
                            attached['initialized'] = True
                    guard.files.initialize = initialize
                return guard
            except BaseException:
                guard.close(); raise
        module.open_native_composition = open_native
        return module

    def install_controls(composition, sources, guard):
        original_install(composition, sources, guard)
        need(guard is attached['guard'] and attached['initialized'])
        # Parent calls this AFTER its initialization transaction. Never wait
        # on private pipes while holding native RLock/publication flock.
        try: state['channel'].initialized(state['proof'], attached['journalSha256'])
        except BaseException:
            # Use the genuine coordinator's existing held/close semantics.
            with guard.transaction(): raise
        diagnostic_stage('native_loop')
    parent.verify_inputs, parent.captured_module, parent.install_control_guards = verify_inputs, captured_module, install_controls
    return parent.main()


def captured_inputs():
    profile_raw = image_file(OWNED / 'runtime-profile.json', 65536); need(sha(profile_raw) == PROFILE_SHA)
    profile = decode(profile_raw.rstrip(b'\n'), 65536)
    artifact_raw = image_file(OWNED / 'bootstrap-artifact.json', 32768)
    artifact = decode(artifact_raw, 32768)
    need(set(artifact) == {'schema', 'version', 'producerCommit', 'profileSha256', 'native', 'ownedFiles', 'qualification'} and
         artifact['schema'] == 'amz.ap.public-beta.yacht-production-bootstrap-artifact.v1' and artifact['version'] == 1 and
         type(artifact['producerCommit']) is str and re.fullmatch('[a-f0-9]{40}', artifact['producerCommit']) and
         artifact['profileSha256'] == PROFILE_SHA and artifact['native'] == profile['native'] and
         artifact['qualification'] == profile['qualification'] and
         type(artifact['ownedFiles']) is list and [r.get('path') for r in artifact['ownedFiles']] ==
         ['bootstrap.py', 'launcher.mjs', 'runtime-profile.json', 'trust-profile.json'])
    for row in artifact['ownedFiles']:
        need(row['path'] in ('bootstrap.py', 'launcher.mjs', 'runtime-profile.json', 'trust-profile.json'))
        raw = image_file(OWNED / row['path'], 262144); need(len(raw) == row['bytes'] and sha(raw) == row['sha256'])
    trust = decode(image_file(OWNED / 'trust-profile.json', 4096), 4096)
    need(set(trust) == {'schema', 'issuer', 'provider'} and
         trust['schema'] == 'amz.ap.public-beta.production-bootstrap-trust.v1')
    for role, purpose in (('issuer', 'amz.ap.public-beta.production-bootstrap-seal.v1'),
                          ('provider', 'amz.ap.public-beta.yacht-provider-launch.v1')):
        value = trust[role]
        need(type(value) is dict and set(value) == {'keyId', 'rootPublicKeyPem', 'rootSpkiSha256'} and
             value['keyId'] == purpose and type(value['rootSpkiSha256']) is str and
             re.fullmatch('[a-f0-9]{64}', value['rootSpkiSha256']))
    need(trust['issuer']['rootSpkiSha256'] != trust['provider']['rootSpkiSha256'])
    native_raw = image_file(PARENT / 'public-yacht-publication-runtime.v1.json', 1048576)
    need(sha(native_raw) == profile['native']['artifactSha256'])
    native = json.loads(native_raw); need(len(native['ownedFiles']) == 22)
    code = {}
    for row in native['ownedFiles']:
        need(re.fullmatch('[A-Za-z0-9_.-]+', row['path']) and row['path'] not in code)
        raw = image_file(PARENT / row['path'], 262144); need(len(raw) == row['bytes'] and sha(raw) == row['sha256'])
        code[row['path']] = raw
    need(sha(code['loader.py']) == profile['native']['loaderSha256'])
    return profile, sha(artifact_raw), code, trust['issuer']['rootSpkiSha256']


def main():
    diagnostic_stage('capture_inputs')
    startup = Budget(30000)
    need(sys.platform == 'linux' and os.getuid() == 65532 and os.getgid() == 65532 and os.getppid() == 1 and
         sys.version_info[:2] == (3, 12) and os.statvfs('/').f_flag & os.ST_RDONLY)
    startup = parent_startup(startup)
    profile, artifact_sha, code, signer_sha = captured_inputs(); startup.current()
    native_fd = boot_fd = snapshot = channel = None
    metadata_fds = []
    try:
        diagnostic_stage('challenge')
        native_fd = root(NATIVE, create=True); boot_fd = root(BOOT, create=True)
        need(os.listdir(native_fd) == [] and os.listdir(boot_fd) == [])
        now = startup.current(); info = os.fstat(native_fd)
        challenge = {'schema': 'amz.ap.public-beta.production-bootstrap-challenge.v1', 'nonce': secrets.token_hex(32),
                     'process': {'pid1StartTicks': process_start(1), 'workerStartTicks': process_start(os.getpid()),
                                 'workerPid': os.getpid()},
                     'bootstrapArtifactSha256': artifact_sha, 'profileSha256': PROFILE_SHA,
                     'nativeRoot': {'device': str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)),
                                    'inode': str(info.st_ino)},
                     'bootstrapRoot': {'device': str(os.major(os.fstat(boot_fd).st_dev)) + ':' + str(os.minor(os.fstat(boot_fd).st_dev)),
                                       'inode': str(os.fstat(boot_fd).st_ino)},
                     'issuedAt': iso(now), 'expiresAt': iso(startup.expiry)}
        publish_metadata(boot_fd, 'challenge.json', canonical(challenge), startup)
        challenge_raw, challenge_identity, challenge_fd = read_at(boot_fd, 'challenge.json', 4096, keep=True)
        metadata_fds.append(challenge_fd)
        need(challenge_raw == canonical(challenge))
        def metadata_current(name, fd, expected, raw, maximum):
            boot_root_current(boot_fd)
            need(private(os.fstat(fd), maximum) == expected and
                 private(os.stat(name, dir_fd=boot_fd, follow_symlinks=False), maximum) == expected and
                 os.pread(fd, maximum + 1, 0) == raw)
            boot_root_current(boot_fd)
        metadata_current('challenge.json', challenge_fd, challenge_identity, challenge_raw, 4096)
        channel = PrivateChannel(challenge, startup, signer_sha); channel.register()
        diagnostic_stage('seal_verify')
        while True:
            audit_boot(boot_fd, startup)
            anchor = (time.monotonic_ns(), time.time_ns() // 1000000)
            try: raw, seal_identity, seal_fd = read_at(boot_fd, 'seal.json', 16384, keep=True)
            except FileNotFoundError:
                time.sleep(min(.05, startup.seconds())); continue
            metadata_fds.append(seal_fd)
            envelope = decode(raw, 16384); body = envelope['body']
            short = Budget(5000, parent=startup, issued=body['issuedAt'], expires=body['expiresAt'], anchor=anchor)
            proof = channel.verify(raw, short)
            metadata_current('seal.json', seal_fd, seal_identity, raw, 16384)
            metadata_current('challenge.json', challenge_fd, challenge_identity, challenge_raw, 4096)
            diagnostic_stage('snapshot')
            snapshot = capture_snapshot(proof, channel, code)
            diagnostic_stage('handoff')
            audit_boot(boot_fd, short, sealed=True)
            publish_metadata(boot_fd, 'consumed.json', canonical({'schema': 'amz.ap.public-beta.production-bootstrap-consumed.v1',
                'nonce': challenge['nonce'], 'sealSha256': sha(raw), 'state': 'handoff-intent',
                'nativeStartObservedAtIntent': False, 'resourceReleaseAuthorized': False}), short)
            snapshot_current(snapshot); short.current()
            metadata_current('seal.json', seal_fd, seal_identity, raw, 16384)
            metadata_current('challenge.json', challenge_fd, challenge_identity, challenge_raw, 4096)
            while metadata_fds:
                descriptor = metadata_fds.pop(); os.close(descriptor); short.current()
            audit_boot(boot_fd, short, sealed=True)
            approval(proof, channel)['consumed'] = True  # Permanent same-worker BYTE binding, not a grant.
            break
        run_native_loader(snapshot)
        return 0
    finally:
        failed_stage = _DIAGNOSTIC_STAGE if sys.exc_info()[0] is not None else None
        diagnostic_stage('cleanup')
        closers = []
        if snapshot is not None and snapshot in _SNAPSHOTS and not _SNAPSHOTS[snapshot]['closed']:
            closers.append(lambda: close_snapshot(snapshot))
        if channel is not None and not channel.closed: closers.append(channel.close)
        for descriptor in (boot_fd, native_fd):
            if descriptor is not None: closers.append(lambda descriptor=descriptor: os.close(descriptor))
        while metadata_fds:
            descriptor = metadata_fds.pop(); closers.append(lambda descriptor=descriptor: os.close(descriptor))
        first = None
        for close in closers:
            try: close()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first
        if failed_stage is not None: diagnostic_stage(failed_stage)


if __name__ == '__main__':
    try: result = main()
    except BaseException:
        result = 1
        try:
            sys.stderr.buffer.write(failure_marker()); sys.stderr.buffer.flush()
        except BaseException: pass
    raise SystemExit(result)

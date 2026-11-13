"""Fixed, one-shot host publisher. No signer, provider client or engine import.

The independently installed root owner must own this actual child/socket and
durably record intent before authorizing writes. A caller's JSON is never a
provider capability. The normal runtime independently verifies both signatures.
"""
import base64
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import struct
import sys
import time

HOST = Path('/srv/public-beta/wings/data')
ENTRY = Path('/opt/dms/public-provider-owner/server/first-start-v1/publisher.py')
ROOT_FDS = (9, 10)  # Root owner opens from its independently retained namespace.
CHANNEL = 'amz.ap.public-beta.yacht-first-start-publisher.v1'
DOMAIN = 'amz.ap.public-beta.production-bootstrap-seal.v1'
LAUNCH = 'amz.ap.public-beta.yacht-provider-launch.v1'
NATIVE = {'artifactSha256': '7c65cc7984339622d1c515cdc7648af8220c3ade26a076292cc16fbcf3b2411c',
          'profileSha256': '45d0e5de9dd8aade8197b2e66a36d5b6d1bfcf9e15f713c639c676b6b1978c1e',
          'sourceCommit': '406c32eced755111a945d8b01128faa1f08e6635'}
PROFILE_SHA = 'ce3658a8c96fb7b5e29506d8faf728edd8e962982e5cbad535e18add7365e02d'
BOOT_CAPS = {'challenge.json': 4096, '.challenge.json.pending': 4096,
             'seal.json': 16384, '.seal.json.pending': 16384,
             'consumed.json': 4096, '.consumed.json.pending': 4096,
             'first-start-control.json': 4096, '.first-start-control.json.pending': 4096,
             'first-start-ack.json': 4096, '.first-start-ack.json.pending': 4096}
FILES = (('public-control-publication.lock', 2048), ('public-publication-scope.json', 16384),
         ('public-runtime.json', 16384), ('public-seed.archipelago', 524288), ('public-yacht-keys.json', 4096))
ID_FIELDS = frozenset(('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'externalId',
                       'allocationRevision', 'serverId', 'attemptId', 'seedRevision', 'credentialEpoch', 'runtimeLaunchId'))


def need(value):
    if not value: raise RuntimeError('production_bootstrap_publisher_refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def pairs(items):
    value = {}
    for key, entry in items:
        need(key not in value); value[key] = entry
    return value


def decode(raw, maximum=65536):
    need(type(raw) in (bytes, bytearray) and 0 < len(raw) <= maximum)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=lambda _: need(False))
    need(type(value) is dict and canonical(value) == raw)
    return value


def instant(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', value))
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') == value)
    return int(parsed.timestamp() * 1000)


def iso(value): return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def uuid(value): return type(value) is str and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value)


class Budget:
    def __init__(self):
        self.mono = time.monotonic_ns(); self.wall = time.time_ns() // 1000000
        self.start = self.wall; self.expiry = self.wall + 30000; self.deadline = self.mono + 30000000000
        self.parent = os.getppid(); self.parent_start = process_start(self.parent); self.pid = os.getpid()

    def cap(self, issued, expires, maximum):
        now = self.current(); begin, end = instant(issued), instant(expires)
        need(begin <= now < end and 0 < end - begin <= maximum)
        self.expiry = min(self.expiry, end); self.deadline = min(self.deadline, self.mono + (end - now) * 1000000)
        self.current()

    def current(self):
        parent_start = process_start(self.parent)
        mono, wall = time.monotonic_ns(), time.time_ns() // 1000000
        need(self.pid == os.getpid() and os.getppid() == self.parent and parent_start == self.parent_start and
             self.mono <= mono < self.deadline and self.wall <= wall < self.expiry)
        self.mono, self.wall = mono, wall
        return wall

    def seconds(self):
        self.current(); return max(0, (self.deadline - time.monotonic_ns()) / 1000000000)


def process_start(pid):
    with open('/proc/' + str(pid) + '/stat', 'rb', buffering=0) as stream: raw = stream.read(4097)
    need(0 < len(raw) <= 4096)
    at = raw.rfind(b') '); need(at > 0)
    value = raw[at + 2:].split()[19].decode('ascii'); need(re.fullmatch('[1-9][0-9]{0,19}', value)); return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def root_identity(info):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 65532 and info.st_gid == 65532 and stat.S_IMODE(info.st_mode) == 0o700)
    return identity(info)[:5]


def root_value(info): return {'device': str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)), 'inode': str(info.st_ino)}


def private(info, maximum, links=1):
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 65532 and info.st_gid == 65532 and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == links and 0 < info.st_size <= maximum)
    return identity(info)


def bounded(fd, maximum, budget):
    before = os.fstat(fd); need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum)
    raw = bytearray()
    try:
        while len(raw) <= before.st_size:
            budget.current(); part = os.pread(fd, min(65536, before.st_size + 1 - len(raw)), len(raw))
            if not part: break
            raw.extend(part)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before)); budget.current()
        return raw
    except BaseException:
        raw[:] = b'\0' * len(raw); raise


class Channel:
    def __init__(self, budget):
        need(stat.S_ISSOCK(os.fstat(3).st_mode))
        self.socket = socket.socket(fileno=3); self.closed = False
        try:
            self.peer = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(self.peer == (os.getppid(), 0, 0))
            self.socket.setblocking(False); self.budget = budget; self.sequence = 0
        except BaseException:
            self.closed = True; self.socket.close(); raise

    def exchange(self, kind, body, reply):
        self.budget.current(); need(not self.closed and self.sequence < 3)
        need(struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == self.peer)
        raw = canonical({'schema': CHANNEL, 'direction': 'publisher-to-owner', 'sequence': self.sequence, 'kind': kind, 'body': body})
        need(len(raw) <= 65536); pending = memoryview(struct.pack('>I', len(raw)) + raw)
        while pending:
            need(select.select([], [3], [], self.budget.seconds())[1]); self.budget.current()
            try: count = self.socket.send(pending[:4096])
            except BlockingIOError: continue
            need(count > 0); pending = pending[count:]
        def read(size):
            value = bytearray()
            while len(value) < size:
                need(select.select([3], [], [], self.budget.seconds())[0]); self.budget.current()
                try: piece = self.socket.recv(size - len(value))
                except BlockingIOError: continue
                need(piece); value.extend(piece)
            return bytes(value)
        size = struct.unpack('>I', read(4))[0]; need(0 < size <= 65536)
        frame = decode(read(size)); self.budget.current()
        need(set(frame) == {'schema', 'direction', 'sequence', 'kind', 'body'} and frame['schema'] == CHANNEL and
             frame['direction'] == 'owner-to-publisher' and type(frame['sequence']) is int and
             frame['sequence'] == self.sequence and frame['kind'] == reply and type(frame['body']) is dict)
        self.sequence += 1; return frame['body']

    def close(self):
        need(not self.closed); self.closed = True; self.socket.close()


class Namespace:
    def __init__(self, server_uuid, budget):
        self.server = server_uuid; self.budget = budget; self.handles = []; self.created = {}; self.published = False; self.seal_record = None
        self.native = self.boot = None
        try:
            self.native_path = HOST / server_uuid / '.amz'; self.boot_path = HOST / server_uuid / '.amz-bootstrap'
            self.native, self.boot = ROOT_FDS; self.handles.extend(ROOT_FDS)
            for fd in ROOT_FDS:
                need(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY and stat.S_ISDIR(os.fstat(fd).st_mode))
            self.roots = (root_identity(os.fstat(self.native)), root_identity(os.fstat(self.boot)))
            self.current(); need(os.listdir(self.native) == [])
            need(set(os.listdir(self.boot)) == {'challenge.json'})
            challenge_fd = os.open('challenge.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.boot)
            self.handles.append(challenge_fd); self.challenge_fd = challenge_fd
            self.challenge_stat = private(os.fstat(challenge_fd), 4096)
            self.challenge_raw = bounded(challenge_fd, 4096, budget); self.challenge = decode(self.challenge_raw, 4096)
            c = self.challenge
            need(set(c) == {'schema', 'nonce', 'process', 'bootstrapArtifactSha256', 'profileSha256', 'nativeRoot', 'bootstrapRoot', 'issuedAt', 'expiresAt'} and
                 c['schema'] == 'amz.ap.public-beta.production-bootstrap-challenge.v1' and
                 type(c['nonce']) is str and re.fullmatch('[a-f0-9]{64}', c['nonce']) and c['profileSha256'] == PROFILE_SHA and
                 type(c['bootstrapArtifactSha256']) is str and re.fullmatch('[a-f0-9]{64}', c['bootstrapArtifactSha256']) and
                 c['nativeRoot'] == root_value(os.fstat(self.native)) and c['bootstrapRoot'] == root_value(os.fstat(self.boot)))
            need(type(c['process']) is dict and set(c['process']) == {'pid1StartTicks', 'workerStartTicks', 'workerPid'} and
                 type(c['process']['workerPid']) is int and c['process']['workerPid'] > 1 and
                 all(type(c['process'][k]) is str and re.fullmatch('[1-9][0-9]{0,19}', c['process'][k]) for k in ('pid1StartTicks', 'workerStartTicks')))
            budget.cap(c['issuedAt'], c['expiresAt'], 30000); self.current()
        except BaseException:
            self.close(); raise

    def current(self):
        self.budget.current()
        names = os.listdir(self.boot)
        need(4096 + sum(BOOT_CAPS.values()) <= 81920 and len(names) <= 10 and set(names) <= set(BOOT_CAPS) and
             max(os.fstat(self.boot).st_size, os.fstat(self.boot).st_blocks * 512) <= 4096)
        for name in names:
            info = os.stat(name, dir_fd=self.boot, follow_symlinks=False)
            # Other fixed metadata can be in its writer's link/fsync span.
            # This is only an allocation audit; seal/five-input authority below
            # still requires its original exact same-FD completed identities.
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 65532 and info.st_gid == 65532 and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink in (1, 2) and
                 (0 if name.startswith('.') else 1) <= info.st_size <= BOOT_CAPS[name])
            need(max(info.st_size, info.st_blocks * 512) <= BOOT_CAPS[name])
        for path, fd, expected in ((self.native_path, self.native, self.roots[0]), (self.boot_path, self.boot, self.roots[1])):
            # Does not traverse a root0700 ancestor from UID65532. The actual
            # root parent independently rechecks its named ancestry at each
            # exchange; these are kernel paths of the exact inherited dirFDs.
            need(os.readlink('/proc/self/fd/' + str(fd)) == str(path) and root_identity(os.fstat(fd)) == expected)
        if hasattr(self, 'challenge_fd'):
            need(private(os.fstat(self.challenge_fd), 4096) == self.challenge_stat == private(os.stat('challenge.json', dir_fd=self.boot, follow_symlinks=False), 4096) and
                 os.pread(self.challenge_fd, 4097, 0) == self.challenge_raw)
        # After the exclusive seal link, the actual worker may initialize its
        # native journal immediately. This producer still binds all FIVE input
        # inodes/bytes; it never attests that later native state is empty/Ready.
        names = set(os.listdir(self.native))
        need(set(self.created) <= names if self.published else names == set(self.created))
        for name, row in self.created.items():
            need(private(os.fstat(row['fd']), row['maximum']) == row['identity'] == private(os.stat(name, dir_fd=self.native, follow_symlinks=False), row['maximum']) and
                 os.pread(row['fd'], row['maximum'] + 1, 0) == row['raw'])
        if self.seal_record is not None:
            fd, expected, raw = self.seal_record
            need(private(os.fstat(fd), 16384) == expected == private(os.stat('seal.json', dir_fd=self.boot, follow_symlinks=False), 16384) and
                 os.pread(fd, 16385, 0) == raw)
        self.budget.current()

    def write(self, name, raw):
        self.current(); maximum = dict(FILES)[name]; need(0 < len(raw) <= maximum and name not in self.created)
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.native)
        self.handles.append(fd)  # Ownership begins before any later operation.
        pending = memoryview(raw)
        while pending:
            self.budget.current(); count = os.write(fd, pending[:65536]); need(count > 0); pending = pending[count:]
        os.fsync(fd); os.fsync(self.native)
        info = os.fstat(fd); expected = private(info, maximum)
        need(os.pread(fd, maximum + 1, 0) == raw and expected == private(os.stat(name, dir_fd=self.native, follow_symlinks=False), maximum))
        self.created[name] = {'fd': fd, 'identity': expected, 'raw': raw, 'maximum': maximum}; self.current()
        return info

    def rows(self):
        self.current(); need(set(self.created) == dict(FILES).keys())
        return [dict(name=name, bytes=len(self.created[name]['raw']), sha256=sha(self.created[name]['raw']),
                     **root_value(os.fstat(self.created[name]['fd'])), uid=65532, gid=65532, mode=0o600) for name, _ in FILES]

    def seal(self, raw):
        self.current(); need(0 < len(raw) <= 16384 and set(os.listdir(self.boot)) == {'challenge.json'})
        # The worker concurrently audits BOOT. Never expose a named pending
        # inode that can disappear between its list and stat calls.
        need(hasattr(os, 'O_TMPFILE'))
        fd = os.open('.', os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, 0o600, dir_fd=self.boot)
        self.handles.append(fd); pending = memoryview(raw)
        while pending:
            self.budget.current(); count = os.write(fd, pending); need(count > 0); pending = pending[count:]
        os.fsync(fd); before = private(os.fstat(fd), 16384, links=0)
        need(os.pread(fd, 16385, 0) == raw and identity(os.fstat(fd)) == before)
        libc = ctypes.CDLL(None, use_errno=True); link = libc.linkat
        link.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]; link.restype = ctypes.c_int
        source = ('/proc/self/fd/' + str(fd)).encode('ascii')
        self.current(); need(link(-100, source, self.boot, b'seal.json', 0x400) == 0); self.published = True
        os.fsync(self.boot); self.current()
        final = private(os.fstat(fd), 16384)
        need(final == private(os.stat('seal.json', dir_fd=self.boot, follow_symlinks=False), 16384) and
             final[:2] == before[:2] and os.pread(fd, 16385, 0) == raw)
        self.seal_record = (fd, final, raw); self.current()

    def close(self):
        first = None
        while self.handles:
            fd = self.handles.pop()
            try: os.close(fd)
            except OSError as error:
                if first is None: first = error
        if first is not None: raise first


def inputs(budget, owned):
    values, rows = [], []
    for fd, (name, maximum) in enumerate(FILES, 4):
        # These are private data descriptors, not paths, signatures or authority.
        info = os.fstat(fd); need(stat.S_ISREG(info.st_mode) and info.st_uid == 65532 and info.st_gid == 65532 and
                                  stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink in (0, 1) and 0 < info.st_size <= maximum and
                                  fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
        raw = bounded(fd, maximum, budget); owned.append(raw); values.append(raw)
        rows.append({'name': name, 'bytes': len(raw), 'sha256': sha(raw)})
    return values, rows


def prepared(values, server_uuid):
    lock, scope, config, seed, keys = decode(values[0], 2048), decode(values[1], 16384), decode(values[2], 16384), values[3], decode(values[4], 4096)
    need(set(lock) == {'schema', 'identity', 'serverUuid', 'nonce'} and lock['schema'] == 'amz.ap.public-beta.publication-lock.v1' and lock['serverUuid'] == server_uuid and uuid(lock['nonce']))
    binding = lock['identity']; need(type(binding) is dict and set(binding) == ID_FIELDS and binding['appVariant'] == 'public-beta' and binding['policyId'] == 'public-disposable-beta-v1')
    need(set(scope) == {'schema', 'identity', 'serverUuid', 'containerId', 'runtimeArtifactSha256', 'runtimeProfileSha256', 'publisherSourceSha256', 'runtimeSourceCommit', 'imageId', 'issuedAt', 'expiresAt'} and
         scope['schema'] == 'amz.ap.public-beta.publication-scope-input.v1' and scope['identity'] == binding and scope['serverUuid'] == server_uuid and
         scope['runtimeArtifactSha256'] == NATIVE['artifactSha256'] and scope['runtimeProfileSha256'] == NATIVE['profileSha256'] and
         scope['runtimeSourceCommit'] == NATIVE['sourceCommit'] and scope['publisherSourceSha256'] == 'f7cf95840762e7e28194b5a589014ceb88fbe95cde05b6b1737aadc8f0be2ce2' and
         type(scope['containerId']) is str and re.fullmatch('[a-f0-9]{64}', scope['containerId']) and
         type(scope['imageId']) is str and re.fullmatch('sha256:[a-f0-9]{64}', scope['imageId']))
    need(set(config) == {'schema', 'profileId', 'identity', 'runtimeArtifactSha256', 'executionProfileSha256', 'worldPackSha256', 'engineCommit', 'engineInventorySha256', 'seedArtifactSha256', 'password', 'port', 'journalMode', 'requiredCheckpointSha256', 'run', 'roster', 'browserBuildSha256'} and
         config['schema'] == 'amz.ap.public-beta.yacht-publication-configuration.v1' and config['profileId'] == 'public-yacht-publication-fresh-v1' and
         config['identity'] == binding and config['runtimeArtifactSha256'] == NATIVE['artifactSha256'] and config['executionProfileSha256'] == NATIVE['profileSha256'] and
         config['seedArtifactSha256'] == sha(seed) and seed[0] == 3 and config['journalMode'] == 'initialize' and config['requiredCheckpointSha256'] is None and
         type(config['password']) is str and re.fullmatch('[A-Za-z0-9_-]{32,128}', config['password']))
    need(set(keys) == {'schema', 'identity', 'runtimeArtifactSha256', 'runSha256', 'observationKey', 'effectsKey'} and
         keys['schema'] == 'amz.ap.public-beta.yacht-runtime-keys.v1' and keys['identity'] == binding and
         keys['runtimeArtifactSha256'] == NATIVE['artifactSha256'] and keys['runSha256'] == sha(canonical(config['run'])) and
         all(type(keys[k]) is str and re.fullmatch('[a-f0-9]{64}', keys[k]) for k in ('observationKey', 'effectsKey')) and
         keys['observationKey'] != keys['effectsKey'])
    return lock, scope, config, seed, keys


def verify_return(raw, namespace, prepare, operation_id, rows, scope_sha, budget):
    # No cryptographic claim here. The independent owner signs; PID1 checks
    # actual Ed25519. This exact projection prevents publishing a miscorrelated
    # owner's response and rechecks the original short window before linkat.
    envelope = decode(raw, 16384); need(set(envelope) == {'schema', 'body', 'signature'} and envelope['schema'] == 'amz.ap.public-beta.production-bootstrap-envelope.v1')
    body = envelope['body']; challenge = namespace.challenge
    need(type(envelope['signature']) is str and len(base64.b64decode(envelope['signature'], validate=True)) == 64 and
         set(body) == {'schema', 'sealId', 'operationId', 'nonce', 'challengeSha256', 'process', 'identity', 'native', 'bootstrapArtifactSha256', 'provider', 'files', 'launch', 'issuedAt', 'expiresAt'} and
         body['schema'] == DOMAIN and uuid(body['sealId']) and body['operationId'] == operation_id and
         body['nonce'] == challenge['nonce'] and body['challengeSha256'] == sha(namespace.challenge_raw) and
         body['process'] == challenge['process'] and body['identity'] == prepare['identity'] and body['native'] == NATIVE and
         body['bootstrapArtifactSha256'] == challenge['bootstrapArtifactSha256'] and body['provider'] == prepare['provider'] and body['files'] == rows)
    launch = body['launch']; need(type(launch) is dict and set(launch) == {'schema', 'body', 'signature'} and launch['schema'] == 'amz.ap.public-beta.yacht-provider-launch-envelope.v1')
    value = launch['body']; need(type(value) is dict and value.get('schema') == LAUNCH and value.get('operationId') == operation_id and
                              value.get('filesSha256') == sha(canonical(rows)) and value.get('publicationScopeSha256') == scope_sha)
    budget.cap(body['issuedAt'], body['expiresAt'], 5000)


def main(argv=None):
    owned, descriptors, channel, namespace = [], list(range(4, 9)), None, None
    result = None; failed = False
    try:
        argv = list(sys.argv[1:] if argv is None else argv)
        need(sys.platform == 'linux' and sys.version_info[:2] == (3, 12) and os.getuid() == 65532 and os.getgid() == 65532 and
             sys.flags.isolated == 1 and sys.flags.ignore_environment == 1 and
             len(argv) == 2 and argv[0] == '--server-uuid' and uuid(argv[1]) and Path(__file__).absolute() == ENTRY)
        with open('/proc/self/status', 'rb', buffering=0) as stream: status_raw = stream.read(65537)
        need(0 < len(status_raw) <= 65536)
        status = dict(line.split(':', 1) for line in status_raw.decode('ascii').splitlines() if ':' in line)
        need(status['Uid'].split() == ['65532'] * 4 and status['Gid'].split() == ['65532'] * 4 and
             status['Groups'].strip() == '' and status['NoNewPrivs'].strip() == '1' and
             all(int(status[k].strip(), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')))
        os.umask(0o077); budget = Budget(); channel = Channel(budget)
        namespace = Namespace(argv[1], budget); values, input_rows = inputs(budget, owned)
        lock, scope, config, seed, keys = prepared(values, argv[1])
        budget.cap(scope['issuedAt'], scope['expiresAt'], 86400000)
        peer = os.fstat(3); nonce = secrets.token_hex(32)
        request = {'nonce': nonce, 'serverUuid': argv[1], 'publisher': {'pid': os.getpid(), 'parentPid': os.getppid(), 'startTicks': process_start(os.getpid()),
                   'uid': os.getuid(), 'gid': os.getgid(), 'fd3': root_value(peer)}, 'challenge': namespace.challenge,
                   'nativeRoot': root_value(os.fstat(namespace.native)), 'bootstrapRoot': root_value(os.fstat(namespace.boot)),
                   'inputs': input_rows, 'issuedAt': iso(budget.start), 'expiresAt': iso(budget.expiry)}
        request_sha = sha(canonical(request)); reply = channel.exchange('prepare', request, 'prewrite-authorized')
        need(set(reply) == {'nonce', 'requestSha256', 'operationId', 'issuedAt', 'expiresAt'} and reply['nonce'] == nonce and reply['requestSha256'] == request_sha and uuid(reply['operationId']))
        budget.cap(reply['issuedAt'], reply['expiresAt'], 5000); operation_id = reply['operationId']; namespace.current()
        info = namespace.write(FILES[0][0], values[0])
        final_scope = dict(scope, schema='amz.ap.public-beta.publication-scope.v1', rootDevice=root_value(os.fstat(namespace.native))['device'],
                           rootInode=str(os.fstat(namespace.native).st_ino), lockDevice=root_value(info)['device'], lockInode=str(info.st_ino), lockSha256=sha(values[0]))
        scope_raw = bytearray(canonical(final_scope)); owned.append(scope_raw); scope_sha = sha(scope_raw)
        namespace.write(FILES[1][0], scope_raw)
        config_raw = bytearray(canonical(dict(config, publicationScopeSha256=scope_sha))); owned.append(config_raw)
        namespace.write(FILES[2][0], config_raw); namespace.write(FILES[3][0], seed); namespace.write(FILES[4][0], values[4])
        rows = namespace.rows()
        handoff = {'nonce': nonce, 'operationId': operation_id, 'challengeSha256': sha(namespace.challenge_raw), 'files': rows,
                   'publicationScopeSha256': scope_sha, 'requestSha256': request_sha}
        reply = channel.exchange('files-created', handoff, 'seal-authorized')
        need(set(reply) == {'nonce', 'requestSha256', 'sealBase64'} and reply['nonce'] == nonce and reply['requestSha256'] == sha(canonical(handoff)) and type(reply['sealBase64']) is str)
        seal = bytearray(base64.b64decode(reply['sealBase64'], validate=True)); owned.append(seal)
        need(base64.b64encode(seal).decode('ascii') == reply['sealBase64'])
        provider = {k: scope[k] for k in ('serverUuid', 'containerId', 'imageId')}; provider.update(volumeId=scope['serverUuid'], attestation='current-provider-launch-v1')
        verify_return(seal, namespace, {'identity': lock['identity'], 'provider': provider}, operation_id, rows, scope_sha, budget)
        namespace.seal(seal)
        result = {'nonce': nonce, 'operationId': operation_id, 'sealSha256': sha(seal), 'filesSha256': sha(canonical(rows)), 'publicationScopeSha256': scope_sha}
        need(channel.exchange('published', result, 'published-accepted') == result); namespace.current(); budget.current()
    except BaseException:
        failed = True
    finally:
        # Wipe every owned input before any once-only close can fail. Never
        # unlink native/metadata files or guess that a failed close freed them.
        for raw in owned: raw[:] = b'\0' * len(raw)
        closers = []
        if namespace is not None: closers.append(namespace.close)
        if channel is not None: closers.append(channel.close)
        for fd in descriptors: closers.append(lambda fd=fd: os.close(fd))
        for close in closers:
            try: close()
            except BaseException: failed = True
    if failed: return 1
    try:
        budget.current(); sys.stdout.write(canonical({'schema': 'amz.ap.public-beta.production-bootstrap-published.v1', **result,
            'runtimeInitialized': False, 'resourceReleaseAuthorized': False}).decode() + '\n'); sys.stdout.flush(); budget.current(); return 0
    except BaseException: return 1


if __name__ == '__main__': raise SystemExit(main())

"""Unregistered Linux publication kernel. No bootstrap, CLI, or native proof.

An independently pinned scope file conveys custody/integrity only. This module
does not verify current deployment authority, MFA, placement, or a node permit.
All participants must use the same enrolled lock in a future runtime profile.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
import weakref

try:
    import fcntl
except ImportError:
    fcntl = None

RUNTIME_ROOT = '/home/container/.amz'
HOST_ROOT = '/srv/public-beta/wings/data'
OWNER_UID = 65532
OWNER_GID = 65532
SCOPE = 'public-publication-scope.json'
LOCK = 'public-control-publication.lock'
LIMIT = 65536
AGGREGATE = 3 * 1024 * 1024
METADATA = 256 * 1024
CONTROLS = {'gateway': 'public-gateway-control.json',
            'yacht-observation': 'public-yacht-observation-control.json',
            'yacht-effects': 'public-yacht-effects-control.json'}
CAPS = {'public-runtime.json': 16384, 'public-yacht-keys.json': 4096,
        'public-seed.archipelago': 524288, 'public-seed.apsave': 524288,
        'public-gateway-native.lock': 1024, 'public-gateway-journal.json': 524288,
        'public-yacht-effects-journal.json': 524288,
        'public-yacht-observation-ack.json': 524288,
        'public-gateway-ack.json': 65536, 'public-yacht-effects-ack.json': 65536,
        'public-runtime-status.json': 16384, SCOPE: 16384, LOCK: 2048,
        **{name: LIMIT for name in CONTROLS.values()}}
EXTERNAL_RESERVE = 2 * LIMIT * len(CONTROLS)
IDENTITY = ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId',
            'externalId', 'allocationRevision', 'serverId', 'attemptId',
            'seedRevision', 'credentialEpoch', 'runtimeLaunchId')
UUID = re.compile(r'^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
SHA = re.compile(r'^[a-f0-9]{64}$')
_SCOPES = weakref.WeakKeyDictionary()
_LOCKS = weakref.WeakKeyDictionary()
_WINDOWS = weakref.WeakKeyDictionary()
_PUBLISHERS = weakref.WeakKeyDictionary()


class PublicationRefused(RuntimeError):
    """Fixed codes only. Never include payloads, paths, or secret bytes."""


def _need(value, code='publication_refused'):
    if not value:
        raise PublicationRefused(code)


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _tree(value, depth=0):
    _need(depth <= 48, 'publication_json')
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        _need(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), 'publication_json')
        return
    if type(value) is int:
        _need(abs(value) <= 9007199254740991, 'publication_json')
        return
    _need(type(value) in (dict, list), 'publication_json')
    if type(value) is dict:
        _need(all(type(k) is str for k in value), 'publication_json')
        for k, v in value.items():
            _tree(k, depth + 1); _tree(v, depth + 1)
    else:
        for v in value:
            _tree(v, depth + 1)


def _canonical(value):
    _tree(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (ValueError, UnicodeError, RecursionError):
        raise PublicationRefused('publication_json') from None


def _pairs(pairs):
    value = {}
    for k, v in pairs:
        _need(k not in value, 'publication_json')
        value[k] = v
    return value


def _decode(raw, maximum):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, 'publication_limit')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _need(False, 'publication_json'))
    except (ValueError, UnicodeError, RecursionError):
        raise PublicationRefused('publication_json') from None
    _need(type(value) is dict and _canonical(value) == raw, 'publication_canonical')
    return value


def _instant(value):
    _need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', value), 'publication_time')
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        _need(date.isoformat(timespec='milliseconds').replace('+00:00', 'Z') == value, 'publication_time')
        return int(date.timestamp() * 1000)
    except (ValueError, OverflowError):
        raise PublicationRefused('publication_time') from None


def _wall():
    return time.time_ns() // 1000000


class PublicationWindow:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise PublicationRefused('publication_window_brand')

    def cancel(self):
        _window_state(self)['cancelled'] = True


def capture_window(issued_at, expires_at):
    """Capture remaining original time before any filesystem IO; never renew it."""
    mono, now = time.monotonic_ns(), _wall()
    issued, expiry = _instant(issued_at), _instant(expires_at)
    _need(issued <= now < expiry and 0 < expiry - issued <= 5000, 'publication_expired')
    window = object.__new__(PublicationWindow)
    _WINDOWS[window] = {'issued': issued_at, 'expires': expires_at, 'expiry': expiry,
                        'deadline': mono + (expiry - now) * 1000000,
                        'wallFloor': now, 'monoFloor': mono, 'cancelled': False}
    return window


def _window_state(window):
    _need(type(window) is PublicationWindow and window in _WINDOWS, 'publication_window_brand')
    return _WINDOWS[window]


def _current_window(window):
    value = _window_state(window)
    mono, now = time.monotonic_ns(), _wall()
    _need(not value['cancelled'] and value['wallFloor'] <= now < value['expiry'] and
          value['monoFloor'] <= mono < value['deadline'], 'publication_expired')
    value['wallFloor'], value['monoFloor'] = now, mono
    return value


def _linux():
    _need(sys.platform == 'linux' and os.name == 'posix' and fcntl is not None and
          all(hasattr(os, k) for k in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC', 'pread')),
          'publication_linux_required')
    _need(os.geteuid() == OWNER_UID and os.getegid() == OWNER_GID, 'publication_principal')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _regular(info, maximum):
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER_UID and info.st_gid == OWNER_GID and
          stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
          0 < info.st_size <= maximum, 'publication_file_identity')
    return _identity(info)


def _open_root(root):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(root).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == OWNER_UID and info.st_gid == OWNER_GID and
              stat.S_IMODE(info.st_mode) == 0o700, 'publication_root_identity')
        return fd
    except BaseException:
        os.close(fd); raise


def _entry(fd, name):
    try:
        return os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _read(fd, directory, name, maximum):
    before = _entry(directory, name)
    _need(before is not None, 'publication_file_missing')
    identity = _regular(before, maximum)
    _need(_regular(os.fstat(fd), maximum) == identity, 'publication_file_changed')
    raw = os.pread(fd, maximum + 1, 0)
    after = _entry(directory, name)
    _need(after is not None and _regular(after, maximum) == identity and
          _regular(os.fstat(fd), maximum) == identity and len(raw) == before.st_size,
          'publication_file_changed')
    return raw, identity


def _read_named(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        return _read(fd, directory, name, maximum)
    finally:
        os.close(fd)


def _check_identity(value):
    _need(_exact(value, IDENTITY) and value['appVariant'] == 'public-beta' and
          value['policyId'] == 'public-disposable-beta-v1', 'publication_binding')
    _need(all(type(value[k]) is str and UUID.fullmatch(value[k]) for k in
              ('environmentId', 'dataEpoch', 'roomId', 'attemptId', 'runtimeLaunchId')), 'publication_binding')
    _need(all(type(value[k]) is int and 1 <= value[k] <= 1000000000 for k in
              ('allocationRevision', 'seedRevision', 'credentialEpoch')), 'publication_binding')
    _need(value['externalId'] == 'ap-beta-' + value['roomId'] + '-r' + str(value['allocationRevision']) and
          type(value['serverId']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value['serverId']), 'publication_binding')


class PublicationScope:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise PublicationRefused('publication_scope_brand')

    def close(self):
        value = _scope_state(self)
        with value['lifecycle']:
            _need(_SCOPES.get(self) is value, 'publication_scope_brand')
            reference = value.get('lock')
            _need(reference is None or reference() is None or reference() not in _LOCKS, 'publication_lock_open')
            del _SCOPES[self]
            try:
                os.close(value['enrollmentFd'])
            finally:
                os.close(value['directory'])


def _scope_state(scope):
    _need(type(scope) is PublicationScope and scope in _SCOPES, 'publication_scope_brand')
    value = _SCOPES[scope]
    _need(value['pid'] == os.getpid(), 'publication_scope_process')
    return value


def _scope_current(scope, window):
    value = _scope_state(scope)
    with value['lifecycle']:
        _need(_SCOPES.get(scope) is value, 'publication_scope_brand')
        return _scope_current_locked(value, window)


def _scope_current_locked(value, window):
    _need(not value['held'], 'publication_scope_held')
    _scope_time(value, window)
    _check_root(value)
    raw, identity = _read(value['enrollmentFd'], value['directory'], SCOPE, CAPS[SCOPE])
    _need(identity == value['enrollmentIdentity'] and raw == value['raw'], 'publication_scope_changed')
    _check_root(value)
    _scope_time(value, window)  # Independent scope deadline also survives slow IO/stalled wall time.
    return value


def _check_root(value):
    other = _open_root(value['root'])
    try:
        _need((os.fstat(other).st_dev, os.fstat(other).st_ino) == value['rootIdentity'] and
              (os.fstat(value['directory']).st_dev, os.fstat(value['directory']).st_ino) == value['rootIdentity'],
              'publication_root_changed')
    finally:
        os.close(other)


def _scope_time(value, window):
    current = _current_window(window)
    mono = time.monotonic_ns()
    _need(value['wallFloor'] <= current['wallFloor'] < _instant(value['enrollment']['expiresAt']) and
          value['monoFloor'] <= mono < value['deadline'], 'publication_scope_expired')
    value['wallFloor'], value['monoFloor'] = current['wallFloor'], mono


def _capture(root, expected, server_uuid, window):
    _current_window(window); _linux()
    _need(type(expected) is str and SHA.fullmatch(expected), 'publication_scope_pin')
    directory = enrollment_fd = None
    try:
        directory = _open_root(root); _current_window(window)
        enrollment_fd = os.open(SCOPE, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        raw, file_identity = _read(enrollment_fd, directory, SCOPE, CAPS[SCOPE]); _current_window(window)
        _need(_sha(raw) == expected, 'publication_scope_pin')
        value = _decode(raw, CAPS[SCOPE])
        fields = ('schema', 'identity', 'serverUuid', 'containerId', 'rootDevice', 'rootInode',
                  'lockDevice', 'lockInode', 'lockSha256', 'runtimeArtifactSha256', 'runtimeProfileSha256',
                  'publisherSourceSha256', 'runtimeSourceCommit', 'imageId', 'issuedAt', 'expiresAt')
        _need(_exact(value, fields) and value['schema'] == 'amz.ap.public-beta.publication-scope.v1', 'publication_scope')
        _check_identity(value['identity'])
        _need(type(value['serverUuid']) is str and UUID.fullmatch(value['serverUuid']) and
              (server_uuid is None or server_uuid == value['serverUuid']) and
              type(value['containerId']) is str and SHA.fullmatch(value['containerId']), 'publication_scope')
        _need(all(type(value[k]) is str and SHA.fullmatch(value[k]) for k in
                  ('lockSha256', 'runtimeArtifactSha256', 'runtimeProfileSha256', 'publisherSourceSha256')) and
              type(value['runtimeSourceCommit']) is str and re.fullmatch(r'[a-f0-9]{40}', value['runtimeSourceCommit']) and
              type(value['imageId']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value['imageId']), 'publication_scope')
        for name in ('rootInode', 'lockInode'):
            _need(type(value[name]) is str and re.fullmatch(r'[1-9][0-9]{0,19}', value[name]), 'publication_scope')
        for name in ('rootDevice', 'lockDevice'):
            _need(type(value[name]) is str and re.fullmatch(r'[0-9]{1,10}:[0-9]{1,10}', value[name]), 'publication_scope')
        info = os.fstat(directory)
        _need(value['rootDevice'] == str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)) and
              value['rootInode'] == str(info.st_ino) and file_identity[0] == info.st_dev,
              'publication_root_pin')
        now = _current_window(window)['wallFloor']
        issued, expiry = _instant(value['issuedAt']), _instant(value['expiresAt'])
        _need(issued <= now < expiry and 0 < expiry - issued <= 86400000, 'publication_scope_expired')
        mono = time.monotonic_ns()
        anchor = _window_state(window)
        deadline = anchor['deadline'] + (expiry - anchor['expiry']) * 1000000
        _need(mono < deadline, 'publication_scope_expired')
        scope = object.__new__(PublicationScope)
        _SCOPES[scope] = {'root': root, 'directory': directory, 'rootIdentity': (info.st_dev, info.st_ino),
                          'enrollmentFd': enrollment_fd, 'enrollmentIdentity': file_identity,
                          'raw': raw, 'enrollment': value, 'held': False,
                          'wallFloor': now, 'monoFloor': mono, 'deadline': deadline,
                          'lifecycle': threading.RLock(), 'pid': os.getpid()}
        directory = enrollment_fd = None
        try:
            _scope_current(scope, window)
        except BaseException:
            captured = _SCOPES.pop(scope)
            os.close(captured['enrollmentFd']); os.close(captured['directory'])
            raise
        return scope
    finally:
        if enrollment_fd is not None: os.close(enrollment_fd)
        if directory is not None: os.close(directory)


def capture_runtime_scope(expected_enrollment_sha256, window):
    return _capture(RUNTIME_ROOT, expected_enrollment_sha256, None, window)


def capture_host_scope(server_uuid, expected_enrollment_sha256, window):
    _need(type(server_uuid) is str and UUID.fullmatch(server_uuid), 'publication_server_uuid')
    return _capture(HOST_ROOT + '/' + server_uuid + '/.amz', expected_enrollment_sha256, server_uuid, window)


def _lock_state(lock):
    _need(type(lock) is PublicationLock and lock in _LOCKS, 'publication_lock_brand')
    state = _LOCKS[lock]
    _scope_state(state['scope'])  # An inherited FD must not unlock its parent's flock.
    return state


def _lock_current(lock, window):
    state = _lock_state(lock); value = _scope_current(state['scope'], window)
    raw, identity = _read(state['fd'], value['directory'], LOCK, CAPS[LOCK])
    _need(identity == state['identity'] and raw == state['raw'], 'publication_lock_changed')
    _scope_time(value, window)
    return state, value


class PublicationLock:
    __slots__ = ('__weakref__',)

    def __init__(self, scope, window):
        _need(type(self) is PublicationLock, 'publication_lock_type')
        value = _scope_state(scope)
        with value['lifecycle']:
            _need(_SCOPES.get(scope) is value, 'publication_scope_brand')
            _scope_current(scope, window)
            reference = value.get('lock')
            _need(reference is None or reference() is None or reference() not in _LOCKS, 'publication_lock_open')
            fd = os.open(LOCK, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=value['directory'])
            try:
                raw, identity = _read(fd, value['directory'], LOCK, CAPS[LOCK])
                document = _decode(raw, CAPS[LOCK]); enrolled = value['enrollment']
                _need(_exact(document, ('schema', 'identity', 'serverUuid', 'nonce')) and
                      document['schema'] == 'amz.ap.public-beta.publication-lock.v1' and
                      document['identity'] == enrolled['identity'] and document['serverUuid'] == enrolled['serverUuid'] and
                      type(document['nonce']) is str and UUID.fullmatch(document['nonce']), 'publication_lock_binding')
                info = os.fstat(fd)
                _need(_sha(raw) == enrolled['lockSha256'] and enrolled['lockDevice'] ==
                      str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)) and
                      str(info.st_ino) == enrolled['lockInode'] and info.st_dev == value['rootIdentity'][0],
                      'publication_lock_pin')
                _scope_current(scope, window)
                _LOCKS[self] = {'scope': scope, 'fd': fd, 'identity': identity, 'raw': raw,
                                'mutex': threading.RLock(), 'depth': 0, 'thread': None, 'closed': False}
                value['lock'] = weakref.ref(self)
            except BaseException:
                _LOCKS.pop(self, None)
                os.close(fd); raise

    @contextmanager
    def hold(self, window):
        state = _lock_state(self)  # No FD IO before owning this state's mutex.
        # RLock waiting must consume the same original deadline as kernel waiting.
        while not state['mutex'].acquire(blocking=False):
            _current_window(window); time.sleep(0.001)
        entered = admitted = False
        try:
            _need(_LOCKS.get(self) is state and not state['closed'], 'publication_lock_brand')
            admitted = True
            _lock_current(self, window)
            if state['depth'] == 0:
                while True:
                    _lock_current(self, window)
                    try:
                        fcntl.flock(state['fd'], fcntl.LOCK_EX | fcntl.LOCK_NB); break
                    except BlockingIOError:
                        time.sleep(0.001)
                state['thread'] = threading.get_ident()
            else:
                _need(state['thread'] == threading.get_ident(), 'publication_lock_thread')
            state['depth'] += 1; entered = True
            _lock_current(self, window)
            yield self
            _lock_current(self, window)
        finally:
            try:
                if entered:
                    state['depth'] -= 1
                # Also covers a signal immediately after flock returned but
                # before depth was incremented. An outer reentrant hold is
                # never unlocked. LOCK_UN on an unheld FD cannot unlock a
                # different process's independent open-file description.
                if admitted and _LOCKS.get(self) is state and not state['closed'] and state['depth'] == 0:
                    fcntl.flock(state['fd'], fcntl.LOCK_UN); state['thread'] = None
            finally:
                state['mutex'].release()

    def close(self):
        state = _lock_state(self)
        _need(state['mutex'].acquire(blocking=False), 'publication_lock_busy')
        try:
            _need(_LOCKS.get(self) is state and not state['closed'] and state['depth'] == 0, 'publication_lock_busy')
            scope_value = _scope_state(state['scope'])
            with scope_value['lifecycle']:
                state['closed'] = True
                del _LOCKS[self]
                try:
                    os.close(state['fd'])
                except BaseException:
                    scope_value['held'] = True
                    raise
        finally:
            state['mutex'].release()


def _pending(name):
    return '.' + name + '.publication-pending'


def _audit(value):
    sizes = {}
    with os.scandir(value['directory']) as entries:
        for count, entry in enumerate(entries):
            _need(count < len(CAPS) and entry.name in CAPS, 'publication_unknown_or_pending')
            info = _entry(value['directory'], entry.name)
            _need(info is not None, 'publication_file_changed')
            _need(info.st_dev == value['rootIdentity'][0], 'publication_file_device')
            _regular(info, CAPS[entry.name]); sizes[entry.name] = info.st_size
    # The entire current+pending control maxima remain charged even if absent.
    _need(METADATA + EXTERNAL_RESERVE + sum(size for name, size in sizes.items()
          if name not in CONTROLS.values()) <= AGGREGATE, 'publication_budget')


def _command(kind, operation_id, raw, window, value):
    _need(type(kind) is str and kind in CONTROLS and type(operation_id) is str and UUID.fullmatch(operation_id),
          'publication_purpose')
    command = _decode(raw, LIMIT); w = _current_window(window)
    _need(command.get('identity') == value['enrollment']['identity'] and command.get('issuedAt') == w['issued'] and
          command.get('expiresAt') == w['expires'], 'publication_payload_binding')
    if kind == 'gateway':
        _need(_exact(command, ('schema', 'operationId', 'command', 'identity', 'gate', 'payload', 'issuedAt', 'expiresAt')) and
              command['schema'] == 'amz.ap.public-beta.gateway-control.v2' and command['operationId'] == operation_id and
              command['command'] in ('prepare_connection', 'confirm_connection', 'detach_slot', 'revoke_slot', 'idle_fence') and
              type(command['payload']) is dict and type(command['gate']) in (dict, type(None)), 'publication_payload_binding')
    elif kind == 'yacht-observation':
        _need(_exact(command, ('schema', 'requestId', 'identity', 'actorUuid', 'issuedAt', 'expiresAt', 'requestMac')) and
              command['schema'] == 'amz.ap.public-beta.yacht-observation-control.v1' and command['requestId'] == operation_id and
              type(command['actorUuid']) is str and UUID.fullmatch(command['actorUuid']) and
              type(command['requestMac']) is str and SHA.fullmatch(command['requestMac']), 'publication_payload_binding')
    else:
        _need(_exact(command, ('schema', 'deliveryId', 'identity', 'issuedAt', 'expiresAt', 'commit', 'commitMac', 'deliveryMac')) and
              command['schema'] == 'amz.ap.public-beta.yacht-effects-control.v1' and command['deliveryId'] == operation_id and
              type(command['commit']) is dict and all(type(command[k]) is str and SHA.fullmatch(command[k])
              for k in ('commitMac', 'deliveryMac')), 'publication_payload_binding')
    # Native validation remains authoritative, including both MAC purposes.


class FixedControlPublisher:
    __slots__ = ('__weakref__',)

    def __init__(self, scope, lock, window):
        _need(type(self) is FixedControlPublisher, 'publication_publisher_type')
        with lock.hold(window):
            state, _ = _lock_current(lock, window)
            _need(state['scope'] is scope, 'publication_scope_mismatch')
            _PUBLISHERS[self] = (scope, lock)

    def publish(self, kind, operation_id, raw, window):
        _need(type(self) is FixedControlPublisher and self in _PUBLISHERS, 'publication_publisher_brand')
        scope, lock = _PUBLISHERS[self]
        value = _scope_current(scope, window)
        _command(kind, operation_id, raw, window, value)
        name, temporary = CONTROLS[kind], _pending(CONTROLS[kind])
        attempted = False; fd = None
        try:
            with lock.hold(window):
                _audit(value); _lock_current(lock, window)
                previous = _entry(value['directory'], name)
                previous_raw = None if previous is None else _read_named(value['directory'], name, LIMIT)[0]
                if previous_raw is not None:
                    previous_value = _decode(previous_raw, LIMIT)
                    _need(previous_value.get('schema') == _decode(raw, LIMIT)['schema'] and
                          previous_value.get('identity') == value['enrollment']['identity'], 'publication_previous_binding')
                    id_field = {'gateway': 'operationId', 'yacht-observation': 'requestId',
                                'yacht-effects': 'deliveryId'}[kind]
                    _need(previous_value.get(id_field) != operation_id or previous_raw == raw,
                          'publication_operation_conflict')
                _lock_current(lock, window)
                attempted = True
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=value['directory'])
                remaining = memoryview(raw)
                while remaining:
                    _lock_current(lock, window)
                    written = os.write(fd, remaining); _need(written > 0, 'publication_write')
                    remaining = remaining[written:]
                os.fsync(fd); _lock_current(lock, window)
                staged = _regular(os.fstat(fd), LIMIT)
                _need(_entry(value['directory'], temporary) is not None and
                      _regular(_entry(value['directory'], temporary), LIMIT) == staged, 'publication_pending_changed')
                # Retain the write descriptor and open an independent bounded read descriptor.
                verified, verified_identity = _read_named(value['directory'], temporary, LIMIT)
                _need(verified == raw and verified_identity == staged, 'publication_pending_changed')
                _lock_current(lock, window)
                _need(_entry(value['directory'], name) is None if previous is None else
                      _entry(value['directory'], name) is not None and
                      _regular(_entry(value['directory'], name), LIMIT) == _regular(previous, LIMIT),
                      'publication_target_changed')
                os.replace(temporary, name, src_dir_fd=value['directory'], dst_dir_fd=value['directory'])
                os.fsync(value['directory']); _lock_current(lock, window)
                final_raw, final_identity = _read_named(value['directory'], name, LIMIT)
                _need(final_raw == raw and final_identity == _regular(os.fstat(fd), LIMIT), 'publication_readback')
                _audit(value); _lock_current(lock, window)
                closing, fd = fd, None  # A failed close must never retry a reused numeric FD.
                os.close(closing)
                _lock_current(lock, window)
            _scope_current(scope, window)
            return {'schema': 'amz.ap.public-beta.fixed-control-publication.v1', 'kind': kind,
                    'operationId': operation_id, 'payloadSha256': _sha(raw), 'bytes': len(raw),
                    'previousSha256': None if previous_raw is None else _sha(previous_raw),
                    'enrollmentSha256': _sha(value['raw']), 'sourceOnly': True, 'activation': False,
                    'nativeAcknowledged': False, 'nativeSaveDurable': False,
                    'resourceReleaseAuthorized': False, 'qualification': False}
        except BaseException:
            if attempted: value['held'] = True
            raise
        finally:
            if fd is not None:
                closing, fd = fd, None
                try:
                    os.close(closing)
                except BaseException:
                    value['held'] = True
                    raise

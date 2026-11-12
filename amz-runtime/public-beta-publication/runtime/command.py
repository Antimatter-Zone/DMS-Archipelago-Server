"""Uninstalled, one-shot private publication command; no transport authority.

Only an independently protected launcher may select the boot server/scope pin.
The stdin protocol cannot select a host, path, principal, key or executable.
Nothing here enrolls that launcher, a provider target, an image or a node.
"""
import base64
import builtins
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import threading
import time
import types
import weakref

KERNEL_SHA256 = 'f7cf95840762e7e28194b5a589014ceb88fbe95cde05b6b1737aadc8f0be2ce2'
REQUEST_SCHEMA = 'amz.ap.public-beta.publication-command.v1'
RESPONSE_SCHEMA = 'amz.ap.public-beta.publication-command-result.v1'
REQUEST_LIMIT = 98304
RESPONSE_LIMIT = 720896
READS = types.MappingProxyType({
    'gateway-ack': ('public-gateway-ack.json', 65536),
    'yacht-observation-ack': ('public-yacht-observation-ack.json', 524288),
    'yacht-effects-ack': ('public-yacht-effects-ack.json', 65536),
    'status': ('public-runtime-status.json', 16384),
})
_STDLIB = frozenset(('contextlib', 'datetime', 'fcntl', 'hashlib', 'json', 'os',
                     'pathlib', 're', 'stat', 'sys', 'threading', 'time', 'weakref'))
_SOURCES = weakref.WeakKeyDictionary()
_WINDOWS = weakref.WeakKeyDictionary()
_COMMANDS = weakref.WeakKeyDictionary()


class PublicationCommandRefused(RuntimeError):
    def __init__(self, code='publication_command_refused', *, process_exit_required=False):
        super().__init__(code)
        self.process_exit_required = process_exit_required
        self.activation = False


def _need(value, code='publication_command_refused'):
    if not value: raise PublicationCommandRefused(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _need(key not in value, 'publication_command_json')
        value[key] = item
    return value


def _decode(raw, maximum):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, 'publication_command_limit')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _need(False, 'publication_command_json'))
        _need(type(value) is dict and _canonical(value) == raw, 'publication_command_canonical')
        return value
    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise PublicationCommandRefused('publication_command_json') from None


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _instant(value):
    _need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', value),
          'publication_command_time')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        _need(parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') == value,
              'publication_command_time')
        return int(parsed.timestamp() * 1000)
    except (ValueError, OverflowError):
        raise PublicationCommandRefused('publication_command_time') from None


class _OriginalWindow:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise PublicationCommandRefused('publication_command_window_brand')


def _capture_window(issued_at, expires_at):
    # This precedes source reads, stdin and target IO in the explicit CLI.
    mono, wall = time.monotonic_ns(), time.time_ns() // 1000000
    issued, expiry = _instant(issued_at), _instant(expires_at)
    _need(issued <= wall < expiry and 0 < expiry - issued <= 5000, 'publication_command_expired')
    window = object.__new__(_OriginalWindow)
    _WINDOWS[window] = {'issued': issued_at, 'expires': expires_at, 'expiry': expiry,
                        'deadline': mono + (expiry - wall) * 1000000,
                        'wallFloor': wall, 'monoFloor': mono, 'cancelled': False}
    return window


def _current_window(window):
    _need(type(window) is _OriginalWindow and window in _WINDOWS, 'publication_command_window_brand')
    value = _WINDOWS[window]
    mono, wall = time.monotonic_ns(), time.time_ns() // 1000000
    _need(not value['cancelled'] and value['wallFloor'] <= wall < value['expiry'] and
          value['monoFloor'] <= mono < value['deadline'], 'publication_command_expired')
    value['wallFloor'], value['monoFloor'] = wall, mono
    return value


class CapturedCommandSources:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise PublicationCommandRefused('publication_command_source_brand')


def capture_command_sources(kernel_raw):
    """Exact fixed bytes only, before compile/import; no caller module is trusted."""
    _need(type(kernel_raw) is bytes and 0 < len(kernel_raw) <= 65536 and
          _sha(kernel_raw) == KERNEL_SHA256, 'publication_command_source_pin')
    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        _need(level == 0 and name in _STDLIB, 'publication_command_source_import')
        return builtins.__import__(name, globals, locals, fromlist, level)
    module = types.ModuleType('captured_publication_command_kernel')
    module.__dict__['__file__'] = '<captured:' + KERNEL_SHA256 + ':publication>'
    module.__dict__['__builtins__'] = {**vars(builtins), '__import__': fixed_import}
    exec(compile(kernel_raw, module.__dict__['__file__'], 'exec'), module.__dict__)
    sources = object.__new__(CapturedCommandSources)
    _SOURCES[sources] = {'kernel': module, 'pid': os.getpid()}
    return sources


def _sources(sources):
    _need(type(sources) is CapturedCommandSources and sources in _SOURCES and
          _SOURCES[sources]['pid'] == os.getpid(), 'publication_command_source_brand')
    return _SOURCES[sources]['kernel']


def _current(state):
    _need(state['pid'] == os.getpid() and not state['closed'] and not state['uncertain'],
          'publication_command_held')
    _current_window(state['window'])
    state['kernel']._lock_current(state['lock'], state['nativeWindow'])
    _current_window(state['window'])


def _state(command):
    _need(type(command) is HostPublicationCommand and command in _COMMANDS,
          'publication_command_brand')
    state = _COMMANDS[command]
    _need(state['pid'] == os.getpid(), 'publication_command_pid')
    return state


def _request(raw, state):
    request = _decode(raw, REQUEST_LIMIT)
    _need(_exact(request, ('schema', 'requestId', 'identity', 'issuedAt', 'expiresAt',
                           'action', 'channel', 'payload')) and request['schema'] == REQUEST_SCHEMA,
          'publication_command_request')
    kernel = state['kernel']; window = _current_window(state['window'])
    _need(type(request['requestId']) is str and kernel.UUID.fullmatch(request['requestId']) and
          request['identity'] == state['identity'] and request['issuedAt'] == window['issued'] and
          request['expiresAt'] == window['expires'], 'publication_command_binding')
    kernel._check_identity(request['identity'])
    action, channel = request['action'], request['channel']
    _need(type(action) is str and type(channel) is str, 'publication_command_channel')
    if action == 'publish':
        _need(channel in kernel.CONTROLS and type(request['payload']) is str and
              0 < len(request['payload']) <= 87384, 'publication_command_channel')
        try: payload = base64.b64decode(request['payload'], validate=True)
        except ValueError: raise PublicationCommandRefused('publication_command_payload') from None
        _need(0 < len(payload) <= kernel.LIMIT and
              base64.b64encode(payload).decode('ascii') == request['payload'], 'publication_command_payload')
        kernel._command(channel, request['requestId'], payload, state['nativeWindow'],
                        kernel._scope_state(state['scope']))
    else:
        _need(action == 'read' and channel in READS and request['payload'] is None,
              'publication_command_channel')
        payload = None
    return request, payload


class HostPublicationCommand:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise PublicationCommandRefused('publication_command_brand')

    def cancel(self):
        state = _state(self)
        _WINDOWS[state['window']]['cancelled'] = True
        state['nativeWindow'].cancel()

    def execute(self, raw):
        """Exactly one attempt; no retry, replay, reconciliation or inferred ACK."""
        state = _state(self)
        _need(state['mutex'].acquire(blocking=False), 'publication_command_busy')
        attempted = False
        try:
            _current(state)
            _need(not state['used'], 'publication_command_used')
            state['used'] = True
            request, payload = _request(raw, state)
            _current(state)
            kernel = state['kernel']
            if request['action'] == 'publish':
                # A lost acknowledgement is unknown, including a successful
                # rename followed by an expired readback. Never redispatch here.
                attempted = True
                state['publicationAttempted'] = True
                result = state['publisher'].publish(request['channel'], request['requestId'],
                                                     payload, state['nativeWindow'])
            else:
                name, maximum = READS[request['channel']]
                with state['lock'].hold(state['nativeWindow']):
                    _current(state)
                    value = kernel._scope_current(state['scope'], state['nativeWindow'])
                    kernel._audit(value)
                    entry = kernel._entry(value['directory'], name)
                    body = None if entry is None else kernel._read_named(value['directory'], name, maximum)[0]
                    kernel._audit(value)
                    _current(state)
                result = {'state': 'absent' if body is None else 'read',
                          'payload': None if body is None else base64.b64encode(body).decode('ascii'),
                          'payloadSha256': None if body is None else _sha(body),
                          'bytes': 0 if body is None else len(body)}
            _current(state)
            response = {'schema': RESPONSE_SCHEMA, 'requestId': request['requestId'],
                        'requestSha256': _sha(raw), 'identity': state['identity'].copy(),
                        'issuedAt': request['issuedAt'], 'expiresAt': request['expiresAt'],
                        'action': request['action'], 'channel': request['channel'], 'result': result,
                        'sourceOnly': True, 'activation': False, 'qualification': False,
                        'nativeAcknowledged': False, 'nativeSaveDurable': False,
                        'resourceReleaseAuthorized': False}
            _need(len(_canonical(response)) <= RESPONSE_LIMIT, 'publication_command_output_limit')
            _current(state)
            return response
        except BaseException as error:
            if attempted:
                state['uncertain'] = True
            if isinstance(error, OSError):
                state['processExitRequired'] = True
            raise
        finally:
            state['mutex'].release()

    def close(self):
        state = _state(self)
        _need(state['mutex'].acquire(blocking=False), 'publication_command_busy')
        try:
            _need(not state['closed'], 'publication_command_closed')
            state['closed'] = True
            # Remove each owned reference BEFORE close; never guess/retry a
            # numeric descriptor after an interrupted or failed close.
            lock, state['lock'] = state['lock'], None
            scope, state['scope'] = state['scope'], None
            first = None
            try: lock.close()
            except BaseException as error:
                state['uncertain'] = state['processExitRequired'] = True; first = error
            try: scope.close()
            except BaseException as error:
                state['uncertain'] = state['processExitRequired'] = True
                if first is None: first = error
            if first is not None:
                raise PublicationCommandRefused('publication_command_close_unknown', process_exit_required=True) from None
            return {'sourceOnly': True, 'activation': False, 'closed': True,
                    'publicationUncertain': state['uncertain'],
                    'processExitRequired': state['processExitRequired'],
                    'resourceReleaseAuthorized': False}
        finally:
            state['mutex'].release()


def _open(sources, server_uuid, expected_scope_sha256, window):
    original = _current_window(window)
    kernel = _sources(sources)
    _need(type(server_uuid) is str and kernel.UUID.fullmatch(server_uuid) and
          type(expected_scope_sha256) is str and kernel.SHA.fullmatch(expected_scope_sha256),
          'publication_command_boot_binding')
    native_window = kernel.capture_window(original['issued'], original['expires'])
    native_state = kernel._window_state(native_window)
    native_state['deadline'] = min(native_state['deadline'], original['deadline'])
    scope = lock = None
    try:
        _current_window(window)
        scope = kernel.capture_host_scope(server_uuid, expected_scope_sha256, native_window)
        _current_window(window)
        lock = kernel.PublicationLock(scope, native_window)
        publisher = kernel.FixedControlPublisher(scope, lock, native_window)
        identity = kernel._scope_current(scope, native_window)['enrollment']['identity'].copy()
        state = {'kernel': kernel, 'scope': scope, 'lock': lock, 'publisher': publisher,
                 'window': window, 'nativeWindow': native_window, 'identity': identity,
                 'pid': os.getpid(), 'used': False, 'closed': False, 'uncertain': False,
                 'publicationAttempted': False, 'processExitRequired': False, 'mutex': threading.RLock()}
        _current(state)
        command = object.__new__(HostPublicationCommand)
        _COMMANDS[command] = state
        scope = lock = None
        return command
    except BaseException as original_error:
        unknown = isinstance(original_error, OSError)
        if lock is not None:
            try: lock.close()
            except BaseException: unknown = True
        if scope is not None:
            try: scope.close()
            except BaseException: unknown = True
        if unknown:
            raise PublicationCommandRefused('publication_command_open_unknown', process_exit_required=True) from None
        raise


def open_host_command(sources, server_uuid, expected_scope_sha256, issued_at, expires_at):
    """Protected boot args; this is custody, NOT current target/dial authority."""
    window = _capture_window(issued_at, expires_at)
    return _open(sources, server_uuid, expected_scope_sha256, window)


def _source_bytes(window):
    _current_window(window)
    path = Path(__file__).with_name('publication.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 65536,
              'publication_command_source_file')
        raw = os.pread(fd, 65537, 0)
        after = os.fstat(fd); named = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        _need(identity(before) == identity(after) == identity(named) and
              len(raw) == before.st_size and _sha(raw) == KERNEL_SHA256,
              'publication_command_source_file')
        _current_window(window)
        return raw
    finally:
        os.close(fd)


def _read_stdin(window):
    output = bytearray()
    while True:
        current = _current_window(window)
        remaining = (current['deadline'] - time.monotonic_ns()) / 1000000000
        _need(remaining > 0 and select.select([0], [], [], remaining)[0], 'publication_command_expired')
        block = os.read(0, min(8192, REQUEST_LIMIT + 1 - len(output)))
        _current_window(window)
        if not block:
            _need(0 < len(output) <= REQUEST_LIMIT, 'publication_command_limit')
            return bytes(output)
        output.extend(block)
        _need(len(output) <= REQUEST_LIMIT, 'publication_command_limit')


def _write_stdout(raw, window):
    _need(type(raw) is bytes and 0 < len(raw) <= RESPONSE_LIMIT, 'publication_command_output_limit')
    previous = os.get_blocking(1)
    try:
        os.set_blocking(1, False)
        rest = memoryview(raw)
        while rest:
            current = _current_window(window)
            remaining = (current['deadline'] - time.monotonic_ns()) / 1000000000
            _need(remaining > 0 and select.select([], [1], [], remaining)[1], 'publication_command_expired')
            try: written = os.write(1, rest[:4096])
            except BlockingIOError: continue
            _need(written > 0, 'publication_command_output')
            rest = rest[written:]
            _current_window(window)
    finally:
        os.set_blocking(1, previous)


def main(argv=None):
    """Explicit, uninstalled --once program. Exactly one frame followed by EOF."""
    command = None
    try:
        argv = list(sys.argv[1:] if argv is None else argv)
        _need(len(argv) == 9 and argv[0] == '--once' and
              argv[1::2] == ['--server-uuid', '--scope-sha256', '--issued-at', '--expires-at'],
              'publication_command_arguments')
        server_uuid, pin, issued, expires = argv[2::2]
        window = _capture_window(issued, expires)
        _need(type(server_uuid) is str and re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', server_uuid) and
              type(pin) is str and re.fullmatch(r'[a-f0-9]{64}', pin), 'publication_command_boot_binding')
        _need(sys.platform == 'linux' and os.name == 'posix' and os.geteuid() == 65532 and os.getegid() == 65532,
              'publication_command_principal')
        raw = _source_bytes(window)
        sources = capture_command_sources(raw)
        _current_window(window)
        request = _read_stdin(window)
        _current_window(window)
        command = _open(sources, server_uuid, pin, window)
        response = command.execute(request)
        closing, command = command, None
        closure = closing.close()
        _need(not closure['publicationUncertain'] and not closure['processExitRequired'], 'publication_command_held')
        _current_window(window)
        _write_stdout(_canonical(response), window)
        return 0
    except BaseException:
        # No exception messages, paths, payloads, ACKs or credentials on stderr.
        return 1
    finally:
        if command is not None:
            try: command.close()
            except BaseException: pass  # Exit this single-job process; no FD retries.


if __name__ == '__main__':
    raise SystemExit(main())

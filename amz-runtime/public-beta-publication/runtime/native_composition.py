"""Inactive source-only native/publication composition; no loader or transport.

Future immutable bootstrap must provide the independently admitted scope pin
and captured source bytes, and enter transaction() around direct loader key,
SAVE and directory checks. No transaction may span await or engine callbacks.
This module does not enroll a publisher, image, principal, game or node permit.
"""
import builtins
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
import threading
import time
import types
import weakref

SOURCE_PINS = types.MappingProxyType({
    'publication': 'f7cf95840762e7e28194b5a589014ceb88fbe95cde05b6b1737aadc8f0be2ce2',
    'gateway_barrier': '8f7c953249d9d646511599ff267233f617f06223951855259855693f10cee3d9',
    'native_files': '31a06a804af044442b4b2040a8e30f4be277bbe44fe5ae544c14b38686dd9e24',
    'checkpoint_custody': '3ef2db1ea532fecca39b4e9792818458f5cd7833fba175cd9466d08ecabaa818',
    'native_checkpoint': 'ad77afbf01c74fcf275f19c30e1bd016b7920700a3082f70e50eb0fa757abaa6',
    'native_budget': 'b648e1d11ed9d97ea7c6267b23199b3725b19c7a6d780ffc08802288ebc14e2f',
    'gateway_hooks': 'dbfb8fe3ee524dfecd761d3b7c188497ab4c5f5944bf34bc025465e8dac9f8e4',
    'native_yacht_effects': 'a6630c05b97c4971251a66c8108da732dc301587101b44782b75566b2631cdf2',
    'native_yacht_observations': 'a6dbe041e2ac40fc78eeffc8f33ffff00366ff3a30e72a0b14a65a288f8a00d2',
})
_STDLIB = frozenset(('asyncio', 'base64', 'collections', 'contextlib', 'copy', 'datetime',
                     'enum', 'fcntl', 'hashlib', 'hmac', 'json', 'logging', 'math', 'os',
                     'pathlib', 'pickle', 'pickletools', 're', 'stat', 'struct', 'sys',
                     'threading', 'time', 'types', 'uuid', 'weakref', 'zlib'))
_SOURCES = weakref.WeakKeyDictionary()
_COMPOSITIONS = weakref.WeakKeyDictionary()
_OWNERS = weakref.WeakKeyDictionary()


class NativeCompositionRefused(RuntimeError):
    def __init__(self, code, *, process_exit_required=False):
        super().__init__(code)
        self.process_exit_required = process_exit_required
        self.activation = False


def _need(value, code='native_publication_refused'):
    if not value: raise NativeCompositionRefused(code)


class CapturedNativeSources:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise NativeCompositionRefused('native_source_brand')


def capture_native_sources(bundle):
    """Validate/copy ALL fixed raw bytes before compiling any of them.

    Fixed imports share the actual captured NativeFiles class, without exposing
    global sys.modules to substitution. No caller module or callback is admitted.
    """
    _need(type(bundle) is dict, 'native_source_inventory')
    copied = bundle.copy()  # Snapshot caller-owned keys before validation/exec.
    _need(set(copied) == set(SOURCE_PINS), 'native_source_inventory')
    _need(all(type(raw) is bytes and 0 < len(raw) <= 262144 for raw in copied.values()) and
          sum(map(len, copied.values())) <= 1048576, 'native_source_limit')
    _need(all(hashlib.sha256(copied[name]).hexdigest() == digest for name, digest in SOURCE_PINS.items()),
          'native_source_pin')
    modules = {}
    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        _need(level == 0, 'native_source_import')
        if name in SOURCE_PINS:
            _need(name in modules, 'native_source_dependency_order')
            return modules[name]
        _need(name in _STDLIB, 'native_source_import')
        return builtins.__import__(name, globals, locals, fromlist, level)
    for name in SOURCE_PINS:
        module = types.ModuleType(name)
        module.__dict__['__builtins__'] = {**vars(builtins), '__import__': fixed_import}
        module.__dict__['__file__'] = '<captured:' + SOURCE_PINS[name] + ':' + name + '>'
        exec(compile(copied[name], module.__dict__['__file__'], 'exec'), module.__dict__)
        modules[name] = module
    publication, budget = modules['publication'], modules['native_budget']
    old_publish = budget.PUBLISH
    budget.CAPS = types.MappingProxyType({**budget.CAPS,
                                         publication.SCOPE: publication.CAPS[publication.SCOPE],
                                         publication.LOCK: publication.CAPS[publication.LOCK]})
    _need(dict(budget.CAPS) == dict(publication.CAPS) and budget.PUBLISH is old_publish and
          publication.SCOPE not in budget.PUBLISH and publication.LOCK not in budget.PUBLISH,
          'native_budget_extension')
    files = modules['native_files']
    _need(modules['native_checkpoint'].NativeFiles is files.NativeFiles and
          modules['native_yacht_effects'].NativeFiles is files.NativeFiles and
          modules['native_yacht_observations'].NativeFiles is files.NativeFiles,
          'native_source_type_identity')
    sources = object.__new__(CapturedNativeSources)
    _SOURCES[sources] = {'modules': modules, 'pid': os.getpid()}
    # Automatically bind the actual binary save constructor before any caller
    # can obtain it through a composed component reference.
    save_type = modules['native_checkpoint'].NativeSaveFiles
    original_save_init = save_type.__init__
    source_ref = weakref.ref(sources)
    def save_init(instance, owner):
        _need(type(instance) is save_type and owner in _OWNERS, 'native_save_composition_required')
        state = _OWNERS[owner]
        _need(state['sources'] is source_ref() and not state['closed'], 'native_save_composition_required')
        with state['mutex']:
            original_save_init(instance, owner)
            state['budget'].bind_save(instance)
            original_read, original_write = instance.read, instance.write
            def read(*args, **kwargs):
                with state['mutex']: return original_read(*args, **kwargs)
            def write(*args, **kwargs):
                with state['mutex']: return original_write(*args, **kwargs)
            instance.read, instance.write = read, write
    save_type.__init__ = save_init
    return sources


def _sources(value):
    _need(type(value) is CapturedNativeSources and value in _SOURCES and
          _SOURCES[value]['pid'] == os.getpid(), 'native_source_brand')
    return _SOURCES[value]


def _iso(milliseconds):
    return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _coordination_window(state):
    # Local lock/IO ceiling only. Native payload/MAC deadlines are never changed.
    pub = state['modules']['publication']
    if state.get('openingWindow') is not None:
        pub._current_window(state['openingWindow'])
        return state['openingWindow']
    now = pub._wall()
    return pub.capture_window(_iso(now), _iso(now + 5000))


def _held(state, error=None):
    state['uncertain'] = True
    # Captured implementations can close inaccessible local FDs in finally.
    # An OS failure cannot establish their settlement or justify a numeric retry.
    if isinstance(error, OSError): state['processExitRequired'] = True
    owner = state.get('owner')
    if owner is not None:
        owner._uncertain, owner._durable = True, None


def _audit(state):
    pub = state['modules']['publication']
    if state['budget'].fd is not None: state['rawAudit']()
    pub._audit(pub._scope_state(state['scope']))


class _CoordinatedMutex:
    def __init__(self, state, native_mutex):
        self.state, self.native = state, native_mutex
        self.depth, self.window, self.manager = 0, None, None
        self.thread = None

    def __enter__(self):
        state = self.state
        nested = self.thread == threading.get_ident()
        _need(state['pid'] == os.getpid() and not state['closed'] and
              (not state['closing'] or nested or state['closeThread'] == threading.get_ident()) and
              (not state['uncertain'] or state['closeThread'] == threading.get_ident()), 'native_composition_closed_or_held')
        pub = state['modules']['publication']; window = self.window if nested else _coordination_window(state)
        while not self.native.acquire(blocking=False):
            pub._current_window(window); time.sleep(.001)
        outer = self.depth == 0
        manager_entered = entered = False
        try:
            _need(state['pid'] == os.getpid() and not state['closed'] and
                  (not state['closing'] or self.thread == threading.get_ident() or
                   state['closeThread'] == threading.get_ident()) and
                  (not state['uncertain'] or state['closeThread'] == threading.get_ident()), 'native_composition_closed_or_held')
            if outer:
                self.window, self.manager = window, state['lock'].hold(window)
                self.manager.__enter__()
                manager_entered = True
                self.thread = threading.get_ident()
            self.depth += 1
            entered = True
            pub._current_window(self.window)
            if outer: _audit(state)
            return self
        except BaseException as error:
            _held(state, error)
            if entered: self.depth -= 1
            try:
                if outer and manager_entered:
                    self.manager.__exit__(*__import__('sys').exc_info())
            finally:
                if outer: self.manager = self.window = self.thread = None
                self.native.release()
            raise

    def __exit__(self, error_type, error, traceback):
        state = self.state; outer = self.depth == 1
        exit_error = None
        try:
            if error is not None: _held(state, error)
            if outer and error is None:
                try:
                    _need(not state['closed'] and (not state['uncertain'] or
                          state['closeThread'] == threading.get_ident()), 'native_composition_closed_or_held')
                    _audit(state)
                except BaseException as failure:
                    _held(state, failure); exit_error = failure
            self.depth -= 1
            if outer:
                try:
                    if exit_error is None: self.manager.__exit__(error_type, error, traceback)
                    else: self.manager.__exit__(type(exit_error), exit_error, exit_error.__traceback__)
                except BaseException as failure:
                    _held(state, failure)
                    if error is None: exit_error = failure
                finally: self.manager = self.window = self.thread = None
        finally: self.native.release()
        if exit_error is not None and error is None: raise exit_error
        return False


class NativePublicationComposition:
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise NativeCompositionRefused('native_composition_brand')

    @property
    def files(self):
        return _state(self)['owner']

    @property
    def components(self):
        """Fixed genuine refs only; no caller-selected module or approval."""
        return _state(self)['components']

    @contextmanager
    def transaction(self):
        state = _state(self)
        with state['mutex']:
            yield self

    def audit(self):
        state = _state(self)
        with state['mutex']:
            return dict(state['rawAudit']())

    def open_save_files(self):
        state = _state(self)
        with state['mutex']:
            return state['modules']['native_checkpoint'].NativeSaveFiles(state['owner'])

    def publish_status(self, value):
        state = _state(self)
        with state['mutex']:
            canonical = state['modules']['gateway_barrier'].canonical
            state['budget'].publish_status(value, canonical)

    def describe(self):
        state = _state(self, allow_closed=True, allow_held=True)
        return {'sourceOnly': True, 'activation': False, 'qualification': False,
                'uncertain': state['uncertain'], 'processExitRequired': state['processExitRequired'],
                'resourceReleaseAuthorized': False, 'sources': dict(SOURCE_PINS)}

    def close(self):
        state = _state(self, allow_closed=True, allow_held=True)
        with state['lifecycle']:
            if state['closed']:
                if state['uncertain'] or state['processExitRequired']:
                    raise NativeCompositionRefused('native_composition_close_unknown',
                                                   process_exit_required=state['processExitRequired'])
                return self.describe()
            state['closing'], state['closeThread'] = True, threading.get_ident()
            failure = None
            can_close_publication = True
            try:
                with state['mutex']:
                    if not state['ownerCloseAttempted']:
                        state['ownerCloseAttempted'] = True
                        state['rawOwnerClose']()
                        state['ownerCloseCompleted'] = True
                    state['budgetCloseAttempted'] = True
                    state['rawBudgetClose']()
                    state['budgetCloseCompleted'] = True
            except BaseException as error:
                _held(state, error); failure = error
                if state['rawNativeMutex'].acquire(blocking=False):
                    try: _close_live_handles_only(state)
                    finally: state['rawNativeMutex'].release()
                else:
                    # Never close a descriptor under an in-flight native user.
                    state['processExitRequired'] = True; can_close_publication = False
            finally:
                state['closed'] = True
                if can_close_publication:
                    try: state['lock'].close()
                    except BaseException as error:
                        state['processExitRequired'] = True
                        if failure is None: failure = error
                    try: state['scope'].close()
                    except BaseException as error:
                        state['processExitRequired'] = True
                        if failure is None: failure = error
            result = {'sourceOnly': True, 'activation': False, 'qualification': False,
                      'uncertain': state['uncertain'], 'processExitRequired': state['processExitRequired'],
                      'resourceReleaseAuthorized': False}
            if not state['processExitRequired']: _OWNERS.pop(state['owner'], None)
            if failure is not None or state['uncertain'] or state['processExitRequired']:
                raise NativeCompositionRefused('native_composition_close_unknown',
                                               process_exit_required=state['processExitRequired']) from None
            return result


def _state(value, allow_closed=False, allow_held=False):
    _need(type(value) is NativePublicationComposition and value in _COMPOSITIONS, 'native_composition_brand')
    state = _COMPOSITIONS[value]
    _need(state['pid'] == os.getpid() and (allow_closed or not state['closed']) and
          (allow_held or not state['uncertain']), 'native_composition_closed_or_held')
    return state


def _close_live_handles_only(state):
    """No unlink/reconciliation. Never retry a native close's stale numbers."""
    handles = []
    owner = state.get('owner')
    if owner is not None:
        if state['ownerCloseAttempted'] and not state['ownerCloseCompleted']:
            # NativeFiles.close sets _closed before its own descriptor closes;
            # an error leaves settlement uncertain. Its numbers are not ours
            # to retry, even if they now refer to a different file.
            state['processExitRequired'] = True
        elif not state['ownerCloseCompleted']:
            owner._closed = True
            for name in ('_lock', '_directory'):
                descriptor = getattr(owner, name, None)
                setattr(owner, name, None)
                if descriptor is not None: handles.append(descriptor)
    budget = state.get('budget')
    if budget is not None:
        if state['budgetCloseAttempted'] and not state['budgetCloseCompleted']: state['processExitRequired'] = True
        elif budget.fd is not None:
            handles.append(budget.fd); budget.fd = None
    for descriptor in handles:
        try: os.close(descriptor)
        except BaseException: state['processExitRequired'] = True


def open_native_composition(sources, protected_enrollment_sha256, issued_at, expires_at):
    captured = _sources(sources); modules = captured['modules']; pub = modules['publication']
    window = pub.capture_window(issued_at, expires_at)
    try:
        scope = pub.capture_runtime_scope(protected_enrollment_sha256, window)
    except OSError:
        # The accepted kernel owns any partial capture's descriptors. It may
        # have lost a close acknowledgement; never guess/retry its FD numbers.
        raise NativeCompositionRefused('native_scope_capture_unknown', process_exit_required=True) from None
    lock = None
    state = {'sources': sources, 'modules': modules, 'scope': scope, 'owner': None, 'budget': None,
             'pid': os.getpid(), 'closed': False, 'uncertain': False, 'processExitRequired': False,
             'ownerCloseAttempted': False, 'ownerCloseCompleted': False,
             'budgetCloseAttempted': False, 'budgetCloseCompleted': False,
             'ownerConstructorAttempted': False,
             'budgetConstructorAttempted': False, 'budgetConstructorCompleted': False,
             'lockConstructorAttempted': False, 'lockConstructorCompleted': False,
             'openingWindow': window,
             'closing': False, 'closeThread': None, 'lifecycle': threading.RLock()}
    try:
        state['lockConstructorAttempted'] = True
        lock = pub.PublicationLock(scope, window); state['lock'] = lock
        state['lockConstructorCompleted'] = True
        # No native owner/mutex exists yet. Nothing is exposed until this
        # bootstrap hold has covered first audit, reservation and constructor.
        with lock.hold(window):
            state['budgetConstructorAttempted'] = True
            budget = modules['native_budget'].NativeBudget(pub.RUNTIME_ROOT); state['budget'] = budget
            state['budgetConstructorCompleted'] = True
            budget.reserve_lock()
            # Do not retain/reclose a partial constructor's numeric attributes.
            state['ownerConstructorAttempted'] = True
            owner = modules['native_files'].NativeFiles(); state['owner'] = owner
            state['rawNativeMutex'] = owner._mutex
            state['rawAudit'] = budget.audit; state['rawBudgetClose'] = budget.close; state['rawOwnerClose'] = owner.close
        # The bootstrap-only publication hold has ended. From this point the
        # actual native RLock is always acquired BEFORE the publication lock.
        # The owner is still private and no native loop has been started.
        # Keep the genuine native mutex itself unchanged: effects hold it while
        # invoking engine handlers. Only the fixed filesystem spans acquire the
        # publication flock through this separate coordinator.
        mutex = _CoordinatedMutex(state, owner._mutex); state['mutex'] = mutex
        _OWNERS[owner] = state
        def wrap_native(original):
            def guarded(*args, **kwargs):
                with mutex: return original(*args, **kwargs)
            return guarded
        for name in ('_active', '_entry', '_read', '_check_directory', '_reject_pending',
                     'load_journal', 'initialize', 'commit_journal', 'read_control', 'publish_ack'):
            setattr(owner, name, wrap_native(getattr(owner, name)))
        original_audit = budget.audit
        def audit():
            with mutex: return original_audit()
        budget.audit = audit
        with mutex:
            budget.install(owner)  # Actual pre-plan + actual _replace/readback.
        # Wrap the entire ACTUAL budget-installed function, not only its inner
        # native replace: audit + plan + old bytes + temp + fsync + readback.
        owner._replace = wrap_native(owner._replace)
        def close_owner():
            with mutex:
                state['ownerCloseAttempted'] = True
                try:
                    result = state['rawOwnerClose']()
                except BaseException:
                    state['processExitRequired'] = True
                    raise
                state['ownerCloseCompleted'] = True
                return result
        owner.close = close_owner
        names = {'gateway_barrier': ('NativeBarrier', 'initial_state', 'canonical', 'iso'),
                 'gateway_hooks': ('ControlPump', 'PublicHooks', 'install_log_redaction'),
                 'native_checkpoint': ('NativeSnapshots', 'NativeSaveFiles'),
                 'native_yacht_effects': ('YachtEffectsControl', 'VerifiedYachtHandlers', 'initialize_effects'),
                 'native_yacht_observations': ('YachtObservationControl', 'VerifiedYachtObservationABI')}
        state['components'] = types.MappingProxyType({name: types.MappingProxyType({key: getattr(modules[name], key) for key in keys})
                                                      for name, keys in names.items()})
        composition = object.__new__(NativePublicationComposition); _COMPOSITIONS[composition] = state
        with mutex: _audit(state)
        pub._scope_current(scope, window)
        state['openingWindow'] = None
        return composition
    except BaseException as error:
        _held(state, error)
        if state['owner'] is None and state['ownerConstructorAttempted']: state['processExitRequired'] = True
        if state['budgetConstructorAttempted'] and not state['budgetConstructorCompleted']: state['processExitRequired'] = True
        if state['lockConstructorAttempted'] and not state['lockConstructorCompleted']: state['processExitRequired'] = True
        _close_live_handles_only(state)
        if state['owner'] is not None and not state['processExitRequired']: _OWNERS.pop(state['owner'], None)
        if lock is not None:
            try: lock.close()
            except BaseException: state['processExitRequired'] = True
        try: scope.close()
        except BaseException: state['processExitRequired'] = True
        raise NativeCompositionRefused('native_composition_boot_unknown',
                                       process_exit_required=state['processExitRequired']) from None

"""Unregistered committed-Yacht-effects candidate; no engine import or timer.

Only a future verified loader may enroll this separate profile. Immutable CP
commit authentication authorizes historical effects, never current game access.
"""
import copy
import enum
import hashlib
import hmac
import math
import os
import struct
import threading
import time
import types
from types import SimpleNamespace

from gateway_barrier import BarrierError, canonical, exact, identity, instant, integer, iso, require, SHA, UUID
from native_files import NativeFiles

SCHEMA = 'amz.ap.public-beta.yacht-effects-control.v1'
COMMIT = 'amz.ap.public-beta.yacht-committed-effects.v1'
STATE = 'amz.ap.public-beta.yacht-effects-journal.v1'
ACK_SCHEMA = 'amz.ap.public-beta.yacht-effects-ack.v1'
CONTROL = 'public-yacht-effects-control.json'
JOURNAL = 'public-yacht-effects-journal.json'
ACK = 'public-yacht-effects-ack.json'
LIMIT = 2 * 1024 * 1024
MESSAGE_LIMIT = 64 * 1024
ENGINE_FILE = '/engine/MultiServer.py'
ENGINE_SHA = 'e157abab8a56351d58f1cf5a84c6c2a9144d295956d6be08cbd5811c7a2932de'
NETUTILS_SHA = '0c4acb2e0a434bcd91ed03d6e9c66f5d119597b3feb300620241f206bd7f0b06'
STATUSES = {'CLIENT_UNKNOWN': 0, 'CLIENT_CONNECTED': 5, 'CLIENT_READY': 10, 'CLIENT_PLAYING': 20, 'CLIENT_GOAL': 30}
RUN = ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId',
       'seedRevision', 'configurationRevision', 'seedArtifactSha256', 'seedName')
SLOT = ('actorUuid', 'slotAlias', 'team', 'slot')
BASE = 16871244500


def sha(raw): return hashlib.sha256(raw).hexdigest()


def run_binding(value):
    require(exact(value, RUN) and value['appVariant'] == 'public-beta' and
            value['policyId'] == 'public-disposable-beta-v1', 'yacht_effects_run')
    require(all(type(value[k]) is str and UUID.fullmatch(value[k]) for k in
                ('environmentId', 'dataEpoch', 'roomId', 'attemptId')) and
            all(integer(value[k], 1, 1000000000) for k in ('seedRevision', 'configurationRevision')) and
            type(value['seedArtifactSha256']) is str and SHA.fullmatch(value['seedArtifactSha256']) and
            type(value['seedName']) is str and 0 < len(value['seedName']) <= 256 and
            all(ord(c) >= 32 and ord(c) != 127 for c in value['seedName']), 'yacht_effects_run')
    return copy.deepcopy(value)


def slot_binding(value):
    import re
    require(exact(value, SLOT) and type(value['actorUuid']) is str and UUID.fullmatch(value['actorUuid']) and
            type(value['slotAlias']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,16}', value['slotAlias']) and
            integer(value['team'], 0, 0) and integer(value['slot'], 1, 16), 'yacht_effects_slot')
    return copy.deepcopy(value)


def roster_binding(value):
    require(type(value) is list and 1 <= len(value) <= 16, 'yacht_effects_roster')
    result = [slot_binding(row) for row in value]
    require(result == sorted(result, key=lambda row: row['slot']) and
            all(len({row[k] for row in result}) == len(result) for k in ('actorUuid', 'slotAlias', 'slot')),
            'yacht_effects_roster')
    return result


def effects_binding(value):
    require(exact(value, ('checks', 'goal')) and type(value['goal']) is bool and
            type(value['checks']) is list and len(value['checks']) <= 1000 and
            all(integer(v, BASE + 1, BASE + 1000) for v in value['checks']) and
            value['checks'] == sorted(set(value['checks'])), 'yacht_effects_set')
    return copy.deepcopy(value)


def commit_binding(value, run, roster):
    require(exact(value, ('schema', 'run', 'player', 'commitId', 'commitRevision', 'checkpointSha256', 'effects')) and
            value['schema'] == COMMIT and run_binding(value['run']) == run and
            slot_binding(value['player']) in roster and type(value['commitId']) is str and UUID.fullmatch(value['commitId']) and
            integer(value['commitRevision'], 1, 1000000000) and type(value['checkpointSha256']) is str and
            SHA.fullmatch(value['checkpointSha256']), 'yacht_effects_commit')
    effects_binding(value['effects'])
    require(len(canonical(value)) <= MESSAGE_LIMIT, 'yacht_effects_limit')
    return copy.deepcopy(value)


def _code(container, name):
    result = [v for v in container.co_consts if type(v) is types.CodeType and v.co_name == name]
    require(len(result) == 1, 'yacht_effects_handler_abi')
    return result[0]


def _code_identity(code, budget=None, depth=0):
    """Executable identity, excluding marshal's reference/intern bookkeeping."""
    if budget is None: budget = [0]
    budget[0] += 1
    require(type(code) is types.CodeType and depth <= 64 and budget[0] <= 100000, 'yacht_effects_handler_abi')
    fields = ('co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals', 'co_stacksize', 'co_flags',
              'co_code', 'co_names', 'co_varnames', 'co_filename', 'co_name', 'co_qualname', 'co_firstlineno',
              'co_linetable', 'co_exceptiontable', 'co_freevars', 'co_cellvars')
    return ('code', tuple(getattr(code, name) for name in fields),
            tuple(_constant_identity(value, budget, depth + 1) for value in code.co_consts))


def _constant_identity(value, budget, depth):
    budget[0] += 1
    require(depth <= 64 and budget[0] <= 100000, 'yacht_effects_handler_abi')
    kind = type(value)
    if value is None: return ('none',)
    if value is Ellipsis: return ('ellipsis',)
    if kind in (str, bytes, int, bool): return (kind.__name__, value)
    if kind is float: return ('float', struct.pack('!d', value))
    if kind is complex: return ('complex', struct.pack('!d', value.real), struct.pack('!d', value.imag))
    if kind is types.CodeType: return _code_identity(value, budget, depth + 1)
    if kind is tuple: return ('tuple', tuple(_constant_identity(v, budget, depth + 1) for v in value))
    if kind is frozenset: return ('frozenset', frozenset(_constant_identity(v, budget, depth + 1) for v in value))
    require(False, 'yacht_effects_handler_abi')


class VerifiedYachtHandlers:
    """Exact pinned normal functions, not request-selected callback enrollment.

    Compile compares code only; it executes/imports none of the supplied source.
    Full engine inventory verification before engine import remains mandatory.
    """
    def __init__(self, module, source):
        require(type(module) is types.ModuleType and module.__name__ == 'MultiServer' and
                type(source) is bytes and 0 < len(source) <= 1024 * 1024 and sha(source) == ENGINE_SHA,
                'yacht_effects_verified_handlers_required')
        compiled = compile(source, ENGINE_FILE, 'exec', dont_inherit=True, optimize=0)
        self.module = module
        self.status_type = getattr(module, 'ClientStatus', None)
        self.expected = {'register_location_checks': _code(compiled, 'register_location_checks'),
                         'update_client_status': _code(compiled, 'update_client_status'),
                         'on_goal_achieved': _code(_code(compiled, 'Context'), 'on_goal_achieved')}
        self.check_code()

    def check_code(self):
        native = getattr(self.module, 'NetUtils', None)
        require(type(native) is types.ModuleType and native.__name__ == 'NetUtils' and
                isinstance(self.status_type, enum.EnumType) and issubclass(self.status_type, enum.IntEnum) and
                self.status_type.__module__ == 'NetUtils' and self.module.ClientStatus is self.status_type and
                getattr(native, 'ClientStatus', None) is self.status_type and
                {name: int(value) for name, value in self.status_type.__members__.items()} == STATUSES,
                'yacht_effects_handler_abi')
        functions = {name: getattr(self.module, name, None) for name in ('register_location_checks', 'update_client_status')}
        functions['on_goal_achieved'] = getattr(getattr(self.module, 'Context', None), 'on_goal_achieved', None)
        require(all(type(fn) is types.FunctionType and fn.__globals__ is self.module.__dict__ and
                    _code_identity(fn.__code__) == _code_identity(self.expected[name])
                    for name, fn in functions.items()), 'yacht_effects_handler_abi')

    def check_context(self, context, run, roster):
        self.check_code()
        require(type(context) is self.module.Context and not context.exit_event.is_set() and
                context.auto_saver_thread is None and context.seed_name == run['seedName'] and
                context.connect_names == {row['slotAlias']: (row['team'], row['slot']) for row in roster} and
                context.games == {row['slot']: 'Yacht Dice' for row in roster}, 'yacht_effects_native_binding')

    def observe(self, context, player):
        key = player['team'], player['slot']
        checks = context.location_checks.get(key, set())
        status = context.client_game_state.get(key, 0)
        require(type(checks) is set and all(integer(v, BASE + 1, BASE + 1000) for v in checks) and
                (type(status) is int and status in STATUSES.values() or type(status) is self.status_type),
                'yacht_effects_native_observation')
        return set(checks), int(status) == 30

    def apply(self, context, player, effects):
        checks, goal = self.observe(context, player)
        missing = sorted(set(effects['checks']) - checks)
        if missing:
            self.module.register_location_checks(context, player['team'], player['slot'], missing)
        if effects['goal'] and not goal:
            # Exact pinned update_client_status/on_goal_achieved need only this
            # immutable address. It is not a native client, Connect or presence.
            self.module.update_client_status(context, SimpleNamespace(team=player['team'], slot=player['slot']), self.status_type.CLIENT_GOAL)
        checks, goal = self.observe(context, player)
        require(set(effects['checks']) <= checks and (not effects['goal'] or goal), 'yacht_effects_not_observed')


def _state(run, roster, scope):
    return {'schema': STATE, 'run': run_binding(run), 'roster': roster_binding(roster), 'identity': identity(scope),
            'clockFloor': 0, 'slots': {str(row['slot']): None for row in roster}}


def _read(owner, name, maximum, optional=False):
    owner._active()
    return owner._read(name, maximum, optional=optional)


def _write(owner, name, value, maximum):
    previous = _read(owner, name, maximum, optional=True)
    result = owner._replace(name, canonical(value), maximum, previous)
    require(result is not None and result[0] == value and result[2].hex() == sha(canonical(value)), 'yacht_effects_durability')
    return result


def _no_pending(owner):
    with os.scandir(owner._directory) as entries:
        for count, entry in enumerate(entries):
            require(count < 1024 and not entry.name.startswith(tuple('.' + n + '.pending-' for n in (JOURNAL, ACK))),
                    'yacht_effects_reconciliation_required')


def initialize_effects(owner, run, roster, scope):
    """Explicit protected enrollment only. Never a missing-journal fallback."""
    require(type(owner) is NativeFiles, 'yacht_effects_owner_required')
    with owner._mutex:
        owner._active()
        _no_pending(owner)
        require(all(owner._entry(name) is None for name in (JOURNAL, CONTROL, ACK)), 'yacht_effects_initialize_conflict')
        state = _state(run, roster, scope)
        require(all(state['run'][k] == state['identity'][k] for k in
                    ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')),
                'yacht_effects_run')
        _write(owner, JOURNAL, state, LIMIT)


class YachtEffectsControl:
    """Loop-owned opt-in candidate. No default authority or engine discovery.

    Two domain-separated MACs: immutable durable CP commit proof and a fresh
    runtime-bound delivery envelope. Neither supplies current player access.
    """
    def __init__(self, owner, barrier, handlers, context, *, run, roster, independent_key, clock=None, monotonic=None):
        require(type(owner) is NativeFiles and type(handlers) is VerifiedYachtHandlers and
                type(independent_key) is bytes and len(independent_key) == 32 and independent_key != bytes(32) and
                independent_key not in (barrier._master.encode(), hashlib.sha256(barrier._master.encode()).digest()),
                'yacht_effects_enrollment_required')
        self.owner, self.barrier, self.handlers, self.context = owner, barrier, handlers, context
        self.run, self.roster, self.scope = run_binding(run), roster_binding(roster), identity(barrier.identity)
        require(all(self.run[k] == self.scope[k] for k in
                    ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')), 'yacht_effects_run')
        self._key = bytearray(independent_key)
        self.thread, self.clock, self.monotonic = threading.get_ident(), clock or (lambda: int(time.time() * 1000)), monotonic or time.monotonic
        self._deadline, self._last, self._closed = None, None, False
        self._delivery, self._mono_floor = None, None
        with owner._mutex:
            owner._active()
            _no_pending(owner)
            self._load()  # Missing/foreign launch must be protected-migrated, never reset.
            handlers.check_context(context, self.run, self.roster)

    def _load(self):
        packet = _read(self.owner, JOURNAL, LIMIT)
        state = packet[0]
        require(exact(state, ('schema', 'run', 'roster', 'identity', 'clockFloor', 'slots')) and state['schema'] == STATE and
                state['run'] == self.run and state['roster'] == self.roster and state['identity'] == self.scope and
                integer(state['clockFloor']) and type(state['slots']) is dict and
                set(state['slots']) == {str(row['slot']) for row in self.roster}, 'yacht_effects_journal')
        for key, row in state['slots'].items():
            if row is None: continue
            require(exact(row, ('commit', 'definitionSha256', 'phase')) and row['phase'] in ('intent', 'observed', 'unknown') and
                    commit_binding(row['commit'], self.run, self.roster)['player']['slot'] == int(key) and
                    row['definitionSha256'] == sha(COMMIT.encode() + b'\n' + canonical(row['commit'])), 'yacht_effects_journal')
        return state

    def _active(self):
        require(not self._closed and threading.get_ident() == self.thread, 'yacht_effects_stopped_or_thread')
        self.owner._active()
        require(self.barrier.identity == self.scope and self.barrier.state['ready'] and not self.barrier.state['uncertain'] and
                not any(row['gate']['kind'] == 'idle' for row in self.barrier.state['gates'].values()) and
                self.barrier._actual() is not None, 'yacht_effects_native_unavailable')
        self.handlers.check_context(self.context, self.run, self.roster)

    def process(self, value):
        with self.owner._mutex:
            self._active()
            require(exact(value, ('schema', 'deliveryId', 'identity', 'issuedAt', 'expiresAt', 'commit', 'commitMac', 'deliveryMac')) and
                    value['schema'] == SCHEMA and identity(value['identity']) == self.scope and
                    type(value['deliveryId']) is str and UUID.fullmatch(value['deliveryId']) and
                    all(type(value[k]) is str and SHA.fullmatch(value[k]) for k in ('commitMac', 'deliveryMac')), 'yacht_effects_delivery')
            commit = commit_binding(value['commit'], self.run, self.roster)
            require(len(canonical(value)) <= MESSAGE_LIMIT, 'yacht_effects_limit')
            definition = COMMIT.encode() + b'\n' + canonical(commit)
            unsigned = {k: v for k, v in value.items() if k != 'deliveryMac'}
            require(hmac.compare_digest(value['commitMac'], hmac.digest(self._key, definition, 'sha256').hex()) and
                    hmac.compare_digest(value['deliveryMac'], hmac.digest(self._key, SCHEMA.encode() + b'\n' + canonical(unsigned), 'sha256').hex()),
                    'yacht_effects_authentication')
            state = self._load()
            digest = sha(canonical(value))
            start, expiry = instant(value['issuedAt']), instant(value['expiresAt'])
            require(0 < expiry - start <= 5000, 'yacht_effects_expired')
            def current():
                self._active()
                now, mono = self.clock(), self.monotonic()
                require(integer(now, max(state['clockFloor'], self.barrier._now())) and start <= now < expiry and
                        type(mono) in (float, int) and math.isfinite(mono), 'yacht_effects_expired')
                if self._delivery != value['deliveryId']:
                    self._delivery, self._deadline, self._mono_floor = value['deliveryId'], mono + (expiry - now) / 1000, mono
                    self._delivery_sha = digest
                require(self._delivery_sha == digest and self._mono_floor <= mono < self._deadline, 'yacht_effects_expired')
                self._mono_floor = mono
                state['clockFloor'] = now
                return now
            current()
            key = str(commit['player']['slot'])
            prior = state['slots'][key]
            if prior is not None:
                previous = prior['commit']
                require(commit['commitRevision'] >= previous['commitRevision'], 'yacht_effects_superseded')
                if commit['commitRevision'] == previous['commitRevision']:
                    require(commit == previous, 'yacht_effects_commit_conflict')
                else:
                    require(commit['commitId'] != previous['commitId'] and
                            set(previous['effects']['checks']) <= set(commit['effects']['checks']) and
                            (not previous['effects']['goal'] or commit['effects']['goal']), 'yacht_effects_nonmonotone')
            allowed = set(self.context.locations[commit['player']['slot']])
            require(set(commit['effects']['checks']) <= allowed, 'yacht_effects_location_binding')
            record = {'commit': commit, 'definitionSha256': sha(definition), 'phase': 'intent'}
            state['slots'][key] = record
            _write(self.owner, JOURNAL, state, LIMIT)
            current()
            try:
                # Synchronous exact pinned normal handlers: no native-loop
                # await, fake Connect, presence counter or admission change.
                self.handlers.apply(self.context, commit['player'], commit['effects'])
                current()
                record['phase'] = 'observed'
                durable = _write(self.owner, JOURNAL, state, LIMIT)
                current()
                acknowledgement = {'schema': ACK_SCHEMA, 'deliveryId': value['deliveryId'], 'deliverySha256': digest,
                    'identity': self.scope, 'commitId': commit['commitId'], 'commitRevision': commit['commitRevision'],
                    'definitionSha256': sha(definition), 'observedAt': iso(self.clock()),
                    'result': {'state': 'observed', 'journalSha256': durable[2].hex(), 'nativeSaveDurable': False}}
                _write(self.owner, ACK, acknowledgement, MESSAGE_LIMIT)
                current()
                self._last = digest
                return copy.deepcopy(acknowledgement)
            except BaseException:
                # A partial normal handler or late IO is never an applied proof.
                # Exact historical intents remain available to protected recovery.
                self.barrier.state['ready'], self.barrier.state['uncertain'] = False, True
                try: self.barrier._save()
                except BaseException: pass  # The original intent/owner uncertainty remains.
                record['phase'] = 'unknown'
                try: _write(self.owner, JOURNAL, state, LIMIT)
                except BaseException: pass  # Never claim this best effort reached disk.
                raise BarrierError('yacht_effects_apply_unknown') from None

    def poll_once(self):
        with self.owner._mutex:
            self._active()
            packet = _read(self.owner, CONTROL, MESSAGE_LIMIT, optional=True)
            if packet is None or sha(canonical(packet[0])) == self._last: return False
            self.process(packet[0])
            return True

    def close(self):
        self._closed = True
        for index in range(len(self._key)): self._key[index] = 0

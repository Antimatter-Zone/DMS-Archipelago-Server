"""Pure new-profile fixtures. No engine imports, native listeners or resources."""
import copy
import enum
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'public-beta/runtime'))
SPEC = importlib.util.spec_from_file_location('yacht_effects_candidate', ROOT / 'public-beta-effects/runtime/native_yacht_effects.py')
effects = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(effects)
from gateway_barrier import BarrierError, canonical, iso
from native_files import NativeFiles

NOW = 1794432300000
KEY = b'fixture independent commit key!!'


def uid(number): return '00000000-0000-4000-8000-' + str(number).zfill(12)


SOURCE = b'''class Context:
    def on_goal_achieved(self, client):
        self.events.append(('goal', client.team, client.slot))

def register_location_checks(ctx, team, slot, locations):
    ctx.events.append(('checks', tuple(locations)))
    ctx.location_checks.setdefault((team, slot), set()).update(locations)
    ctx.save_dirty = True

def update_client_status(ctx, client, new_status):
    if ctx.client_game_state.get((client.team, client.slot), 0) != 30:
        ctx.on_goal_achieved(client)
        ctx.client_game_state[client.team, client.slot] = new_status
        ctx.save_dirty = True
'''


def fixture():
    temporary = tempfile.TemporaryDirectory()
    scope = {'appVariant': 'public-beta', 'policyId': 'public-disposable-beta-v1', 'environmentId': uid(1),
             'dataEpoch': uid(2), 'roomId': uid(3), 'externalId': 'ap-beta-' + uid(3) + '-r1',
             'allocationRevision': 1, 'serverId': 'private_fixture', 'attemptId': uid(4),
             'seedRevision': 1, 'credentialEpoch': 1, 'runtimeLaunchId': uid(5)}
    run = {k: scope[k] for k in ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')}
    run.update(configurationRevision=1, seedArtifactSha256='a' * 64, seedName='synthetic-no-engine')
    roster = [{'actorUuid': uid(6), 'slotAlias': 'Yacht_One', 'team': 0, 'slot': 1}]
    records, events, wall, mono = {}, [], [NOW], [0.0]
    owner = object.__new__(NativeFiles)
    owner._mutex, owner._directory = threading.RLock(), temporary.name
    owner._active = lambda: None
    owner._entry = lambda name: None if name not in records else object()
    def read(name, maximum, optional=False):
        if name not in records:
            if optional: return None
            raise BarrierError('fixture_journal_missing')
        return copy.deepcopy(records[name]), (), hashlib.sha256(canonical(records[name])).digest()
    def replace(name, raw, maximum, previous):
        if previous != read(name, maximum, True): raise BarrierError('fixture_concurrent_write')
        if len(raw) > maximum: raise BarrierError('fixture_limit')
        records[name] = json.loads(raw)
        events.append(('write', name, copy.deepcopy(records[name])))
        return read(name, maximum)
    owner._read, owner._replace = read, replace
    module = types.ModuleType('MultiServer')
    exec(compile(SOURCE, effects.ENGINE_FILE, 'exec', dont_inherit=True, optimize=0), module.__dict__)
    module.NetUtils = types.ModuleType('NetUtils')
    module.ClientStatus = module.NetUtils.ClientStatus = enum.IntEnum('ClientStatus', effects.STATUSES, module='NetUtils')
    with patch.object(effects, 'ENGINE_SHA', effects.sha(SOURCE)):
        handlers = effects.VerifiedYachtHandlers(module, SOURCE)
    context = module.Context()
    context.events = events
    context.exit_event = types.SimpleNamespace(is_set=lambda: False)
    context.auto_saver_thread, context.seed_name = None, run['seedName']
    context.connect_names, context.games = {'Yacht_One': (0, 1)}, {1: 'Yacht Dice'}
    context.locations, context.location_checks, context.client_game_state = {1: {effects.BASE + 1, effects.BASE + 2}}, {}, {}
    context.save_dirty = False
    barrier = types.SimpleNamespace(identity=scope, _master='Z' * 64,
        state={'ready': True, 'uncertain': False, 'gates': {}, 'generation': 4, 'lastDisconnectAt': iso(NOW - 60000)},
        _actual=lambda: [], _now=lambda: wall[0], _save=lambda: events.append(('barrier_save',)))
    effects.initialize_effects(owner, run, roster, scope)
    def new_control():
        return effects.YachtEffectsControl(owner, barrier, handlers, context, run=run, roster=roster,
            independent_key=KEY, clock=lambda: wall[0], monotonic=lambda: mono[0])
    control = new_control()
    f = types.SimpleNamespace(temporary=temporary, owner=owner, scope=scope, run=run, roster=roster,
        records=records, events=events, wall=wall, mono=mono, module=module, handlers=handlers, context=context,
        barrier=barrier, control=control, new_control=new_control)
    return f


def logical(f, revision=1, checks=None, goal=True):
    return {'schema': effects.COMMIT, 'run': copy.deepcopy(f.run), 'player': copy.deepcopy(f.roster[0]),
            'commitId': uid(100 + revision), 'commitRevision': revision, 'checkpointSha256': str(revision % 10) * 64,
            'effects': {'checks': [effects.BASE + 1] if checks is None else checks, 'goal': goal}}


def delivery(f, commit=None, number=1):
    commit = copy.deepcopy(commit or logical(f))
    value = {'schema': effects.SCHEMA, 'deliveryId': uid(200 + number), 'identity': copy.deepcopy(f.scope),
        'issuedAt': iso(f.wall[0]), 'expiresAt': iso(f.wall[0] + 5000), 'commit': commit,
        'commitMac': hmac.digest(KEY, effects.COMMIT.encode() + b'\n' + canonical(commit), 'sha256').hex()}
    value['deliveryMac'] = hmac.digest(KEY, effects.SCHEMA.encode() + b'\n' + canonical(value), 'sha256').hex()
    return value


class Candidate(unittest.TestCase):
    def setUp(self):
        self.f = fixture()
        self.addCleanup(self.f.temporary.cleanup)

    def test_intent_precedes_normal_handlers_and_durable_ack_is_not_native_save_proof(self):
        f = self.f; f.events.clear()
        before = copy.deepcopy(f.barrier.state)
        ack = f.control.process(delivery(f))
        self.assertEqual([event[0] for event in f.events], ['write', 'checks', 'goal', 'write', 'write'])
        self.assertEqual(f.events[0][2]['slots']['1']['phase'], 'intent')
        self.assertEqual(f.events[-2][2]['slots']['1']['phase'], 'observed')
        self.assertFalse(ack['result']['nativeSaveDurable'])
        self.assertEqual(ack['result']['journalSha256'], effects.sha(canonical(f.records[effects.JOURNAL])))
        self.assertEqual(f.barrier.state, before)
        self.assertTrue(f.context.save_dirty)

    def test_renewed_transport_same_commit_and_native_rollback_replay_missing_effects(self):
        f = self.f; commit = logical(f)
        first = f.control.process(delivery(f, commit))
        f.wall[0] += 100; f.mono[0] += .1
        f.control.process(delivery(f, commit, 2))
        self.assertEqual(len([e for e in f.events if e[0] == 'checks']), 1)
        f.context.location_checks.clear(); f.context.client_game_state.clear()
        f.wall[0] += 100; f.mono[0] += .1
        last = f.control.process(delivery(f, commit, 3))
        self.assertEqual(len([e for e in f.events if e[0] == 'checks']), 2)
        self.assertEqual(len([e for e in f.events if e[0] == 'goal']), 2)
        self.assertEqual(first['definitionSha256'], last['definitionSha256'])
        self.assertNotEqual(first['deliverySha256'], last['deliverySha256'])

    def test_coalesced_advancing_commit_preserves_monotone_effects_and_rejects_superseded(self):
        f = self.f
        f.control.process(delivery(f))
        f.control.process(delivery(f, logical(f, 30, [effects.BASE + 1, effects.BASE + 2]), 2))
        before = copy.deepcopy(f.records)
        with self.assertRaisesRegex(BarrierError, 'superseded'): f.control.process(delivery(f, logical(f), 3))
        self.assertEqual(f.records, before)

    def test_same_revision_changed_bytes_or_reused_commit_id_cannot_relabel(self):
        f = self.f; first = logical(f)
        f.control.process(delivery(f, first))
        changed = copy.deepcopy(first); changed['checkpointSha256'] = 'f' * 64
        with self.assertRaisesRegex(BarrierError, 'conflict'): f.control.process(delivery(f, changed, 2))
        reused = logical(f, 2); reused['commitId'] = first['commitId']
        with self.assertRaisesRegex(BarrierError, 'nonmonotone'): f.control.process(delivery(f, reused, 3))

    def test_reset_cannot_remove_historical_checks_or_goal(self):
        f = self.f; f.control.process(delivery(f))
        for number, (checks, goal) in enumerate((([], True), ([effects.BASE + 1], False)), 2):
            with self.assertRaisesRegex(BarrierError, 'nonmonotone'):
                f.control.process(delivery(f, logical(f, 2, checks, goal), number))

    def test_authentication_is_required_for_commit_and_delivery_independently(self):
        f = self.f
        for field in ('commitMac', 'deliveryMac'):
            packet = delivery(f); packet[field] = '0' * 64
            with self.assertRaisesRegex(BarrierError, 'authentication'): f.control.process(packet)
        self.assertNotIn(effects.ACK, f.records)
        self.assertFalse(any(e[0] == 'checks' for e in f.events))

    def test_foreign_run_roster_runtime_and_extra_command_never_apply(self):
        f = self.f
        packets = []
        p = logical(f); p['run']['seedArtifactSha256'] = 'b' * 64; packets.append(delivery(f, p))
        p = logical(f); p['player']['actorUuid'] = uid(99); packets.append(delivery(f, p))
        p = delivery(f); p['identity']['runtimeLaunchId'] = uid(99); packets.append(p)
        p = delivery(f); p['command'] = 'arbitrary'; packets.append(p)
        for packet in packets:
            with self.assertRaises(BarrierError): f.control.process(packet)
        self.assertFalse(any(e[0] == 'checks' for e in f.events))

    def test_checks_must_be_sorted_unique_safe_yacht_ids_and_in_exact_seed(self):
        f = self.f
        for checks in ([effects.BASE + 1] * 2, [effects.BASE + 2, effects.BASE + 1], [True], [effects.BASE], [effects.BASE + 3]):
            with self.assertRaises(BarrierError): f.control.process(delivery(f, logical(f, checks=checks)))
        self.assertNotIn(effects.ACK, f.records)

    def test_actual_shaped_pinned_client_status_enum_is_accepted_and_goal_remains_enum(self):
        f = self.f
        f.context.client_game_state[(0, 1)] = f.module.ClientStatus.CLIENT_CONNECTED
        ack = f.control.process(delivery(f))
        self.assertEqual(ack['result']['state'], 'observed')
        self.assertIs(f.context.client_game_state[(0, 1)], f.module.ClientStatus.CLIENT_GOAL)
        self.assertEqual(f.handlers.observe(f.context, f.roster[0]), ({effects.BASE + 1}, True))

    def test_status_rejects_bool_foreign_enum_integer_subclass_and_unknown_plain_value(self):
        class ForeignStatus(enum.IntEnum): CONNECTED = 5
        class ForeignInteger(int): pass
        f = self.f
        for status in (True, ForeignStatus.CONNECTED, ForeignInteger(5), 6):
            f.context.client_game_state[(0, 1)] = status
            with self.assertRaisesRegex(BarrierError, 'native_observation'):
                f.handlers.observe(f.context, f.roster[0])
        f.module.NetUtils.ClientStatus = ForeignStatus
        with self.assertRaisesRegex(BarrierError, 'handler_abi'): f.control.process(delivery(f))

    def test_wall_and_nonextendable_monotonic_expiry_block_before_application(self):
        f = self.f; packet = delivery(f)
        f.wall[0] += 5000
        with self.assertRaisesRegex(BarrierError, 'expired'): f.control.process(packet)
        self.assertFalse(any(e[0] == 'checks' for e in f.events))
        f.wall[0] = NOW
        replace = f.owner._replace
        def slow(name, *args):
            result = replace(name, *args)
            if name == effects.JOURNAL: f.mono[0] = 5.1
            return result
        f.owner._replace = slow
        with self.assertRaisesRegex(BarrierError, 'expired'): f.control.process(packet)
        self.assertNotIn(effects.ACK, f.records)
        self.assertEqual(f.records[effects.JOURNAL]['slots']['1']['phase'], 'intent')

    def test_late_durability_after_application_holds_unknown_and_publishes_no_ack(self):
        f = self.f; replace = f.owner._replace
        def slow(name, raw, *args):
            result = replace(name, raw, *args)
            if name == effects.JOURNAL and json.loads(raw)['slots']['1']['phase'] == 'observed': f.mono[0] = 6
            return result
        f.owner._replace = slow
        with self.assertRaises(BarrierError): f.control.process(delivery(f))
        self.assertNotIn(effects.ACK, f.records)
        self.assertFalse(f.barrier.state['ready']); self.assertTrue(f.barrier.state['uncertain'])
        self.assertEqual(f.records[effects.JOURNAL]['slots']['1']['phase'], 'unknown')

    def test_lost_ack_reobserves_without_repeating_already_present_normal_effects(self):
        f = self.f; replace = f.owner._replace
        def lost(name, *args):
            if name == effects.ACK: raise OSError('synthetic lost acknowledgement')
            return replace(name, *args)
        f.owner._replace = lost
        with self.assertRaisesRegex(BarrierError, 'apply_unknown'): f.control.process(delivery(f))
        self.assertEqual(f.records[effects.JOURNAL]['slots']['1']['phase'], 'unknown')
        self.assertEqual(len([e for e in f.events if e[0] == 'checks']), 1)
        f.owner._replace = replace
        # Explicit synthetic protected reconciliation, never a runtime fallback.
        f.barrier.state.update(ready=True, uncertain=False)
        f.new_control().process(delivery(f, number=2))
        self.assertEqual(len([e for e in f.events if e[0] == 'checks']), 1)

    def test_record_survives_process_reconstruction_and_key_clears_on_close(self):
        f = self.f; f.control.process(delivery(f))
        f.control.close(); self.assertEqual(f.control._key, bytes(32))
        with self.assertRaises(BarrierError): f.control.process(delivery(f, number=2))
        f.context.location_checks.clear(); f.context.client_game_state.clear()
        f.new_control().process(delivery(f, number=3))
        self.assertEqual(len([e for e in f.events if e[0] == 'checks']), 2)

    def test_missing_journal_and_foreign_launch_refuse_no_automatic_initialization(self):
        f = self.f; saved = f.records.pop(effects.JOURNAL)
        with self.assertRaises(BarrierError): f.new_control()
        self.assertNotIn(effects.JOURNAL, f.records)
        f.records[effects.JOURNAL] = saved
        f.scope['runtimeLaunchId'] = uid(40)
        with self.assertRaisesRegex(BarrierError, 'journal'): f.new_control()

    def test_explicit_initialize_and_open_refuse_pending_evidence(self):
        f = self.f
        pending = Path(f.temporary.name) / ('.' + effects.JOURNAL + '.pending-fixture')
        pending.write_bytes(b'synthetic uncertain write')
        with self.assertRaisesRegex(BarrierError, 'reconciliation'): f.new_control()
        f.records.clear()
        with self.assertRaisesRegex(BarrierError, 'reconciliation'):
            effects.initialize_effects(f.owner, f.run, f.roster, f.scope)
        self.assertEqual(f.records, {})

    def test_takeover_does_not_change_stable_committed_definition_or_grant_access(self):
        f = self.f; commit = logical(f)
        f.control.process(delivery(f, commit))
        stable = f.records[effects.JOURNAL]['slots']['1']['definitionSha256']
        f.scope['credentialEpoch'] += 1
        # This edits only a synthetic protected migration fixture; production
        # migration/enrollment is deliberately not implemented in this cohort.
        f.records[effects.JOURNAL]['identity'] = copy.deepcopy(f.scope)
        newer = f.new_control(); ack = newer.process(delivery(f, commit, 2))
        self.assertEqual(ack['definitionSha256'], stable)
        self.assertNotIn('credentialEpoch', commit)
        self.assertFalse(any('Connect' in str(e) for e in f.events))

    def test_idle_gate_unknown_observation_and_other_thread_block_native_mutation(self):
        f = self.f
        f.barrier.state['gates'] = {'x': {'gate': {'kind': 'idle'}}}
        with self.assertRaises(BarrierError): f.control.process(delivery(f))
        f.barrier.state['gates'].clear(); f.barrier._actual = lambda: None
        with self.assertRaises(BarrierError): f.control.process(delivery(f))
        f.barrier._actual = lambda: []; f.control.thread += 1
        with self.assertRaises(BarrierError): f.control.process(delivery(f))
        self.assertFalse(any(e[0] == 'checks' for e in f.events))

    def test_historical_commit_allowed_under_revocation_without_changing_presence_or_gate(self):
        f = self.f
        f.barrier.state['gates'] = {'x': {'gate': {'kind': 'revocation'}}}
        before = copy.deepcopy(f.barrier.state)
        f.control.process(delivery(f))
        self.assertEqual(f.barrier.state, before)

    def test_code_enrollment_rejects_arbitrary_callbacks_and_changed_source_or_normal_handler(self):
        f = self.f
        with self.assertRaises(BarrierError): effects.VerifiedYachtHandlers(f.module, SOURCE)
        f.module.register_location_checks = lambda *args: None
        with self.assertRaisesRegex(BarrierError, 'handler_abi'): f.control.process(delivery(f))
        self.assertNotIn(effects.ACK, f.records)

    def test_wrong_seed_context_and_reused_master_key_refuse_enrollment(self):
        f = self.f; f.context.seed_name = 'foreign'
        with self.assertRaises(BarrierError): f.new_control()
        f.context.seed_name = f.run['seedName']
        with self.assertRaises(BarrierError):
            effects.YachtEffectsControl(f.owner, f.barrier, f.handlers, f.context, run=f.run, roster=f.roster,
                independent_key=hashlib.sha256(f.barrier._master.encode()).digest())

    def test_clock_rollback_and_duplicate_delivery_changed_expiry_refuse(self):
        f = self.f; packet = delivery(f)
        f.control.process(packet)
        f.wall[0] -= 1
        with self.assertRaisesRegex(BarrierError, 'expired'): f.control.process(delivery(f, number=2))
        f.wall[0] = NOW + 10
        with self.assertRaisesRegex(BarrierError, 'expired'): f.control.process(delivery(f, number=1))

    def test_poll_has_no_import_timer_and_same_delivery_does_not_hot_loop_disk_writes(self):
        f = self.f
        self.assertFalse(f.control.poll_once())
        f.records[effects.CONTROL] = delivery(f)
        self.assertTrue(f.control.poll_once())
        count = len(f.events)
        self.assertFalse(f.control.poll_once()); self.assertEqual(len(f.events), count)

    def test_profile_exact_source_and_foundation_pins_and_closed_registration(self):
        profile = json.loads((ROOT / 'public-beta-effects/runtime/profile.v1.json').read_bytes())
        self.assertTrue(profile['sourceOnly'])
        self.assertTrue(all(v is False for v in profile['qualification'].values()))
        self.assertEqual(profile['moduleSha256'], effects.sha(Path(SPEC.origin).read_bytes()))
        self.assertEqual(profile['multiServerLfSha256'], effects.ENGINE_SHA)
        self.assertEqual(profile['netUtilsLfSha256'], effects.NETUTILS_SHA)
        for row in profile['foundationFiles']:
            self.assertEqual(effects.sha((ROOT / row['path']).read_bytes()), row['sha256'])


if __name__ == '__main__': unittest.main()

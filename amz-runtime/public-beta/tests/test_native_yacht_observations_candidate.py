"""Pure source fixtures, not engine or production qualification."""
import copy
import collections
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
from typing import NamedTuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'public-beta/runtime'))
sys.path.insert(0, str(ROOT / 'public-beta-effects/runtime'))
SPEC = importlib.util.spec_from_file_location('yacht_observations_candidate', ROOT / 'public-beta-observations/runtime/native_yacht_observations.py')
observations = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observations)
from gateway_barrier import BarrierError, canonical, iso
from native_files import NativeFiles

NOW = 1794440000000
KEY = b'fixture observation channel key!'
SEED = b'fixture exact seed, not an AP artifact'


def uid(number): return '00000000-0000-4000-8000-' + str(number).zfill(12)


SOURCE = b'''class Context:
    @staticmethod
    def decompress(data):
        if data != EXPECTED_SEED:
            raise RuntimeError('fixture seed changed')
        return DECODED

    def _load(self, decoded_obj, use_embedded_server_options):
        self.seed_name = decoded_obj['seed_name']

def get_received_items(ctx, team, player, remote_items):
    return ctx.received_items.setdefault((team, player, remote_items), [])

def get_start_inventory(ctx, player, remote_start_inventory):
    return ctx.start_inventory.setdefault(player, []) if remote_start_inventory else []

def send_new_items(ctx):
    pass
'''


def fixture(*, native_tuples=False):
    temporary = tempfile.TemporaryDirectory()
    scope = {'appVariant': 'public-beta', 'policyId': 'public-disposable-beta-v1', 'environmentId': uid(1),
             'dataEpoch': uid(2), 'roomId': uid(3), 'externalId': 'ap-beta-' + uid(3) + '-r1',
             'allocationRevision': 1, 'serverId': 'synthetic', 'attemptId': uid(4),
             'seedRevision': 1, 'credentialEpoch': 1, 'runtimeLaunchId': uid(5)}
    run = {k: scope[k] for k in ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')}
    run.update(configurationRevision=1, seedArtifactSha256=observations.sha(SEED), seedName='synthetic-yacht')
    roster = [{'actorUuid': uid(6), 'slotAlias': 'Yacht_One', 'team': 0, 'slot': 1},
              {'actorUuid': uid(7), 'slotAlias': 'Yacht_Two', 'team': 0, 'slot': 2}]
    records, wall, mono = {}, [NOW], [0.0]
    owner = object.__new__(NativeFiles)
    owner._mutex, owner._directory = threading.RLock(), temporary.name
    owner._active = lambda: None
    def read(name, maximum, optional=False):
        if name not in records:
            if optional: return None
            raise BarrierError('fixture_missing')
        return copy.deepcopy(records[name]), (), hashlib.sha256(canonical(records[name])).digest()
    def replace(name, raw, maximum, previous):
        if previous != read(name, maximum, True): raise BarrierError('fixture_changed')
        if len(raw) > maximum: raise BarrierError('fixture_limit')
        records[name] = json.loads(raw)
        return read(name, maximum)
    owner._read, owner._replace = read, replace
    module = types.ModuleType('MultiServer')
    exec(compile(SOURCE, observations.ENGINE_FILE, 'exec', dont_inherit=True, optimize=0), module.__dict__)
    net = module.NetUtils = types.ModuleType('NetUtils')
    net.NetworkItem = NamedTuple('NetworkItem', [('item', int), ('location', int), ('player', int), ('flags', int)])
    net.NetworkSlot = NamedTuple('NetworkSlot', [('name', str), ('game', str), ('type', int), ('group_members', tuple)])
    net.NetworkItem.__module__ = net.NetworkSlot.__module__ = 'NetUtils'
    net.SlotType = enum.IntFlag('SlotType', {'spectator': 0, 'player': 1, 'group': 2}, module='NetUtils')
    module.NetworkItem, module.NetworkSlot, module.SlotType = net.NetworkItem, net.NetworkSlot, net.SlotType
    module.Utils = types.ModuleType('Utils')
    class KeyedDefaultDict(dict):
        def __missing__(self, key): return 'Unknown item (ID:' + str(key) + ')'
    module.Utils.KeyedDefaultDict = KeyedDefaultDict
    slots = {}
    for player in roster:
        slots[player['slot']] = dict(seed_name=run['seedName'], player_name=player['slotAlias'], player_id=player['slot'], race=False,
            game_difficulty=2, score_for_last_check=1000, score_for_goal=800, number_of_dice_fragments_per_dice=3,
            number_of_roll_fragments_per_roll=3, which_story=-1, allow_manual_input=2, goal_score=800,
            last_check_score=1000, allowed_categories=(tuple if native_tuples else list)(observations.CATEGORY_NAMES[:16]), ap_world_version='2.1.4')
    decoded = {'seed_name': run['seedName'], 'connect_names': {p['slotAlias']: (0, p['slot']) for p in roster},
               'slot_info': {p['slot']: net.NetworkSlot(p['slotAlias'], 'Yacht Dice', net.SlotType.player, ()) for p in roster},
               'slot_data': slots, 'locations': {p['slot']: {observations.BASE + 2: (1, 1, 0), observations.BASE + 10: (2, 2, 0)} for p in roster},
               'precollected_items': {1: (1,) if native_tuples else [1], 2: () if native_tuples else []}}
    module.EXPECTED_SEED, module.DECODED = SEED, decoded
    with patch.object(observations, 'ENGINE_SHA', observations.sha(SOURCE)):
        abi = observations.VerifiedYachtObservationABI(module, SOURCE)
    context = module.Context()
    context.exit_event, context.auto_saver_thread = types.SimpleNamespace(is_set=lambda: False), None
    context.seed_name, context.connect_names, context.slot_data, context.slot_info = run['seedName'], copy.deepcopy(decoded['connect_names']), copy.deepcopy(slots), copy.deepcopy(decoded['slot_info'])
    context.games, context.locations = {1: 'Yacht Dice', 2: 'Yacht Dice'}, copy.deepcopy(decoded['locations'])
    context.start_inventory = {1: [net.NetworkItem(1, -2, 0, 0)]}
    context.received_items = {(0, 1, True): [net.NetworkItem(2, observations.BASE + 10, 2, 0)],
                              (0, 1, False): [net.NetworkItem(3, observations.BASE + 20, 2, 0)]}
    context.item_names = collections.defaultdict(KeyedDefaultDict)
    context.item_names['Yacht Dice'] = KeyedDefaultDict({1: 'Dice', 2: 'Roll', 3: 'Bonus Point'})
    barrier = types.SimpleNamespace(identity=copy.deepcopy(scope), state={'ready': True, 'uncertain': False, 'gates': {}}, _master='Z' * 64)
    def create(**overrides):
        return observations.YachtObservationControl(owner, barrier, abi, context, run=run, roster=roster, scope=scope,
            build_id='b' * 64, seed_bytes=SEED, independent_key=KEY, clock=lambda: wall[0], monotonic=lambda: mono[0], **overrides)
    control = create()
    return types.SimpleNamespace(temporary=temporary, scope=scope, run=run, roster=roster, owner=owner, records=records, wall=wall, mono=mono,
        context=context, module=module, abi=abi, barrier=barrier, control=control, create=create, decoded=decoded)


def command(f, number=1):
    value = {'schema': observations.CONTROL_SCHEMA, 'requestId': uid(100 + number), 'identity': copy.deepcopy(f.scope),
             'actorUuid': f.roster[0]['actorUuid'], 'issuedAt': iso(f.wall[0]), 'expiresAt': iso(f.wall[0] + 5000)}
    value['requestMac'] = hmac.digest(KEY, observations.CONTROL_SCHEMA.encode() + b'\n' + canonical(value), 'sha256').hex()
    return value


class Candidate(unittest.TestCase):
    def setUp(self):
        self.f = fixture(); self.addCleanup(self.f.temporary.cleanup)

    def test_exact_slot_seed_sparse_locations_and_items_handling_seven(self):
        f = self.f; descriptor = f.control.snapshot(f.roster[0]['actorUuid'])
        self.assertEqual(descriptor['locationIds'], [observations.BASE + 2, observations.BASE + 10])
        self.assertNotIn(observations.BASE + 800, descriptor['locationIds'])
        self.assertEqual(descriptor['slotData'], f.decoded['slot_data'][1])
        self.assertEqual(descriptor['observation']['items'], ['Dice', 'Roll'])
        self.assertEqual(descriptor['itemStream']['itemsHandling'], 7)
        self.assertEqual(descriptor['itemStream']['startInventoryCount'], 1)
        self.assertEqual(descriptor['itemStream']['networkItems'][0], {'item': 1, 'location': -2, 'player': 0, 'flags': 0})
        self.assertEqual(descriptor['observation']['bindingSha256'], observations.sha(canonical(descriptor['binding'])))
        self.assertEqual(descriptor['observation']['slotDataSha256'], observations.sha(canonical(descriptor['slotData'])))
        self.assertEqual(descriptor['observation']['locationIdsSha256'], observations.sha(canonical(descriptor['locationIds'])))
        self.assertEqual(descriptor['binding']['buildId'], 'b' * 64)

    def test_appended_native_items_preserve_exact_record_prefix_and_rollback_refuses(self):
        f = self.f; f.control.snapshot(f.roster[0]['actorUuid'])
        f.context.received_items[0, 1, True].append(f.module.NetworkItem(3, observations.BASE + 2, 1, 1))
        self.assertEqual(f.control.snapshot(f.roster[0]['actorUuid'])['observation']['items'], ['Dice', 'Roll', 'Bonus Point'])
        f.context.received_items[0, 1, True].pop()
        with self.assertRaisesRegex(BarrierError, 'prefix_changed'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_pinned_native_tuples_and_json_lists_produce_identical_copied_descriptors(self):
        f = fixture(native_tuples=True); self.addCleanup(f.temporary.cleanup)
        before_context, before_seed = copy.deepcopy(f.context.slot_data), copy.deepcopy(f.decoded)
        for player in f.roster:
            actual = f.control.snapshot(player['actorUuid'])
            expected = self.f.control.snapshot(player['actorUuid'])
            self.assertEqual(actual, expected)
            self.assertEqual(observations.sha(canonical(actual)), observations.sha(canonical(expected)))
            self.assertIs(type(actual['slotData']['allowed_categories']), list)
        self.assertEqual(f.context.slot_data, before_context)
        self.assertEqual(f.decoded, before_seed)
        self.assertIs(type(f.context.slot_data[1]['allowed_categories']), tuple)
        self.assertIs(type(f.decoded['precollected_items'][1]), tuple)
        self.assertIs(type(f.control.seed_start[1]), list)
        f.control.seed_data[1]['allowed_categories'].reverse()
        self.assertEqual(f.context.slot_data, before_context)

    def test_only_exact_native_category_sequence_is_normalized(self):
        class TupleSubclass(tuple): pass
        class ListSubclass(list): pass
        f = self.f
        good = copy.deepcopy(f.decoded['slot_data'][1])
        for categories in (TupleSubclass(good['allowed_categories']), ListSubclass(good['allowed_categories']),
                           [tuple(good['allowed_categories'])], tuple([good['allowed_categories'][0]] * 16),
                           tuple(good['allowed_categories'][:15]), tuple(range(16))):
            with self.subTest(categories_type=type(categories).__name__):
                f.decoded['slot_data'][1] = {**good, 'allowed_categories': categories}
                with self.assertRaises(BarrierError): f.create()
        f.decoded['slot_data'][1] = {**good, 'which_story': (-1,)}
        with self.assertRaisesRegex(BarrierError, 'yacht_observation_json'): f.create()
        with self.assertRaisesRegex(BarrierError, 'yacht_observation_json'): observations._json({'unrelated': (1,)})
        with self.assertRaisesRegex(BarrierError, 'yacht_observation_json'): observations._json({'allowed_categories': tuple(good['allowed_categories'])})

    def test_native_precollected_sequence_copies_only_bounded_exact_integer_ids(self):
        class TupleSubclass(tuple): pass
        class ListSubclass(list): pass
        class IntSubclass(int): pass
        f = self.f
        for items in (TupleSubclass((1,)), ListSubclass([1]), ((1,),), (True,), (IntSubclass(1),),
                      (-1,), (9007199254740992,), tuple([1] * (observations.MAX_ITEMS + 1))):
            with self.subTest(items_type=type(items).__name__):
                f.decoded['precollected_items'][1] = items
                with self.assertRaisesRegex(BarrierError, 'start_inventory'): f.create()
        f.decoded['precollected_items'][1] = (1,)
        control = f.create()
        f.decoded['precollected_items'][1] = (2,)
        self.assertEqual(control.seed_start[1], [1])
        # Genuine Context start/received streams keep their exact native list ABI.
        f.context.start_inventory[1] = tuple(f.context.start_inventory[1])
        with self.assertRaisesRegex(BarrierError, 'item_stream'): control.snapshot(f.roster[0]['actorUuid'])
        f.context.start_inventory[1] = list(f.context.start_inventory[1])
        f.context.received_items[0, 1, True] = tuple(f.context.received_items[0, 1, True])
        with self.assertRaisesRegex(BarrierError, 'item_stream'): control.snapshot(f.roster[0]['actorUuid'])

    def test_normalization_cannot_hide_changed_native_context_categories_or_start_items(self):
        f = fixture(native_tuples=True); self.addCleanup(f.temporary.cleanup)
        categories = f.context.slot_data[1]['allowed_categories']
        f.context.slot_data[1]['allowed_categories'] = categories[1:] + categories[:1]
        with self.assertRaisesRegex(BarrierError, 'native_binding'): f.control.snapshot(f.roster[0]['actorUuid'])
        f.context.slot_data[1]['allowed_categories'] = categories
        f.context.start_inventory[1][0] = f.module.NetworkItem(2, -2, 0, 0)
        with self.assertRaisesRegex(BarrierError, 'start_inventory'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_same_item_names_cannot_hide_changed_network_history(self):
        f = self.f; f.control.snapshot(f.roster[0]['actorUuid'])
        f.context.received_items[0, 1, True][0] = f.module.NetworkItem(2, observations.BASE + 11, 2, 0)
        with self.assertRaisesRegex(BarrierError, 'prefix_changed'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_native_defaultdict_item_maps_are_read_without_mutation_and_cannot_change_after_enrollment(self):
        f = self.f
        before = copy.deepcopy(f.context.item_names)
        f.control.snapshot(f.roster[0]['actorUuid'])
        self.assertEqual(f.context.item_names, before)
        self.assertNotIn(999, f.context.item_names['Yacht Dice'])
        f.context.item_names['Yacht Dice'][1] = 'Roll'
        with self.assertRaisesRegex(BarrierError, 'native_binding'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_seed_and_roster_mismatch_refuse_before_observation(self):
        f = self.f
        f.context.slot_data[1]['seed_name'] = 'foreign'
        with self.assertRaisesRegex(BarrierError, 'slot_data'): f.control.snapshot(f.roster[0]['actorUuid'])
        f.context.slot_data = copy.deepcopy(f.decoded['slot_data'])
        f.decoded['locations'][1][observations.BASE + 800] = (1, 1, 0)
        with self.assertRaisesRegex(BarrierError, 'network_locations'): f.create()

    def test_missing_changed_start_inventory_and_unknown_item_pause_reads(self):
        f = self.f
        f.context.start_inventory[1] = []
        with self.assertRaises(BarrierError): f.control.snapshot(f.roster[0]['actorUuid'])
        f.context.start_inventory[1] = [f.module.NetworkItem(1, -2, 0, 0)]
        f.context.received_items[0, 1, True].append(f.module.NetworkItem(999, 1, 2, 0))
        with self.assertRaisesRegex(BarrierError, 'unknown_item'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_current_launch_native_readiness_idle_hold_and_own_thread_are_required(self):
        f = self.f
        for mutation in ('launch', 'not-ready', 'uncertain', 'idle'):
            before = copy.deepcopy(f.barrier.__dict__)
            if mutation == 'launch': f.barrier.identity['runtimeLaunchId'] = uid(99)
            if mutation == 'not-ready': f.barrier.state['ready'] = False
            if mutation == 'uncertain': f.barrier.state['uncertain'] = True
            if mutation == 'idle': f.barrier.state['gates']['fixture'] = {'reason': 'idle', 'held': True}
            with self.assertRaisesRegex(BarrierError, 'native_not_ready'): f.control.snapshot(f.roster[0]['actorUuid'])
            f.barrier.__dict__.update(before)
        errors = []
        def other():
            try: f.control.snapshot(f.roster[0]['actorUuid'])
            except BarrierError as error: errors.append(str(error))
        thread = threading.Thread(target=other); thread.start(); thread.join()
        self.assertIn('stopped_or_thread', errors[0])

    def test_authenticated_fixed_read_ack_has_independent_response_mac_and_no_grant(self):
        f = self.f; before = copy.deepcopy(f.context.__dict__)
        ack = f.control.process(command(f))
        self.assertEqual(ack, f.records[observations.ACK])
        signed = {k: v for k, v in ack.items() if k != 'responseMac'}
        self.assertEqual(ack['responseMac'], hmac.digest(KEY, observations.ACK_SCHEMA.encode() + b'\n' + canonical(signed), 'sha256').hex())
        self.assertEqual(ack['descriptorSha256'], observations.sha(canonical(ack['descriptor'])))
        self.assertEqual(f.context.__dict__, before)
        self.assertNotIn('grantId', json.dumps(ack)); self.assertNotIn('password', json.dumps(ack))

    def test_foreign_control_extra_fields_wrong_mac_and_unlisted_actor_refuse(self):
        f = self.f
        for change in ('scope', 'extra', 'mac', 'actor'):
            value = command(f)
            if change == 'scope': value['identity']['seedRevision'] += 1
            if change == 'extra': value['slotData'] = {}
            if change == 'mac': value['requestMac'] = '0' * 64
            if change == 'actor':
                value['actorUuid'] = uid(88)
                unsigned = {k: v for k, v in value.items() if k != 'requestMac'}
                value['requestMac'] = hmac.digest(KEY, observations.CONTROL_SCHEMA.encode() + b'\n' + canonical(unsigned), 'sha256').hex()
            with self.assertRaises(BarrierError): f.control.process(value)
        self.assertNotIn(observations.ACK, f.records)

    def test_retry_does_not_extend_monotonic_expiry_and_poll_ignores_consumed_control(self):
        f = self.f; request = command(f); first = f.control.process(request)
        f.wall[0] += 100; f.mono[0] += .1
        self.assertEqual(f.control.process(request), first)
        f.records[observations.CONTROL] = request
        f.wall[0] += 10000; f.mono[0] += 10
        self.assertFalse(f.control.poll_once())
        with self.assertRaisesRegex(BarrierError, 'expired'): f.control.process(request)

    def test_ack_persistence_failure_and_late_io_never_return_success(self):
        f = self.f; replace = f.owner._replace
        f.owner._replace = lambda *args: (_ for _ in ()).throw(BarrierError('fixture_disk_failed'))
        with self.assertRaisesRegex(BarrierError, 'disk_failed'): f.control.process(command(f))
        def late(*args):
            result = replace(*args); f.wall[0] += 6000; f.mono[0] += 6; return result
        f.owner._replace = late
        with self.assertRaisesRegex(BarrierError, 'expired'): f.control.process(command(f, 2))

    def test_changed_enrolled_native_code_and_wrong_class_are_not_a_producer(self):
        f = self.f
        f.module.get_received_items = lambda *args: []
        with self.assertRaisesRegex(BarrierError, 'abi'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_close_clears_observation_key_and_refuses_further_reads(self):
        f = self.f; f.control.close()
        self.assertEqual(f.control.key, b'\x00' * 32)
        with self.assertRaisesRegex(BarrierError, 'stopped_or_thread'): f.control.snapshot(f.roster[0]['actorUuid'])

    def test_profile_pins_actual_candidate_bytes_and_all_foundations_without_claiming_qualification(self):
        profile = json.loads((ROOT / 'public-beta-observations/runtime/profile.v1.json').read_bytes())
        self.assertTrue(profile['sourceOnly']); self.assertTrue(all(value is False for value in profile['qualification'].values()))
        self.assertEqual(profile['moduleSha256'], observations.sha(Path(SPEC.origin).read_bytes()))
        for row in profile['foundationFiles']:
            self.assertEqual(row['sha256'], observations.sha((ROOT / row['path']).read_bytes()))


if __name__ == '__main__': unittest.main()

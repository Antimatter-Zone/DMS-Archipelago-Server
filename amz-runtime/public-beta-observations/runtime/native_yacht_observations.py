"""Explicit private native Yacht observation candidate. No engine import or timer.

The verified loader owns all engine/dependency imports and protected enrollment.
An observation authenticates native facts; it does not authorize a player action.
"""
import copy
import collections
import hashlib
import hmac
import os
import threading
import time
import types

from gateway_barrier import canonical, exact, identity, instant, integer, iso, require, SHA, UUID
from native_files import NativeFiles
from native_yacht_effects import ENGINE_FILE, ENGINE_SHA, NETUTILS_SHA, BASE, _code, _code_identity, run_binding, roster_binding

CONTROL_SCHEMA = 'amz.ap.public-beta.yacht-observation-control.v1'
ACK_SCHEMA = 'amz.ap.public-beta.yacht-observation-ack.v1'
DESCRIPTOR_SCHEMA = 'amz.ap.public-beta.yacht-slot-descriptor.v1'
CONTROL = 'public-yacht-observation-control.json'
ACK = 'public-yacht-observation-ack.json'
MESSAGE_LIMIT = 65536
SNAPSHOT_LIMIT = 1048576
MAX_ITEMS = 4096
SLOT_KEYS = ('seed_name', 'player_name', 'player_id', 'race', 'game_difficulty', 'score_for_last_check',
             'score_for_goal', 'number_of_dice_fragments_per_dice', 'number_of_roll_fragments_per_roll',
             'which_story', 'allow_manual_input', 'goal_score', 'last_check_score', 'allowed_categories', 'ap_world_version')
CATEGORIES = ('Ones', 'Twos', 'Threes', 'Fours', 'Fives', 'Sixes', 'Choice', 'Inverse Choice', 'Pair',
              'Three of a Kind', 'Four of a Kind', 'Tiny Straight', 'Small Straight', 'Large Straight', 'Full House',
              'Yacht', 'Distincts', 'Two times Ones', 'Half of Sixes', 'Twos and Threes', 'Sum of Odds', 'Sum of Evens',
              'Double Threes and Fours', 'Quadruple Ones and Twos', 'Micro Straight', 'Three Odds', '1-2-1 Consecutive',
              'Three Distinct Dice', 'Two Pair', '2-1-2 Consecutive', 'Five Distinct Dice', '4&5 Full House')
CATEGORY_NAMES = tuple('Category ' + name for name in CATEGORIES)
ITEM_NAMES = frozenset(('Dice', 'Dice Fragment', 'Roll', 'Roll Fragment', 'Fixed Score Multiplier', 'Step Score Multiplier',
                        'Encouragement', 'Fun Fact', 'Story Chapter', 'Good RNG', 'Bad RNG', 'Bonus Point',
                        '1 Point', '10 Points', '100 Points', *CATEGORY_NAMES))


def sha(raw): return hashlib.sha256(raw).hexdigest()


def _json(value, depth=0, count=None):
    if count is None: count = [0]
    count[0] += 1
    require(depth <= 32 and count[0] <= 100000, 'yacht_observation_json')
    if value is None or type(value) is bool: return
    if type(value) is int:
        require(abs(value) <= 9007199254740991, 'yacht_observation_json'); return
    if type(value) is str:
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), 'yacht_observation_json'); return
    require(type(value) in (list, dict), 'yacht_observation_json')
    if type(value) is list:
        for item in value: _json(item, depth + 1, count)
    else:
        for key, item in value.items():
            require(type(key) is str, 'yacht_observation_json')
            _json(key, depth + 1, count); _json(item, depth + 1, count)


def _slot_data(value, run, player):
    require(exact(value, SLOT_KEYS), 'yacht_observation_slot_data')
    # Pinned Main.convert_to_base_types serializes the native category list as
    # a tuple. Normalize only this known native field into a private JSON copy.
    categories = value['allowed_categories']
    require(type(categories) in (list, tuple) and len(categories) == 16, 'yacht_observation_categories')
    value = {**value, 'allowed_categories': list(categories)}
    _json(value)
    require(value['seed_name'] == run['seedName'] and value['player_name'] == player['slotAlias'] and
            integer(value['player_id'], 1, 16) and value['player_id'] == player['slot'] and value['ap_world_version'] == '2.1.4' and
            type(value['race']) is bool and integer(value['game_difficulty'], 1, 4) and
            integer(value['score_for_last_check'], 500, 1000) and integer(value['score_for_goal'], 500, 1000) and
            value['last_check_score'] == value['score_for_last_check'] and
            value['goal_score'] == min(value['score_for_goal'], value['last_check_score']) and
            integer(value['number_of_dice_fragments_per_dice'], 1, 5) and
            integer(value['number_of_roll_fragments_per_roll'], 1, 5) and
            type(value['which_story']) is int and value['which_story'] in (-1, 1, 2, 3, 4, 5, 6) and
            type(value['allow_manual_input']) is int and value['allow_manual_input'] in (1, 2), 'yacht_observation_slot_data')
    categories = value['allowed_categories']
    require(type(categories) is list and len(categories) == 16 and
            all(type(name) is str and name in CATEGORY_NAMES for name in categories) and len(set(categories)) == 16 and
            len({CATEGORY_NAMES.index(name) % 16 for name in categories}) == 16, 'yacht_observation_categories')
    return copy.deepcopy(value)


class VerifiedYachtObservationABI:
    """Exact normal native loading/item semantics, captured after full verification.

    Compiling supplied source executes no engine code. Full verified loader
    enrollment remains mandatory; an in-process privileged attacker is outside
    this boundary. The existing gateway may wrap process_client_cmd separately.
    """
    def __init__(self, module, source):
        require(type(module) is types.ModuleType and module.__name__ == 'MultiServer' and
                type(source) is bytes and 0 < len(source) <= 1048576 and sha(source) == ENGINE_SHA,
                'yacht_observation_verified_abi_required')
        compiled = compile(source, ENGINE_FILE, 'exec', dont_inherit=True, optimize=0)
        self.module = module
        context = _code(compiled, 'Context')
        self.expected = {'Context.decompress': _code(context, 'decompress'), 'Context._load': _code(context, '_load')}
        self.expected.update({name: _code(compiled, name) for name in ('get_start_inventory', 'get_received_items', 'send_new_items')})
        self.check()

    def check(self):
        module = self.module
        net = getattr(module, 'NetUtils', None)
        require(type(net) is types.ModuleType and net.__name__ == 'NetUtils', 'yacht_observation_abi')
        for name, fields in (('NetworkItem', ('item', 'location', 'player', 'flags')),
                             ('NetworkSlot', ('name', 'game', 'type', 'group_members'))):
            value = getattr(module, name, None)
            require(type(value) is type and issubclass(value, tuple) and value.__module__ == 'NetUtils' and
                    getattr(net, name, None) is value and value._fields == fields, 'yacht_observation_abi')
        require(module.SlotType is net.SlotType and int(module.SlotType.player) == 1, 'yacht_observation_abi')
        utils = getattr(module, 'Utils', None)
        require(type(utils) is types.ModuleType and utils.__name__ == 'Utils' and
                type(getattr(utils, 'KeyedDefaultDict', None)) is type and issubclass(utils.KeyedDefaultDict, dict), 'yacht_observation_abi')
        functions = {name: getattr(module, name, None) for name in ('get_start_inventory', 'get_received_items', 'send_new_items')}
        functions.update({'Context.decompress': getattr(module.Context, 'decompress', None), 'Context._load': getattr(module.Context, '_load', None)})
        require(all(type(fn) is types.FunctionType and fn.__globals__ is module.__dict__ and
                    _code_identity(fn.__code__) == _code_identity(self.expected[name]) for name, fn in functions.items()),
                'yacht_observation_abi')


class YachtObservationControl:
    """Single-native-loop private read channel. Never accepts browser observations.

    seed_bytes must be the exact captured installed seed bytes already verified
    by the loader. Native Context.decompress parses them under the enrolled ABI.
    Construction and polling do not start an engine, listener or background task.
    """
    def __init__(self, owner, barrier, abi, context, *, run, roster, scope, build_id, seed_bytes,
                 independent_key, clock=None, monotonic=None):
        require(type(owner) is NativeFiles and type(abi) is VerifiedYachtObservationABI, 'yacht_observation_enrollment')
        self.owner, self.barrier, self.abi, self.context = owner, barrier, abi, context
        self.run, self.roster, self.scope = run_binding(run), roster_binding(roster), identity(scope)
        require(type(build_id) is str and SHA.fullmatch(build_id) and type(seed_bytes) is bytes and
                0 < len(seed_bytes) <= 16777216 and sha(seed_bytes) == self.run['seedArtifactSha256'], 'yacht_observation_seed')
        require(all(self.run[k] == self.scope[k] for k in
                    ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')),
                'yacht_observation_identity')
        require(type(independent_key) is bytes and len(independent_key) == 32 and len(set(independent_key)) > 1 and
                independent_key not in (getattr(barrier, '_master', '').encode(),
                                        hashlib.sha256(getattr(barrier, '_master', '').encode()).digest()), 'yacht_observation_independent_key')
        self.key, self.build_id = bytearray(independent_key), build_id
        self.clock, self.monotonic = clock or (lambda: int(time.time() * 1000)), monotonic or time.monotonic
        self.thread, self.closed, self.floor, self.last, self.deadline = threading.get_ident(), False, 0, None, None
        self.previous = {}
        abi.check()
        require(type(context) is abi.module.Context, 'yacht_observation_native_context')
        decoded = abi.module.Context.decompress(seed_bytes)
        require(type(decoded) is dict and decoded.get('seed_name') == self.run['seedName'] and
                decoded.get('connect_names') == {row['slotAlias']: (0, row['slot']) for row in self.roster}, 'yacht_observation_seed_roster')
        self.seed_data, self.seed_locations, self.seed_start = {}, {}, {}
        for player in self.roster:
            slot = player['slot']
            info = decoded['slot_info'].get(slot)
            require(type(info) is abi.module.NetworkSlot and info.game == 'Yacht Dice' and info.name == player['slotAlias'] and
                    info.type is abi.module.SlotType.player and not info.group_members, 'yacht_observation_seed_roster')
            self.seed_data[slot] = _slot_data(decoded['slot_data'][slot], self.run, player)
            locations = decoded['locations'].get(slot)
            require(type(locations) is dict and 1 <= len(locations) <= 1000 and
                    all(integer(v, BASE + 1, BASE + self.seed_data[slot]['last_check_score']) and
                        v != BASE + self.seed_data[slot]['goal_score'] for v in locations), 'yacht_observation_network_locations')
            self.seed_locations[slot] = copy.deepcopy(locations)
            items = decoded['precollected_items'].get(slot, [])
            require(type(items) in (list, tuple) and len(items) <= MAX_ITEMS and all(integer(v, 0) for v in items), 'yacht_observation_start_inventory')
            self.seed_start[slot] = list(items)
        require(set(decoded['slot_info']) == set(self.seed_data) and set(decoded['slot_data']) == set(self.seed_data) and
                set(decoded['locations']) == set(self.seed_data), 'yacht_observation_seed_roster')
        self.item_names = self._native_names()
        self._check()

    def _native_names(self):
        names = self.context.item_names
        require(type(names) in (dict, collections.defaultdict), 'yacht_observation_item_names')
        game = names.get('Yacht Dice')
        require(type(game) in (dict, self.abi.module.Utils.KeyedDefaultDict) and len(game) <= 4096 and
                all(integer(code, 0) and type(name) is str and 0 < len(name) <= 256 for code, name in game.items()),
                'yacht_observation_item_names')
        return dict(game)

    def _check(self):
        require(not self.closed and threading.get_ident() == self.thread, 'yacht_observation_stopped_or_thread')
        self.owner._active()
        self.abi.check()
        require(self.barrier.identity == self.scope and self.barrier.state['ready'] and not self.barrier.state['uncertain'] and
                not any(gate.get('reason') == 'idle' and gate.get('held') for gate in self.barrier.state['gates'].values()),
                'yacht_observation_native_not_ready')
        ctx = self.context
        require(type(ctx) is self.abi.module.Context and not ctx.exit_event.is_set() and ctx.auto_saver_thread is None and
                ctx.seed_name == self.run['seedName'] and ctx.connect_names == {row['slotAlias']: (0, row['slot']) for row in self.roster} and
                ctx.games == {row['slot']: 'Yacht Dice' for row in self.roster} and
                type(ctx.slot_data) is dict and set(ctx.slot_data) == set(self.seed_data) and
                set(ctx.slot_info) == set(self.seed_data) and
                self._native_names() == self.item_names, 'yacht_observation_native_binding')
        for player in self.roster:
            slot = player['slot']; info = ctx.slot_info[slot]
            require(type(info) is self.abi.module.NetworkSlot and info.name == player['slotAlias'] and info.game == 'Yacht Dice' and
                    info.type is self.abi.module.SlotType.player and not info.group_members and
                    _slot_data(ctx.slot_data[slot], self.run, player) == self.seed_data[slot] and
                    dict(ctx.locations[slot]) == self.seed_locations[slot], 'yacht_observation_native_binding')

    def _items(self, player):
        ctx, slot, item_type = self.context, player['slot'], self.abi.module.NetworkItem
        starts, received = ctx.start_inventory.get(slot, []), ctx.received_items.get((0, slot, True), [])
        require(type(starts) is list and type(received) is list and len(starts) + len(received) <= MAX_ITEMS and
                len(starts) == len(self.seed_start[slot]), 'yacht_observation_item_stream')
        require(all(type(item) is item_type and tuple(item) == (code, -2, 0, 0)
                    for item, code in zip(starts, self.seed_start[slot])), 'yacht_observation_start_inventory')
        records, names = [], []
        for item in starts + received:
            require(type(item) is item_type and integer(item.item, 0) and integer(item.location, -2) and
                    integer(item.player, 0, 16) and integer(item.flags, 0, 7), 'yacht_observation_item_stream')
            name = self.item_names.get(item.item)
            require(type(name) is str and name in ITEM_NAMES, 'yacht_observation_unknown_item')
            records.append(dict(zip(('item', 'location', 'player', 'flags'), item))); names.append(name)
        old = self.previous.get(slot, [])
        require(len(records) >= len(old) and records[:len(old)] == old, 'yacht_observation_item_prefix_changed')
        self.previous[slot] = copy.deepcopy(records)
        return records, names, len(starts)

    def snapshot(self, actor_uuid):
        self._check()
        players = [row for row in self.roster if row['actorUuid'] == actor_uuid]
        require(len(players) == 1, 'yacht_observation_player')
        player = players[0]; slot = player['slot']
        records, names, start_count = self._items(player)
        binding = {**self.run, **player, 'buildId': self.build_id}
        slot_data = copy.deepcopy(self.seed_data[slot]); locations = sorted(self.seed_locations[slot])
        observation = {'schema': 'amz.yacht-dice.item-observation.v1', 'bindingSha256': sha(canonical(binding)),
                       'seedName': self.run['seedName'], 'slotAlias': player['slotAlias'], 'team': 0, 'slot': slot,
                       'slotDataSha256': sha(canonical(slot_data)), 'locationIdsSha256': sha(canonical(locations)), 'items': names}
        result = {'schema': DESCRIPTOR_SCHEMA, 'binding': binding, 'slotData': slot_data, 'locationIds': locations,
                  'itemStream': {'itemsHandling': 7, 'startInventoryCount': start_count, 'networkItems': records,
                                 'sha256': sha(canonical(records))}, 'observation': observation}
        require(len(canonical(result)) <= SNAPSHOT_LIMIT - 4096, 'yacht_observation_limit')
        self._check()
        return result

    def _mac(self, schema, value): return hmac.digest(bytes(self.key), schema.encode() + b'\n' + canonical(value), 'sha256').hex()

    def process(self, value):
        with self.owner._mutex:
            self._check()
            require(exact(value, ('schema', 'requestId', 'identity', 'actorUuid', 'issuedAt', 'expiresAt', 'requestMac')) and
                    value['schema'] == CONTROL_SCHEMA and type(value['requestId']) is str and UUID.fullmatch(value['requestId']) and
                    value['identity'] == self.scope and type(value['actorUuid']) is str and UUID.fullmatch(value['actorUuid']) and
                    type(value['requestMac']) is str and SHA.fullmatch(value['requestMac']), 'yacht_observation_control')
            command = {k: copy.deepcopy(v) for k, v in value.items() if k != 'requestMac'}
            require(hmac.compare_digest(value['requestMac'], self._mac(CONTROL_SCHEMA, command)), 'yacht_observation_control_mac')
            now = self.clock(); require(integer(now, self.floor) and 0 < instant(value['expiresAt']) - now <= 5000 and
                                        instant(value['issuedAt']) <= now and
                                        0 < instant(value['expiresAt']) - instant(value['issuedAt']) <= 5000, 'yacht_observation_expired')
            self.floor = now
            digest = sha(canonical(value))
            if self.last and self.last['requestId'] == value['requestId']:
                require(self.last['requestSha256'] == digest and self.monotonic() < self.deadline, 'yacht_observation_retry_changed')
                self.snapshot(value['actorUuid'])  # Recheck genuine native facts before replaying a bounded read.
                return copy.deepcopy(self.last)
            self.deadline = self.monotonic() + (instant(value['expiresAt']) - now) / 1000
            descriptor = self.snapshot(value['actorUuid'])
            ack = {'schema': ACK_SCHEMA, 'requestId': value['requestId'], 'requestSha256': digest, 'identity': copy.deepcopy(self.scope),
                   'observedAt': iso(now), 'expiresAt': value['expiresAt'], 'descriptorSha256': sha(canonical(descriptor)), 'descriptor': descriptor}
            ack['responseMac'] = self._mac(ACK_SCHEMA, ack)
            previous = self.owner._read(ACK, SNAPSHOT_LIMIT, optional=True)
            require(self.monotonic() < self.deadline, 'yacht_observation_expired')
            written = self.owner._replace(ACK, canonical(ack), SNAPSHOT_LIMIT, previous)
            require(written is not None and written[0] == ack and written[2].hex() == sha(canonical(ack)), 'yacht_observation_durability')
            self._check()
            final_now = self.clock()
            require(self.monotonic() < self.deadline and integer(final_now, self.floor) and
                    final_now < instant(value['expiresAt']), 'yacht_observation_expired')
            self.last = copy.deepcopy(ack)
            return ack

    def poll_once(self):
        self._check()
        with os.scandir(self.owner._directory) as entries:
            for count, entry in enumerate(entries):
                require(count < 1024 and not entry.name.startswith('.' + ACK + '.pending-'), 'yacht_observation_reconciliation_required')
        command = self.owner._read(CONTROL, MESSAGE_LIMIT, optional=True)
        if command is not None and self.last and sha(canonical(command[0])) == self.last['requestSha256']:
            return False
        return None if command is None else self.process(command[0])

    def close(self):
        self.closed = True
        self.key[:] = b'\x00' * len(self.key)

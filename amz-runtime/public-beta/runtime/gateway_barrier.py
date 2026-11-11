"""Owned Public-only native state machine; no engine import or auto-start.

Production composition must supply NativeFiles.commit_journal and an exact
native observer after source verification. There is no memory/file fallback.
"""
import base64
import copy
import hashlib
import hmac
import json
import re
import time
import weakref
from datetime import datetime, timezone

CONNECT = 'amz.ap.public-beta.native-connect.v1'
CONTROL = 'amz.ap.public-beta.gateway-control.v2'
ACK = 'amz.ap.public-beta.gateway-control-ack.v2'
STATE = 'amz.ap.public-beta.native-barrier-state.v1'
UUID = re.compile(r'^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
SHA = re.compile(r'^[a-f0-9]{64}$')
IDENTITY = ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'externalId', 'allocationRevision', 'serverId', 'attemptId', 'seedRevision', 'credentialEpoch', 'runtimeLaunchId')
MATERIAL = ('schema', 'identity', 'reservationId', 'connectionId', 'gatewayProcessId', 'grantId', 'actorUuid', 'slotAlias', 'game', 'team', 'slot', 'bindingRevision', 'configurationRevision', 'credentialRevision', 'reservationExpiresAt', 'grantExpiresAt', 'expiresAt')

class BarrierError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code

def require(ok, code='native_control_rejected'):
    if not ok:
        raise BarrierError(code)

def exact(value, fields):
    return type(value) is dict and set(value) == set(fields)

def integer(value, low=0, high=9007199254740991):
    return type(value) is int and low <= value <= high

def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError):
        raise BarrierError('native_control_rejected') from None

def instant(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', value))
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') == value)
        return int(parsed.timestamp() * 1000)
    except (ValueError, OverflowError):
        raise BarrierError('native_control_rejected') from None

def iso(milliseconds):
    return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def identity(value):
    require(exact(value, IDENTITY) and value['appVariant'] == 'public-beta' and value['policyId'] == 'public-disposable-beta-v1')
    require(all(type(value[k]) is str and UUID.fullmatch(value[k]) for k in ('environmentId', 'dataEpoch', 'roomId', 'attemptId', 'runtimeLaunchId')))
    require(all(integer(value[k], 1, 1000000000) for k in ('allocationRevision', 'seedRevision', 'credentialEpoch')))
    require(value['externalId'] == f"ap-beta-{value['roomId']}-r{value['allocationRevision']}" and type(value['serverId']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value['serverId']))
    return copy.deepcopy(value)

def material(value, expected):
    require(exact(value, MATERIAL) and value['schema'] == CONNECT and identity(value['identity']) == expected and len(canonical(value)) <= 4096)
    require(all(type(value[k]) is str and UUID.fullmatch(value[k]) for k in ('reservationId', 'connectionId', 'gatewayProcessId', 'grantId', 'actorUuid')))
    require(type(value['slotAlias']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,16}', value['slotAlias']) and type(value['game']) is str and 0 < len(value['game']) <= 128 and value['game'] != 'Archipelago')
    require(integer(value['team'], 0, 15) and integer(value['slot'], 1, 16) and all(integer(value[k], 1) for k in ('bindingRevision', 'configurationRevision', 'credentialRevision')))
    require(instant(value['expiresAt']) == min(instant(value['reservationExpiresAt']), instant(value['grantExpiresAt'])))
    return copy.deepcopy(value)

def connect_password(master, value):
    require(type(master) is str and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', master))
    value = material(value, identity(value['identity']))
    key = hmac.digest(master.encode(), b'amz.ap.public-beta.native-connect-key.v1\n' + canonical(value['identity']), 'sha256')
    digest = hmac.digest(key, CONNECT.encode() + b'\n' + canonical(value), 'sha256')
    return 'amz1_' + value['reservationId'] + '_' + base64.urlsafe_b64encode(digest).decode().rstrip('=')

def initial_state(scope):
    """Protected first-creation data only. NativeFiles never calls this itself."""
    return {'schema': STATE, 'identity': identity(scope), 'revision': 0, 'clockFloor': 0, 'ready': False, 'uncertain': False,
            'generation': 0, 'everConnected': False, 'initialReadyAt': None, 'lastDisconnectAt': None,
            'preparations': {}, 'gates': {}, 'controls': {}}

def gate_input(gate, request, expected):
    require(exact(gate, ('id', 'operationId', 'requestSha256', 'kind')) and gate['kind'] in ('idle', 'revocation') and
            all(type(gate[k]) is str and UUID.fullmatch(gate[k]) for k in ('id', 'operationId')) and type(gate['requestSha256']) is str and SHA.fullmatch(gate['requestSha256']))
    require(type(request) is dict and request.get('operationId') == gate['operationId'] and
            identity({k: request.get(k) for k in IDENTITY}) == expected)
    domain = 'amz.ap.public-beta.idle-fence.v1' if gate['kind'] == 'idle' else 'amz.ap.public-beta.slot-revocation.v1'
    require(request.get('schema') == domain and hashlib.sha256(domain.encode() + b'\n' + canonical(request)).hexdigest() == gate['requestSha256'])
    if gate['kind'] == 'idle':
        require(exact(request, (*IDENTITY, 'schema', 'action', 'operationId', 'expectedObservationRevision', 'expectedConnectionGeneration', 'provenInitialReadyAt', 'provenLastDisconnectAt')) and
                request['action'] in ('idle_sleep', 'idle_save_close') and integer(request['expectedObservationRevision']) and integer(request['expectedConnectionGeneration']))
        initial, last = request['provenInitialReadyAt'], request['provenLastDisconnectAt']
        require((initial is not None and last is None and request['expectedConnectionGeneration'] == 0) or (last is not None and initial is None))
        instant(initial if initial is not None else last)
    else:
        require(exact(request, (*IDENTITY, 'schema', 'operationId', 'actorUuid', 'slotAlias', 'credentialRevision')) and
                type(request['actorUuid']) is str and UUID.fullmatch(request['actorUuid']) and type(request['slotAlias']) is str and
                re.fullmatch(r'[A-Za-z0-9_-]{1,16}', request['slotAlias']) and integer(request['credentialRevision'], 1))
    return copy.deepcopy({'gate': gate, 'request': request})

class NativeBarrier:
    def __init__(self, scope, master, prior, persist, clock=None, monotonic=None):
        self.identity = identity(scope)
        require(type(master) is str and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', master) and callable(persist))
        self._master, self._persist = master, persist
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._mono, self._deadlines = monotonic or time.monotonic, {}
        require(exact(prior, initial_state(scope)) and prior['schema'] == STATE and prior['identity'] == scope and
                integer(prior['revision']) and integer(prior['clockFloor']) and integer(prior['generation']) and all(type(prior[k]) is bool for k in ('ready', 'uncertain', 'everConnected')))
        require(all(type(prior[k]) is dict and len(prior[k]) <= bound for k, bound in (('preparations', 64), ('gates', 64), ('controls', 256))))
        self.state = copy.deepcopy(prior)
        for name in ('initialReadyAt', 'lastDisconnectAt'):
            if self.state[name] is not None:
                instant(self.state[name])
        for key, row in self.state['preparations'].items():
            require(exact(row, ('material', 'credentialSha256', 'status', 'accepted')) and key == row['material']['reservationId'] and
                    SHA.fullmatch(row['credentialSha256']) and row['status'] in ('prepared', 'consumed', 'connected', 'closed', 'unknown') and type(row['accepted']) is bool)
            material(row['material'], self.identity)
            require(hmac.compare_digest(hashlib.sha256(connect_password(master, row['material']).encode()).hexdigest(), row['credentialSha256']))
            require(row['status'] not in ('prepared', 'consumed') or not row['accepted'])
            require(row['status'] != 'connected' or row['accepted'])
        for key, row in self.state['gates'].items():
            require(exact(row, ('gate', 'request')) and key == row['gate'].get('id'))
            gate_input(row['gate'], row['request'], self.identity)
        for key, row in self.state['controls'].items():
            require(type(key) is str and UUID.fullmatch(key) and exact(row, ('sha256', 'expiresAt')) and type(row['sha256']) is str and SHA.fullmatch(row['sha256']))
            instant(row['expiresAt'])
        require((self.state['everConnected'] and self.state['generation'] > 0 and self.state['initialReadyAt'] is None) or
                (not self.state['everConnected'] and self.state['generation'] == 0 and self.state['lastDisconnectAt'] is None))
        # A previous running process/pending record is never fresh zero.
        self.state['uncertain'] |= self.state['ready'] or any(row['status'] != 'closed' for row in self.state['preparations'].values())
        self.state['ready'] = False
        self._clients, self._inflight, self._detached = {}, set(), set()
        self._attempted = weakref.WeakSet()
        self._observe = None
        self._now()
        self._save()

    def _now(self):
        now = self._clock()
        require(integer(now, 1) and now >= self.state['clockFloor'], 'native_clock_rollback')
        # Persisted with every successful mutation, including expired-row GC.
        # An old private control cannot become valid again after clock rollback.
        self.state['clockFloor'] = now
        return now

    def _save(self):
        self.state['revision'] += 1
        require(len(canonical(self.state)) <= 2 * 1024 * 1024, 'native_journal_limit')
        try:
            self._persist(copy.deepcopy(self.state))
        except BaseException:
            self.state['uncertain'], self.state['ready'] = True, False
            raise BarrierError('native_journal_uncertain') from None

    def bind_observer(self, observer):
        require(self._observe is None and callable(observer), 'native_observer_required')
        self._observe = observer

    def _actual(self):
        if self._observe is None:
            return None
        try:
            clients = list(self._observe())
            require(len(clients) <= 16 and len(set(clients)) == len(clients))
            require(all(client in self._clients and self.state['preparations'][self._clients[client]]['accepted'] for client in clients))
            return clients
        except BaseException:
            return None

    def mark_ready(self):
        require(self._observe is not None and not self.state['uncertain'] and self._actual() == [] and not self._inflight, 'native_not_ready')
        self.state['ready'] = True
        if not self.state['everConnected'] and self.state['initialReadyAt'] is None:
            self.state['initialReadyAt'] = iso(self._now())
        self._save()

    def _blocked(self, value):
        for row in self.state['gates'].values():
            if row['gate']['kind'] == 'idle':
                return True
            request = row['request']
            if all(request[k] == value[k] for k in ('actorUuid', 'slotAlias', 'credentialRevision')):
                return True
        return False

    def _prepared(self, payload):
        require(exact(payload, ('material', 'credentialSha256')) and type(payload['credentialSha256']) is str and SHA.fullmatch(payload['credentialSha256']))
        value = material(payload['material'], self.identity)
        require(hmac.compare_digest(hashlib.sha256(connect_password(self._master, value).encode()).hexdigest(), payload['credentialSha256']))
        return value

    def consume(self, client, args):
        require(type(args) is dict and args.get('cmd') == 'Connect' and client not in self._clients and not getattr(client, 'auth', False) and client not in self._attempted, 'native_connect_rejected')
        # Exact engine Client/Endpoint use __slots__; never add attributes to
        # native objects. Weak ownership bounds refused-socket history by life.
        self._attempted.add(client)
        password = args.get('password')
        require(type(password) is str and len(password) == 85 and not hmac.compare_digest(password, self._master), 'native_connect_rejected')
        match = re.fullmatch(r'amz1_([a-f0-9-]{36})_([A-Za-z0-9_-]{43})', password)
        require(match is not None, 'native_connect_rejected')
        row = self.state['preparations'].get(match[1])
        require(row is not None and row['status'] == 'prepared', 'native_connect_rejected')
        value = row['material']
        require(self.state['ready'] and not self.state['uncertain'] and not self._blocked(value) and instant(value['expiresAt']) > self._now() and
                self._mono() < self._deadlines.get(value['reservationId'], float('-inf')), 'native_connect_rejected')
        require(args.get('name') == value['slotAlias'] and args.get('game') == value['game'] and type(args.get('tags')) in (list, set) and
                all(type(tag) is str for tag in args['tags']) and not {'Tracker', 'TextOnly', 'HintGame'}.intersection(args['tags']), 'native_connect_rejected')
        require(hmac.compare_digest(password, connect_password(self._master, value)), 'native_connect_rejected')
        require(len(self._clients) < 16 and not any(other['status'] in ('consumed', 'connected', 'unknown') and
                (other['material']['slotAlias'] == value['slotAlias'] or (other['material']['team'], other['material']['slot']) == (value['team'], value['slot']))
                for other in self.state['preparations'].values()), 'native_slot_busy')
        row['status'] = 'consumed'
        self._clients[client] = value['reservationId']
        self._inflight.add(client)
        self._save()  # Synchronous durable consume before original Connect can await.
        # A slow durable write must not dispatch an original Connect after its
        # permit expired. The already-consumed record stays retained on failure.
        require(instant(value['expiresAt']) > self._now() and self._mono() < self._deadlines[value['reservationId']], 'native_connect_rejected')
        return copy.deepcopy(value)

    def accepted(self, client):
        require(client in self._clients, 'native_connect_rejected')
        row = self.state['preparations'][self._clients[client]]
        require(not row['accepted'] and getattr(client, 'auth', False) and
                (getattr(client, 'team', None), getattr(client, 'slot', None)) == (row['material']['team'], row['material']['slot']), 'native_connect_rejected')
        row['accepted'], row['status'] = True, 'connected'
        self.state['generation'] += 1
        self.state['everConnected'], self.state['initialReadyAt'], self.state['lastDisconnectAt'] = True, None, None
        self._save()

    def handler_finished(self, client):
        self._inflight.discard(client)
        if client in self._detached:
            self.disconnected(client)
        elif client in self._clients and not self.state['preparations'][self._clients[client]]['accepted']:
            self.state['preparations'][self._clients[client]]['status'] = 'unknown'
            self._save()

    def disconnected(self, client):
        if client not in self._clients:
            return
        self._detached.add(client)
        if client in self._inflight:
            return
        actual = self._actual()
        require(actual is not None and client not in actual, 'native_disconnect_unknown')
        row = self.state['preparations'][self._clients.pop(client)]
        if row['accepted']:
            self.state['generation'] += 1
        row['status'] = 'closed'
        self._detached.discard(client)
        if row['accepted'] and not actual:
            self.state['lastDisconnectAt'] = iso(self._now())
        self._save()

    def _gate(self, command, kind):
        gate, request = command['gate'], command['payload']
        checked = gate_input(gate, request, self.identity)
        require(gate['kind'] == kind)
        old = self.state['gates'].get(gate['id'])
        require(old is None or old == {'gate': gate, 'request': request}, 'native_operation_conflict')
        require(old is not None or len(self.state['gates']) < 64, 'native_journal_limit')
        self.state['gates'][gate['id']] = checked
        self._save()  # Admission closure is durable before any zero evaluation.
        return gate, request

    def control(self, command):
        require(exact(command, ('schema', 'operationId', 'command', 'identity', 'gate', 'payload', 'issuedAt', 'expiresAt')) and command['schema'] == CONTROL and
                type(command['operationId']) is str and UUID.fullmatch(command['operationId']) and identity(command['identity']) == self.identity and len(canonical(command)) <= 65536)
        now = self._now()
        require(instant(command['issuedAt']) <= now < instant(command['expiresAt']) and 0 < instant(command['expiresAt']) - instant(command['issuedAt']) <= 8000)
        digest = hashlib.sha256(CONTROL.encode() + b'\n' + canonical(command)).hexdigest()
        self.state['controls'] = {key: value for key, value in self.state['controls'].items() if instant(value['expiresAt']) > now}
        old = self.state['controls'].get(command['operationId'])
        require(old is None or old['sha256'] == digest, 'native_operation_conflict')
        require(old is not None or len(self.state['controls']) < 256, 'native_journal_limit')
        self.state['controls'][command['operationId']] = {'sha256': digest, 'expiresAt': command['expiresAt']}
        kind, payload = command['command'], command['payload']
        if kind in ('prepare_connection', 'confirm_connection', 'detach_slot'):
            require(command['gate'] is None)
            value = self._prepared(payload)
            key = value['reservationId']
            row = self.state['preparations'].get(key)
            require(row is None or row['material'] == value and row['credentialSha256'] == payload['credentialSha256'], 'native_operation_conflict')
            if kind == 'prepare_connection':
                require(self.state['ready'] and not self.state['uncertain'] and not self._blocked(value) and 0 < instant(value['expiresAt']) - now <= 10000, 'native_not_ready')
                self.state['preparations'] = {key: item for key, item in self.state['preparations'].items() if item['status'] != 'closed' or instant(item['material']['expiresAt']) > now}
                self._deadlines = {key: value for key, value in self._deadlines.items() if key in self.state['preparations']}
                require(row is not None or len(self.state['preparations']) < 64, 'native_journal_limit')
                require(not any(item is not row and item['status'] != 'closed' and (item['material']['team'], item['material']['slot']) == (value['team'], value['slot']) for item in self.state['preparations'].values()), 'native_slot_busy')
                if row is None:
                    row = {'material': value, 'credentialSha256': payload['credentialSha256'], 'status': 'prepared', 'accepted': False}
                    self.state['preparations'][key] = row
                    self._deadlines[key] = self._mono() + (instant(value['expiresAt']) - now) / 1000
                status = 'prepared' if row['status'] == 'prepared' else 'unknown'
            elif kind == 'confirm_connection':
                status = 'connected' if row and row['status'] == 'connected' and self._actual() is not None and any(self._clients.get(client) == key for client in self._actual()) else 'unknown'
            else:
                require(row is not None, 'native_slot_unknown')
                pending = any(self._clients.get(client) == key for client in self._inflight)
                actual = self._actual()
                if actual is not None and not pending and not any(self._clients.get(client) == key for client in actual):
                    row['status'] = 'closed'
                status = 'closed' if row['status'] == 'closed' else 'unknown'
            result = {'state': status, 'connectionGeneration': None if status == 'unknown' else self.state['generation'], 'slotAdmissionHeld': status == 'closed'}
        elif kind == 'revoke_slot':
            gate, request = self._gate(command, 'revocation')
            rows = [row for row in self.state['preparations'].values() if all(row['material'][k] == request[k] for k in ('actorUuid', 'slotAlias', 'credentialRevision'))]
            done = self._actual() is not None and all(row['status'] == 'closed' for row in rows) and not self._inflight and not self.state['uncertain']
            result = {'nativeAcknowledged': done, 'slotAdmissionHeld': True}
        elif kind == 'idle_fence':
            gate, request = self._gate(command, 'idle')
            actual = self._actual()
            known = actual is not None and self.state['ready'] and not self.state['uncertain'] and not self._inflight and all(row['status'] in ('connected', 'closed') for row in self.state['preparations'].values())
            matched = request['expectedConnectionGeneration'] == self.state['generation'] and request['provenInitialReadyAt'] == self.state['initialReadyAt'] and request['provenLastDisconnectAt'] == self.state['lastDisconnectAt']
            status = 'busy' if known and actual else 'fenced' if known and not actual and matched else 'unknown'
            result = {**self.identity, 'schema': 'amz.ap.public-beta.idle-fence-receipt.v1', 'requestSha256': gate['requestSha256'], 'state': status, 'fenceId': gate['id'] if status == 'fenced' else None,
                      'connectedGameClients': len(actual) if known else None, 'connectionGeneration': self.state['generation'] if known else None,
                      'provenInitialReadyAt': request['provenInitialReadyAt'], 'provenLastDisconnectAt': request['provenLastDisconnectAt'], 'observedAt': iso(now)}
        elif kind == 'fence_held':
            gate = command['gate']
            require(payload is None and exact(gate, ('id', 'operationId', 'requestSha256', 'kind')))
            retained = self.state['gates'].get(gate['id'])
            held = retained is not None and retained['gate'] == gate and gate['kind'] == 'idle' and self.state['ready'] and not self.state['uncertain'] and not self._inflight and self._actual() == []
            if held:
                request = retained['request']
                held = request['expectedConnectionGeneration'] == self.state['generation'] and request['provenInitialReadyAt'] == self.state['initialReadyAt'] and request['provenLastDisconnectAt'] == self.state['lastDisconnectAt']
            result = {'held': held}
        else:
            raise BarrierError('native_control_rejected')
        self._save()  # Concrete writer must fsync journal before exposing this ACK.
        return {'schema': ACK, 'operationId': command['operationId'], 'commandSha256': digest, 'identity': copy.deepcopy(self.identity), 'observedAt': iso(now), 'result': result}

    def shutdown(self):
        self.state['ready'] = False
        self.state['uncertain'] |= bool(self._inflight or self._actual() is None or self._actual())
        self._save()

"""Private first-start observation and activation, outside the gameplay channel.

Only the installed loader can open this object: it consumes the real captured
composition, native ABI/context, and the bootstrap's inherited worker channel.
Neither a JSON packet nor an HMAC alone authorizes NativeBarrier.mark_ready.
"""
import copy
import hashlib
import hmac
import os
import threading
import weakref

OBSERVE = 'amz.ap.public-beta.yacht-first-start-observe.v1'
READY = 'amz.ap.public-beta.yacht-first-start-held-ready.v1'
ACTIVATE = 'amz.ap.public-beta.yacht-first-start-activate.v1'
ACTIVATED = 'amz.ap.public-beta.yacht-first-start-activated.v1'
CONTROL = 'first-start-control.json'
ACK = 'first-start-ack.json'
CONTROL_BYTES = 4096
ACK_BYTES = 2048
_OWNERS = weakref.WeakKeyDictionary()


def need(value):
    if not value: raise RuntimeError('first_start_refused')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def held_context_current(observer):
    """Same real ABI and native seed checks, with the actual barrier held."""
    o = observer
    require, slot_data = o._first_modules
    require(not o.closed and threading.get_ident() == o.thread, 'first_start_thread')
    o.owner._active(); o.abi.check()
    b, ctx = o.barrier, o.context
    require(b.identity == o.scope and b.state['ready'] is False and not b.state['uncertain'] and
            b.state['generation'] == 0 and not b.state['everConnected'] and
            b.state['initialReadyAt'] is None and b.state['lastDisconnectAt'] is None and
            not b.state['preparations'] and not b.state['gates'] and not b.state['controls'] and
            not b._clients and not b._inflight and not b._detached and b._actual() == [], 'first_start_not_held')
    require(type(ctx) is o.abi.module.Context and not ctx.exit_event.is_set() and ctx.auto_saver_thread is None and
            ctx.seed_name == o.run['seedName'] and
            ctx.connect_names == {r['slotAlias']: (0, r['slot']) for r in o.roster} and
            ctx.games == {r['slot']: 'Yacht Dice' for r in o.roster} and
            type(ctx.slot_data) is dict and set(ctx.slot_data) == set(o.seed_data) and
            set(ctx.slot_info) == set(o.seed_data) and o._native_names() == o.item_names,
            'first_start_native_binding')
    for player in o.roster:
        slot = player['slot']; info = ctx.slot_info[slot]
        require(type(info) is o.abi.module.NetworkSlot and info.name == player['slotAlias'] and info.game == 'Yacht Dice' and
                info.type is o.abi.module.SlotType.player and not info.group_members and
                slot_data(ctx.slot_data[slot], o.run, player) == o.seed_data[slot] and
                dict(ctx.locations[slot]) == o.seed_locations[slot], 'first_start_native_binding')
        records, _, starts = o._items(player)
        require(len(records) == starts and not ctx.location_checks.get((0, slot), set()), 'first_start_not_fresh')


class FirstStart:
    __slots__ = ('__weakref__',)
    def __new__(cls, *args, **kwargs): raise RuntimeError('first_start_owner_brand')

    def current(self): return _current(self)

    def poll_once(self):
        s = _current(self); w, fd = s['worker'], s['boot']
        w.audit_boot(fd, s['startup'], sealed=True)
        if '.first-start-control.json.pending' in os.listdir(fd):
            # Exact bounded producer write-in-progress, not a completed packet.
            # Preserve it and continue only within the original startup clock.
            return False
        try: raw, identity, handle = w.read_at(fd, CONTROL, CONTROL_BYTES, keep=True)
        except FileNotFoundError: return False
        try:
            request = w.decode(raw, CONTROL_BYTES); request_sha = sha(raw)
            if s['last'] is not None:
                if request_sha == s['last']['sha256']:
                    _current(self); return False
                # Only one observation, then its exact activation, in this PID.
                need(s['last']['kind'] == OBSERVE and request.get('schema') == ACTIVATE)
            need(set(request) == ({'schema', 'requestId', 'nonce', 'identitySha256', 'issuedAt', 'expiresAt', 'requestMac'}
                                  if request.get('schema') == OBSERVE else
                                  {'schema', 'requestId', 'nonce', 'heldReadySha256', 'activation', 'issuedAt', 'expiresAt', 'requestMac'}))
            need(request['schema'] in (OBSERVE, ACTIVATE) and type(request['requestId']) is str and
                 w.re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', request['requestId']) and
                 request['nonce'] == s['challenge']['nonce'] and type(request['requestMac']) is str and
                 w.re.fullmatch('[a-f0-9]{64}', request['requestMac']))
            packet = {k: v for k, v in request.items() if k != 'requestMac'}
            need(hmac.compare_digest(request['requestMac'], _mac(s, request['schema'], packet)))
            short = w.Budget(5000, parent=s['startup'], issued=request['issuedAt'], expires=request['expiresAt'])
            if s['last'] is not None: need(request['requestId'] != s['last']['requestId'])
            _same_request(s, handle, identity, raw); _current(self); short.current()
            if request['schema'] == OBSERVE:
                need(s['last'] is None and request['identitySha256'] == sha(w.canonical(s['binding']['identity'])))
                observed = {'schema': READY, 'binding': s['binding'], 'listenerReady': True,
                            'admissionHeld': True, 'connectedClients': 0,
                            'issuedAt': request['issuedAt'], 'expiresAt': request['expiresAt']}
                s['readySha256'] = sha(w.canonical(observed))
                s['channel'].send('held-ready', observed, short)
                reply = s['channel'].receive('held-ready-accepted', short)
                need(reply == {'nonce': s['challenge']['nonce'], 'heldReadySha256': s['readySha256']})
                _same_request(s, handle, identity, raw); _current(self); short.current()
                ack = {'schema': READY, 'requestId': request['requestId'], 'nonce': s['challenge']['nonce'],
                       'heldReadySha256': s['readySha256'], 'bindingSha256': sha(w.canonical(s['binding'])),
                       'listenerReady': True, 'admissionHeld': True, 'connectedClients': 0,
                       'issuedAt': request['issuedAt'], 'expiresAt': request['expiresAt']}
                _publish_ack(self, ack, short)
                s['readyBudget'] = short
                s['last'] = {'sha256': request_sha, 'requestId': request['requestId'], 'kind': OBSERVE}
                return False
            need(s['last'] is not None and request['heldReadySha256'] == s['readySha256'])
            short = w.Budget(5000, parent=s['readyBudget'], issued=request['issuedAt'], expires=request['expiresAt'])
            need(type(request['activation']) is dict)
            s['channel'].send('verify-activation', {'requestId': request['requestId'], 'nonce': s['challenge']['nonce'],
                'heldReadySha256': s['readySha256'], 'activation': request['activation']}, short)
            reply = s['channel'].receive('activation-verified', short)
            activation_sha = sha(w.canonical(request['activation']))
            need(reply == {'requestId': request['requestId'], 'nonce': s['challenge']['nonce'],
                           'heldReadySha256': s['readySha256'], 'activationSha256': activation_sha})
            signed = request['activation']['body']
            short = w.Budget(5000, parent=short, issued=signed['issuedAt'], expires=signed['expiresAt'])
            _same_request(s, handle, identity, raw); _current(self); short.current()
            # Synchronous native loop: no engine/await callback occurs between
            # the final held observation and the real durable ready transition.
            s['barrier'].mark_ready()
            need(s['barrier'].state['ready'] and not s['barrier'].state['uncertain'])
            short.current(); s['startup'].current()
            s['activation'] = {'requestId': request['requestId'], 'activationSha256': activation_sha,
                               'issuedAt': signed['issuedAt'], 'expiresAt': signed['expiresAt'], 'budget': short}
            s['last'] = {'sha256': request_sha, 'requestId': request['requestId'], 'kind': ACTIVATE}
            return True
        finally: os.close(handle)

    def activated(self):
        s = _state(self); w = s['worker']; need(s['activation'] is not None and not s['completed'])
        short = s['activation']['budget']; short.current()
        _ready_current(s)
        s['channel'].send('activated', {'nonce': s['challenge']['nonce'], 'activationSha256': s['activation']['activationSha256'],
            'heldReadySha256': s['readySha256'], 'journalSha256': sha(w.canonical(s['guard'].files.load_journal()))}, short)
        reply = s['channel'].receive('activated-accepted', short)
        need(reply == {'nonce': s['challenge']['nonce'], 'activationSha256': s['activation']['activationSha256']})
        s['startup'].current(); short.current()
        _publish_ack(self, {'schema': ACTIVATED, 'requestId': s['activation']['requestId'],
            'nonce': s['challenge']['nonce'], 'activationSha256': s['activation']['activationSha256'],
            'heldReadySha256': s['readySha256'], 'issuedAt': s['activation']['issuedAt'],
            'expiresAt': s['activation']['expiresAt']}, short, activated=True)
        s['channel'].close(); s['completed'] = True

    def close(self):
        s = _state(self); s['closed'] = True
        s['observer'].close()
        for i in range(len(s['key'])): s['key'][i] = 0
        first = None
        for item in s['inputs']:
            descriptor, item['fd'] = item['fd'], None
            try: os.close(descriptor)
            except OSError as error:
                if first is None: first = error
        if first is not None: raise first


def _state(owner):
    need(type(owner) is FirstStart and owner in _OWNERS)
    s = _OWNERS[owner]; need(not s['closed'] and s['pid'] == os.getpid() and s['thread'] == threading.get_ident())
    return s


def _current(owner):
    s = _state(owner); need(not s['completed'])
    s['startup'].current(); s['worker'].boot_root_current(s['boot'])
    _inputs_current(s)
    s['observer']._check()
    need(s['base'].native_listener_ready(s['context'], s['config']['port']))
    s['startup'].current()
    return s


def _inputs_current(s):
    with s['guard'].transaction():
        s['composition']._state(s['guard'])
        for item in s['inputs']:
            need(s['worker'].private(os.fstat(item['fd']), item['maximum']) == item['identity'] ==
                 s['worker'].private(os.stat(item['name'], dir_fd=s['guard'].files._directory,
                                            follow_symlinks=False), item['maximum']) and
                 sha(os.pread(item['fd'], item['maximum'] + 1, 0)) == item['sha256'])


def _ready_current(s):
    s['startup'].current(); s['worker'].boot_root_current(s['boot']); _inputs_current(s)
    # Genuine existing ready-state check, after the genuine ready transition.
    s['observations'].YachtObservationControl._check(s['observer'])
    need(s['barrier']._actual() == [] and not s['barrier']._inflight and
         s['base'].native_listener_ready(s['context'], s['config']['port']))
    s['startup'].current()


def _mac(s, domain, value):
    return hmac.digest(bytes(s['key']), domain.encode() + b'\n' + s['worker'].canonical(value), 'sha256').hex()


def _same_request(s, fd, expected, raw):
    w = s['worker']; w.boot_root_current(s['boot'])
    need(w.private(os.fstat(fd), CONTROL_BYTES) == expected ==
         w.private(os.stat(CONTROL, dir_fd=s['boot'], follow_symlinks=False), CONTROL_BYTES) and
         os.pread(fd, CONTROL_BYTES + 1, 0) == raw)


def _publish_ack(owner, value, short, *, activated=False):
    s = _state(owner); w = s['worker']; short.current()
    if not activated: _current(owner)
    else: _ready_current(s)
    value = {**value, 'responseMac': _mac(s, value['schema'], value)}; raw = w.canonical(value)
    need(0 < len(raw) <= ACK_BYTES)
    w.audit_boot(s['boot'], short, sealed=True)
    pending = '.' + ACK + '.pending'
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=s['boot'])
    try:
        rest = memoryview(raw)
        while rest:
            short.current(); count = os.write(fd, rest); need(count > 0); rest = rest[count:]
        os.fsync(fd); expected = w.private(os.fstat(fd), ACK_BYTES)
        check, staged = w.read_at(s['boot'], pending, ACK_BYTES); need(check == raw and staged == expected)
        # Replace only our exact previous ACK; foreign/pending objects refuse.
        if s['ack'] is not None:
            previous, identity = w.read_at(s['boot'], ACK, ACK_BYTES)
            need((previous, identity) == s['ack'])
        else:
            try: os.stat(ACK, dir_fd=s['boot'], follow_symlinks=False)
            except FileNotFoundError: pass
            else: need(False)
        short.current()
        os.replace(pending, ACK, src_dir_fd=s['boot'], dst_dir_fd=s['boot']); os.fsync(s['boot'])
        check, final = w.read_at(s['boot'], ACK, ACK_BYTES)
        need(check == raw and final == w.private(os.fstat(fd), ACK_BYTES) and final[:8] == expected[:8])
        s['ack'] = (check, final); w.audit_boot(s['boot'], short, sealed=True); short.current()
        if activated: _ready_current(s)
        else: _current(owner)
        short.current()
    finally: os.close(fd)


def open_first_start(worker, channel, proof, boot_fd, composition, sources, guard, base, module, native_source,
                     context, barrier, config, seed, keys, artifact_sha):
    """Installed loader-only join; actual private brands are verified here."""
    need(type(channel) is worker.PrivateChannel and not channel.closed)
    approval = worker.approval(proof, channel); need(approval['consumed'])
    channel.startup.current(); worker.boot_root_current(boot_fd)
    state = composition._state(guard)
    need(state['sources'] is sources and state['owner'] is guard.files)
    modules = composition._sources(sources)['modules']; observations = modules['native_yacht_observations']
    need(type(barrier) is modules['gateway_barrier'].NativeBarrier and type(guard.files) is modules['native_files'].NativeFiles)
    # This subclass changes only the readiness precondition. It never changes
    # the barrier flag, native Context or upstream implementation/functions.
    class HeldObservation(observations.YachtObservationControl):
        _first_modules = (observations.require, observations._slot_data)
        def _check(self): held_context_current(self)
    observer = object.__new__(HeldObservation); inputs = []; owner = None
    try:
        observations.YachtObservationControl.__init__(observer, guard.files, barrier,
            observations.VerifiedYachtObservationABI(module, native_source), context,
            run=config['run'], roster=config['roster'], scope=config['identity'], build_id=config['browserBuildSha256'],
            seed_bytes=seed, independent_key=keys[0])
        for row in approval['body']['files']:
            raw, identity, fd = worker.read_at(guard.files._directory, row['name'], row['bytes'], keep=True)
            inputs.append({'name': row['name'], 'fd': fd, 'identity': identity,
                           'maximum': row['bytes'], 'sha256': row['sha256']})
            info = os.fstat(fd)
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'] and
                 row['device'] == str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)) and
                 row['inode'] == str(info.st_ino) and row['uid'] == info.st_uid and row['gid'] == info.st_gid and
                 row['mode'] == (info.st_mode & 0o777))
        observer._check(); need(base.native_listener_ready(context, config['port']))
        binding = {'identity': config['identity'], 'operationId': approval['body']['operationId'],
            'nativeInstance': channel.challenge['process'], 'configurationSha256': sha(worker.canonical(config)),
            'seedArtifactSha256': sha(seed), 'seedNameSha256': sha(context.seed_name.encode('utf-8')),
            'rosterSha256': sha(worker.canonical(config['roster'])), 'browserBuildSha256': config['browserBuildSha256'],
            'listener': {'host': context.host, 'port': config['port']}, 'native': approval['body']['native'],
            'provider': {k: approval['body']['provider'][k] for k in ('serverUuid', 'containerId', 'imageId', 'volumeId')},
            'firstStart': {'artifactSha256': artifact_sha, 'profileSha256': worker.PROFILE_SHA},
            'publicationScopeSha256': config['publicationScopeSha256'], 'startupExpiresAt': worker.iso(channel.startup.expiry)}
        need(binding['listener']['host'] == '0.0.0.0')
        owner = object.__new__(FirstStart)
        _OWNERS[owner] = {'worker': worker, 'channel': channel, 'startup': channel.startup, 'boot': boot_fd,
            'composition': composition, 'guard': guard, 'barrier': barrier, 'observer': observer,
            'observations': observations,
            'inputs': inputs,
            'context': context, 'base': base, 'config': config, 'challenge': channel.challenge,
            'binding': copy.deepcopy(binding), 'key': bytearray(hmac.digest(keys[0], b'amz.ap.public-beta.yacht-first-start-key.v1', 'sha256')),
            'pid': os.getpid(), 'thread': threading.get_ident(), 'closed': False, 'completed': False,
            'last': None, 'ack': None, 'activation': None, 'readySha256': None, 'readyBudget': None}
        _current(owner); return owner
    except BaseException:
        if hasattr(observer, 'key'): observer.close()
        if owner is not None and owner in _OWNERS:
            abandoned = _OWNERS.pop(owner)
            for i in range(len(abandoned['key'])): abandoned['key'][i] = 0
        for item in inputs: os.close(item['fd'])
        raise

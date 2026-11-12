"""Fresh-only immutable Yacht publication runtime. No engine import on import.

Restore, replacement and production admission are explicitly outside this
profile. Every existing/partial run refuses; nothing is wiped or adopted.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import stat
import sys
import types

OWNED = Path('/opt/amz-ap-public')
PRIVATE = Path('/home/container/.amz')
ENGINE = Path('/engine')
PROFILE_SHA = '45d0e5de9dd8aade8197b2e66a36d5b6d1bfcf9e15f713c639c676b6b1978c1e'
FRESH_LOADER_SHA = 'd5afd585c3b4571275b8dad4696d4d7e0d64665eee7650a7ef7a8eda6e46285d'
FOUNDATION_SHA = '61ce07cade1d0c79e4ac421171ce7272a8557623c5668a4d296f947e98c9a509'
PROFILE = 'public-yacht-publication-fresh-v1'
COMPOSITION_SHA = '9883a419994438fe60c0e561b250480c60de2a1ee1aa932989c97b67e2565124'
ACTION_LOADER_SHA = 'a23eeed804c4d512ce4cb01b6b5fd8c2c3791784703d82cf28104f3247cd2587'
FILES = ('gateway_barrier.py', 'gateway_hooks.py', 'native_files.py', 'checkpoint_custody.py', 'native_checkpoint.py',
         'loader.py', 'launcher.mjs', 'portal-source-manifest.json', 'runtime-profile.json', 'source-transfer.v1.json',
         'fresh_loader.py', 'fresh-runtime-profile.json', 'native_yacht_effects.py', 'effects-profile.v1.json',
         'native_yacht_observations.py', 'observation-profile.v1.json', 'yacht_packet_policy.py', 'native_budget.py', 'source-foundation.v1.json', 'publication.py', 'native_composition.py', 'yacht_actions_loader.py')
STAGE = 'guard'
FRESH_FILES = frozenset(('public-runtime.json', 'public-seed.archipelago', 'public-yacht-keys.json',
                         'public-publication-scope.json', 'public-control-publication.lock'))


def need(ok, code='yacht_runtime_refused'):
    if not ok: raise RuntimeError(code)


def bootstrap(file):
    """Bounded same-FD bootstrap before any foundation code can execute."""
    for parent in (file.parent, *file.parent.parents):
        info = parent.lstat(); need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    before = file.lstat(); need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 262144)
    fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(fd); raw = bytearray()
        while len(raw) <= 262144:
            part = os.read(fd, min(65536, 262145 - len(raw)))
            if not part: break
            raw.extend(part)
        after, named = os.fstat(fd), file.lstat()
        identity = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns,
                              v.st_birthtime_ns if sys.platform == 'win32' else v.st_ctime_ns)
        need(identity(before) == identity(opened) == identity(after) == identity(named) and len(raw) == before.st_size)
        return bytes(raw)
    finally: os.close(fd)


def foundation():
    raw = bootstrap(OWNED / 'fresh_loader.py')
    need(hashlib.sha256(raw).hexdigest() == FRESH_LOADER_SHA)
    module = types.ModuleType('verified_fresh_yacht_foundation')
    module.__file__ = str(OWNED / 'fresh_loader.py')
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True, optimize=0), module.__dict__)
    return module


def validate_configuration(base, value):
    need(base.exact(value, ('schema', 'profileId', 'identity', 'runtimeArtifactSha256', 'executionProfileSha256', 'worldPackSha256',
                           'engineCommit', 'engineInventorySha256', 'seedArtifactSha256', 'password', 'port', 'journalMode',
                           'requiredCheckpointSha256', 'run', 'roster', 'browserBuildSha256', 'publicationScopeSha256')))
    need(value['schema'] == 'amz.ap.public-beta.yacht-publication-configuration.v1' and value['profileId'] == PROFILE and
         value['executionProfileSha256'] == PROFILE_SHA and type(value['publicationScopeSha256']) is str and
         base.SHA.fullmatch(value['publicationScopeSha256']) and base.SHA.fullmatch(value['browserBuildSha256']))
    legacy = {k: value[k] for k in ('identity', 'runtimeArtifactSha256', 'worldPackSha256', 'engineCommit', 'engineInventorySha256',
                                   'seedArtifactSha256', 'password', 'port', 'journalMode', 'requiredCheckpointSha256')}
    base.validate_configuration(dict(legacy, schema='amz.ap.public-beta.native-configuration.v1', profileId='public-disposable-beta-v1'))
    return value


def validate_keys(base, value, config):
    need(base.exact(value, ('schema', 'identity', 'runtimeArtifactSha256', 'runSha256', 'observationKey', 'effectsKey')) and
         value['schema'] == 'amz.ap.public-beta.yacht-runtime-keys.v1' and value['identity'] == config['identity'] and
         value['runtimeArtifactSha256'] == config['runtimeArtifactSha256'] and value['runSha256'] == base.sha(base.canonical(config['run'])))
    keys = []
    master = config['password'].encode()
    forbidden = {master, hashlib.sha256(master).digest(), hashlib.sha256(master).hexdigest().encode(),
                 base64.b64encode(master), base64.urlsafe_b64encode(master).rstrip(b'=')}
    forbidden.add(hmac.digest(master, b'amz.ap.public-beta.native-connect-key.v1\n' + base.canonical(config['identity']), 'sha256'))
    # Also reject a configured master represented as a 32-byte hex/base64url key.
    if len(master) == 64:
        try: forbidden.add(bytes.fromhex(master.decode()))
        except ValueError: pass
    try: forbidden.add(base64.urlsafe_b64decode(master + b'=' * (-len(master) % 4)))
    except (ValueError, TypeError): pass
    for name in ('observationKey', 'effectsKey'):
        text = value[name]; need(type(text) is str and base.SHA.fullmatch(text))
        key = bytes.fromhex(text); need(len(set(key)) > 1 and key not in forbidden and key not in keys)
        keys.append(key)
    return tuple(keys)


def scratch_directory():
    """Only a bounded private tmpfs; generated caches never enter retained root."""
    tmp = Path('/tmp'); info = tmp.lstat(); need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode))
    with open('/proc/self/mountinfo', 'rb') as stream: raw = stream.read(262145)
    need(len(raw) <= 262144)
    rows = [line.split(' - ', 1) for line in raw.decode('utf-8', errors='strict').splitlines() if ' - ' in line]
    mounted = [r for r in rows if len(r[0].split()) >= 6 and r[0].split()[4] == '/tmp']
    need(len(mounted) == 1 and mounted[0][1].split()[0] == 'tmpfs')
    vfs = os.statvfs(tmp); need(vfs.f_blocks * vfs.f_frsize <= 64 * 1024 * 1024)
    scratch = tmp / 'amz-yacht-runtime'; scratch.mkdir(mode=0o700)
    for name in ('config', 'cache', 'output'): (scratch / name).mkdir(mode=0o700)
    return scratch


def captured_module(name, raw, expected):
    need(type(raw) is bytes and 0 < len(raw) <= 262144 and hashlib.sha256(raw).hexdigest() == expected)
    module = types.ModuleType(name)
    module.__file__ = '<verified-publication:' + expected + '>'
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True, optimize=0), module.__dict__)
    return module


def validate_scope_binding(base, value, config, artifact):
    # The pin comes from protected configuration, never from hashing an
    # unadmitted scope into a newly trusted configuration or from a room DTO.
    need(type(value) is dict and value.get('identity') == config['identity'] and
         value.get('runtimeArtifactSha256') == config['runtimeArtifactSha256'] and
         value.get('runtimeProfileSha256') == PROFILE_SHA and
         value.get('runtimeSourceCommit') == artifact['sourceCommit'] and
         value.get('publisherSourceSha256') == 'f7cf95840762e7e28194b5a589014ceb88fbe95cde05b6b1737aadc8f0be2ce2')
    # Exact scope schema, Linux UID/device/inode/lock and current deadlines are
    # independently enforced by the captured publication/composition kernel.


def install_control_guards(composition, sources, guard):
    """Fixed actual components only. No lock over engine callbacks or await.

    The older components contain direct scans outside NativeFiles methods.
    Cover these sync spans without wrapping effects.process(), whose genuine
    handlers must execute without the publication flock.
    """
    state = composition._sources(sources)
    need(composition._state(guard)['sources'] is sources)
    modules, owner = state['modules'], guard.files
    effects, observations = modules['native_yacht_effects'], modules['native_yacht_observations']
    original_pending, original_write, original_initialize = effects._no_pending, effects._write, effects.initialize_effects
    def no_pending(actual):
        need(actual is owner)
        with guard.transaction(): return original_pending(actual)
    def write(actual, name, value, maximum):
        need(actual is owner)
        with guard.transaction(): return original_write(actual, name, value, maximum)
    def initialize(actual, run, roster, scope):
        need(actual is owner)
        with guard.transaction(): return original_initialize(actual, run, roster, scope)
    def poll_once(control):
        need(type(control) is observations.YachtObservationControl and control.owner is owner)
        control._check()  # Native ABI/state work is outside the publication lock.
        with guard.transaction():
            with os.scandir(owner._directory) as entries:
                for count, entry in enumerate(entries):
                    observations.require(count < 1024 and not entry.name.startswith('.' + observations.ACK + '.pending-'),
                                         'yacht_observation_reconciliation_required')
            command = owner._read(observations.CONTROL, observations.MESSAGE_LIMIT, optional=True)
        if command is not None and control.last and observations.sha(observations.canonical(command[0])) == control.last['requestSha256']:
            return False
        return None if command is None else control.process(command[0])
    effects._no_pending, effects._write = no_pending, write
    effects.initialize_effects = initialize
    observations.YachtObservationControl.poll_once = poll_once


def bind_native(base, module, config, hints, barrier, hooks_module, checkpoint_factory, guard):
    """Historical binding, with the fixed save precheck in one sync transaction.

    Snapshot serialization/engine get_save(), native handlers and async drain
    run AFTER leaving the publication lock. The actual composed save writer
    independently guards its complete budget/old-read/write/readback span.
    """
    state = {'context': None, 'hooks': None, 'snapshots': None}
    hooks = hooks_module.PublicHooks(barrier, module.process_client_cmd, module.on_client_joined, module.on_client_disconnected)
    module.process_client_cmd, module.on_client_joined, module.on_client_disconnected = (
        hooks.process_client_cmd, hooks.on_client_joined, hooks.on_client_disconnected)
    def world_data(context):
        base.need(hints['engineCommit'] == base.ENGINE_COMMIT and hints['worldPackSha256'] == base.ENGINE_SHA and
                  set(context.played_games) <= {'Archipelago', 'Yacht Dice'} and hints['defaultBlacklist'] == [], 'public_game_not_admitted')
        for game in context.played_games:
            context.non_hintable_names[game] = frozenset(hints['overrides'].get(game, []))
    def initialize_save(context, enabled=True):
        with guard.transaction():
            base.need(enabled and not base.SAVE.exists() and not base.SAVE.is_symlink(), 'public_existing_run_requires_migration')
        base.need(context.host == '0.0.0.0' and context.port == config['port'], 'public_listener_binding_rejected')
        base.need(1 <= len(context.connect_names) <= 16 and set(context.games.values()) == {'Yacht Dice'}, 'public_game_not_admitted')
        base.need(all(type(name) is str and base.re.fullmatch(r'[A-Za-z0-9_-]{1,16}', name) and
                      type(pair) is tuple and len(pair) == 2 and pair[0] == 0 and base.integer(pair[1], 1, 16)
                      for name, pair in context.connect_names.items()), 'public_slot_binding_rejected')
        context.save_filename, context.saving = str(base.SAVE), True
        context.password, context.server_password, context.item_cheat, context.log_network = config['password'], '', False, False
        hooks.bind_context(context)
        state['context'], state['hooks'] = context, hooks
        state['snapshots'] = checkpoint_factory(context)
        context._start_async_saving()
        base.need(context.save(True), 'public_initial_save_failed')
    def serialized_save(context, exit_save=False):
        base.need(state['context'] is context and state['snapshots'] is not None, 'public_checkpoint_composition_required')
        return state['snapshots'].save_now()
    def loop_saving(context, atexit_save=True):
        base.need(state['context'] is context and state['snapshots'] is not None and context.auto_saver_thread is None,
                  'public_native_save_thread_forbidden')
    module.Context._load_world_data, module.Context.init_save = world_data, initialize_save
    module.Context._save, module.Context._start_async_saving = serialized_save, loop_saving
    return state


def verify_inputs(base):
    global STAGE
    need(sys.platform == 'linux' and sys.version_info[:2] == (3, 12) and os.getuid() == 65532 and Path('/.dockerenv').is_file())
    STAGE = 'protected_inputs'
    base.checked_directory(PRIVATE, private=True)
    need(os.statvfs(Path('/')).f_flag & os.ST_RDONLY and os.statvfs(ENGINE).f_flag & os.ST_RDONLY and os.statvfs(OWNED).f_flag & os.ST_RDONLY)
    # Dedicated fresh directory only. No lock, save, ACK, pending or foreign
    # artifact can be reclassified as a new empty run, even after known failure.
    need({entry.name for entry in PRIVATE.iterdir()} == {'public-runtime.json', 'public-seed.archipelago', 'public-yacht-keys.json',
         'public-publication-scope.json', 'public-control-publication.lock'})
    config_raw = base.read_fixed(PRIVATE / 'public-runtime.json', 16384, private=True)
    config = validate_configuration(base, base.strict_json(config_raw))
    raw = base.read_fixed(OWNED / 'public-yacht-publication-runtime.v1.json', 1048576)
    need(base.sha(raw) == config['runtimeArtifactSha256'])
    artifact = base.strict_json(raw)
    need(base.exact(artifact, ('schema', 'version', 'repository', 'sourceCommit', 'profileId', 'composition', 'imageRepository',
                               'executionProfileSha256', 'engine', 'ownedFiles', 'toolchain', 'sourceTransfer', 'sourceFoundation', 'qualification')) and
         artifact['schema'] == 'amz.ap.public-beta.yacht-publication-runtime.v1' and artifact['version'] == 1 and
         artifact['repository'] == 'Antimatter-Zone/DMS-Archipelago-Server' and type(artifact['sourceCommit']) is str and
         base.re.fullmatch('[a-f0-9]{40}', artifact['sourceCommit']) and artifact['profileId'] == PROFILE and
         artifact['composition'] == 'server-headless-public-yacht-publication-v1' and
         artifact['imageRepository'] == 'docker.darkmatterservers.com/dms-public-beta/ap-runtime-public-beta' and artifact['executionProfileSha256'] == PROFILE_SHA)
    legacy = {k: artifact[k] for k in ('version', 'repository', 'sourceCommit', 'imageRepository', 'engine', 'toolchain', 'sourceTransfer', 'qualification')}
    # Retain every historical engine/toolchain/false-qualification check; only
    # the new execution/inventory schema is separately enrolled here.
    legacy.update(schema='amz.ap.public-beta.server-runtime.v1', profileId='public-disposable-beta-v1', composition='server-headless-public-slot-gateway-v1',
                  ownedFiles=[r for r in artifact['ownedFiles'] if r['path'] in base.FILES])
    base.validate_artifact(base.canonical(legacy), base.sha(base.canonical(legacy)))
    rows = artifact['ownedFiles']; need(type(rows) is list and [r.get('path') for r in rows] == sorted(FILES))
    code = {}
    for row in rows:
        need(base.exact(row, ('path', 'sha256', 'bytes')) and base.SHA.fullmatch(row['sha256']) and base.integer(row['bytes'], 1, 262144))
        value = base.read_fixed(OWNED / row['path'], 262144); need(len(value) == row['bytes'] and base.sha(value) == row['sha256']); code[row['path']] = value
    need(base.sha(code['runtime-profile.json']) == PROFILE_SHA and base.sha(code['fresh_loader.py']) == FRESH_LOADER_SHA and
         base.sha(code['source-foundation.v1.json']) == FOUNDATION_SHA and artifact['sourceFoundation'] == base.strict_json(code['source-foundation.v1.json']))
    profile = base.strict_json(code['runtime-profile.json'])
    need(base.sha(code['yacht_packet_policy.py']) == profile['packetPolicy']['sha256'] and
         base.sha(code['native_yacht_effects.py']) == profile['modules']['effectsSha256'] and
         base.sha(code['native_yacht_observations.py']) == profile['modules']['observationSha256'])
    manifest_raw = base.read_fixed(OWNED / 'engine-manifest.json', 2097152); need(base.sha(manifest_raw) == base.ENGINE_SHA)
    manifest = base.strict_json(manifest_raw); need(len(manifest['files']) == 3539 and manifest['engineCommit'] == base.ENGINE_COMMIT)
    STAGE = 'engine_inventory'; base.verify_inventory(ENGINE, manifest)
    hints_raw = base.read_fixed(OWNED / 'world-hints.v1.json', 65536); need(base.sha(hints_raw) == base.HINTS_SHA)
    need(base.sha(code['native_budget.py']) == profile['nativeBudget']['sourceSha256'] and
         base.sha(code['native_composition.py']) == COMPOSITION_SHA and base.sha(code['yacht_actions_loader.py']) == ACTION_LOADER_SHA and
         base.sha(code['publication.py']) == profile['publication']['publisherSourceSha256'])
    seed = base.read_fixed(PRIVATE / 'public-seed.archipelago', 524288, private=True)
    need(base.sha(seed) == config['seedArtifactSha256'] and seed[0] == 3)
    key_raw = base.read_fixed(PRIVATE / 'public-yacht-keys.json', 4096, private=True)
    keys = validate_keys(base, base.strict_json(key_raw), config)
    scope_raw = base.read_fixed(PRIVATE / 'public-publication-scope.json', 16384, private=True)
    need(base.sha(scope_raw) == config['publicationScopeSha256'])
    validate_scope_binding(base, base.strict_json(scope_raw), config, artifact)
    return config, code, base.strict_json(hints_raw), seed, keys, key_raw, config_raw, scope_raw, artifact


def main():
    global STAGE
    base = foundation()
    config, code, hints, seed, keys, key_raw, config_raw, scope_raw, artifact = verify_inputs(base)
    # The exact closed namespace captures all nine bytes before execution.
    # No sys.modules re-import can introduce a second NativeFiles class.
    composition = captured_module('publication_composition', code['native_composition.py'], COMPOSITION_SHA)
    sources = composition.capture_native_sources({name: code[name + '.py'] for name in composition.SOURCE_PINS})
    modules = composition._sources(sources)['modules']  # Fixed verified private namespace only.
    barrier_module, checkpoint, hooks_module = (modules[name] for name in ('gateway_barrier', 'native_checkpoint', 'gateway_hooks'))
    effects, observations = modules['native_yacht_effects'], modules['native_yacht_observations']
    policy = captured_module('publication_packet_policy', code['yacht_packet_policy.py'],
                             'c6259c26b4cb7b23c7f2b2405f9198e2c13e98f235ba1f854891e1cd20fcd263')
    run, roster = effects.run_binding(config['run']), effects.roster_binding(config['roster'])
    need(run['seedArtifactSha256'] == config['seedArtifactSha256'] and all(run[k] == config['identity'][k] for k in
         ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')))
    publication = modules['publication']
    now = publication._wall()
    guard = composition.open_native_composition(sources, config['publicationScopeSha256'],
                                                composition._iso(now), composition._iso(now + 5000))
    files = guard.files
    barrier = None
    stop_redaction = lambda: None
    try:
        stop_redaction = hooks_module.install_log_redaction(config['password'])
        logging.disable(logging.CRITICAL)  # No native raw log/packet export.
        # Minimal bootstrap reads are not sufficient custody. Recheck ALL
        # private startup inputs and fresh-directory preconditions under the
        # same actual lock before the first journal is initialized.
        with guard.transaction():
            need({entry.name for entry in PRIVATE.iterdir()} == FRESH_FILES | {'public-gateway-native.lock'})
            need(base.read_fixed(PRIVATE / 'public-runtime.json', 16384, private=True) == config_raw and
                 base.read_fixed(PRIVATE / 'public-yacht-keys.json', 4096, private=True) == key_raw and
                 base.read_fixed(PRIVATE / 'public-seed.archipelago', 524288, private=True) == seed and
                 base.read_fixed(PRIVATE / 'public-publication-scope.json', 16384, private=True) == scope_raw)
            validate_scope_binding(base, base.strict_json(scope_raw), config, artifact)
            files.initialize(barrier_module.initial_state(config['identity']))
        install_control_guards(composition, sources, guard)
        barrier = barrier_module.NativeBarrier(config['identity'], config['password'], files.load_journal(), files.commit_journal)
        scratch = scratch_directory()
        os.environ.clear(); os.environ.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME=str(scratch), XDG_CONFIG_HOME=str(scratch / 'config'),
                                             XDG_CACHE_HOME=str(scratch / 'cache'), APPDATA=str(scratch), SKIP_REQUIREMENTS_UPDATE='1', PYTHONDONTWRITEBYTECODE='1')
        sys.path.insert(0, str(ENGINE))
        STAGE = 'engine_import'
        import Utils
        import settings
        base.initialize_core_settings(settings)
        for name, destination in (('user_path', scratch), ('home_path', scratch), ('cache_path', scratch / 'cache'), ('output_path', scratch / 'output')):
            getattr(Utils, name).cached_path = str(destination)
        import MultiServer
        import NetUtils
        native_source = base.read_fixed(ENGINE / 'MultiServer.py', 1048576).replace(b'\r\n', b'\n')
        net_source = base.read_fixed(ENGINE / 'NetUtils.py', 1048576).replace(b'\r\n', b'\n')
        packet_current = policy.install(MultiServer, NetUtils, native_source, net_source, effects._code_identity)
        def snapshot_factory(context):
            snapshots = checkpoint.NativeSnapshots(files, context)
            return snapshots
        state = bind_native(base, MultiServer, config, hints, barrier, hooks_module, snapshot_factory, guard)
        def load_seed(context, filename, use_embedded_server_options=False):
            need(filename == str(PRIVATE / 'public-seed.archipelago') and use_embedded_server_options is True)
            context._load(checkpoint.decode_native(seed[1:], MultiServer.restricted_loads), True); context.data_filename = filename
        MultiServer.Context.load = load_seed
        sys.argv = ['MultiServer.py', str(PRIVATE / 'public-seed.archipelago'), '--host', '0.0.0.0', '--port', str(config['port']),
                    '--savefile', str(PRIVATE / 'public-seed.apsave'), '--use_embedded_options', '--disable_item_cheat', '--auto_shutdown', '0', '--loglevel', 'warning']
        args = MultiServer.parse_args(); args.password, args.server_password, args.log_network, args.cert, args.cert_key = config['password'], '', False, None, None
        async def run_native():
            pump = observation_control = effects_control = None
            stopping = asyncio.Event(); remove_signals = base.install_stop_signals(asyncio.get_running_loop(), stopping.set)
            revision = 0
            async def observe():
                nonlocal pump, observation_control, effects_control, revision
                while True:
                    packet_current()
                    context = state['context']
                    if base.native_listener_ready(context, config['port']):
                        if pump is None:
                            try:
                                need(context.connect_names == {r['slotAlias']: (0, r['slot']) for r in roster} and context.seed_name == run['seedName'])
                                barrier.mark_ready()
                                effects.initialize_effects(files, run, roster, config['identity'])
                                effects_control = effects.YachtEffectsControl(files, barrier, effects.VerifiedYachtHandlers(MultiServer, native_source), context,
                                                                             run=run, roster=roster, independent_key=keys[1])
                                observation_control = observations.YachtObservationControl(files, barrier, observations.VerifiedYachtObservationABI(MultiServer, native_source), context,
                                    run=run, roster=roster, scope=config['identity'], build_id=config['browserBuildSha256'], seed_bytes=seed, independent_key=keys[0])
                                pump = hooks_module.ControlPump(files, barrier, state['hooks'])
                            except BaseException:
                                barrier.shutdown(); raise
                        # Single event-loop owner, no independent save/observer/effect threads.
                        await pump.poll_once(); packet_current()
                        data_ready = barrier.state['ready'] and not barrier.state['uncertain'] and not any(r['gate']['kind'] == 'idle' for r in barrier.state['gates'].values())
                        if data_ready:
                            effects_control.poll_once(); observation_control.poll_once()
                        # Old checkpoint_and_hold lacks the effects journal and
                        # is intentionally not enrolled in this fresh profile.
                        with guard.transaction():
                            need(files._entry('public-runtime-control.json') is None, 'yacht_restore_closed')
                        state['snapshots'].periodic()
                        actual = barrier._actual(); known = actual is not None and barrier.state['ready'] and not barrier.state['uncertain']
                        revision += 1
                        guard.publish_status({'schema': 'amz.ap.public-beta.yacht-native-status.v1', **config['identity'], 'state': ('ready' if data_ready else 'held') if known else 'unknown',
                            'runtimeArtifactSha256': config['runtimeArtifactSha256'], 'executionProfileSha256': PROFILE_SHA, 'seedArtifactSha256': config['seedArtifactSha256'],
                            'observationRevision': revision, 'connectedGameClients': len(actual) if known else None, 'connectionGeneration': barrier.state['generation'] if known else None,
                            'provenInitialReadyAt': barrier.state['initialReadyAt'], 'provenLastDisconnectAt': barrier.state['lastDisconnectAt'], 'observedAt': barrier_module.iso(barrier._now())})
                    await asyncio.sleep(0.25)
            native = asyncio.create_task(MultiServer.main(args)); monitor = asyncio.create_task(observe()); stop = asyncio.create_task(stopping.wait())
            try:
                done, _ = await asyncio.wait((native, monitor, stop), return_when=asyncio.FIRST_COMPLETED)
                if monitor in done: await monitor
                if stop not in done: await native
            finally:
                stop.cancel(); await asyncio.gather(stop, return_exceptions=True)
                try:
                    if observation_control: observation_control.close()
                    if effects_control: effects_control.close()
                    await base.drain_native(state, barrier, files, pump, monitor, native)
                finally: remove_signals()
        STAGE = 'native_loop'; asyncio.run(run_native())
    finally:
        try:
            if barrier is not None and barrier.state['ready']: barrier.shutdown()
        finally:
            try: guard.close()
            finally: stop_redaction()


if __name__ == '__main__':
    try: main()
    except BaseException:
        print(json.dumps({'schema': 'amz.ap.public-beta.yacht-publication-runtime-failure.v1', 'stage': STAGE, 'code': 'yacht_runtime_refused'}), file=sys.stderr)
        raise SystemExit(1)

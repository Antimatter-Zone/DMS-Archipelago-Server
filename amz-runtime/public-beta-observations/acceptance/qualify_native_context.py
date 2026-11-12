"""Private component acceptance inside the independently verified fresh79 image.

No listener or browser is started. Fixed inputs, captured source verification,
genuine native loading/item mutation and real NativeFiles are mandatory. This
entrypoint provides no fixture Context or missing-engine fallback.
"""
import asyncio
import ast
import base64
import contextlib
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import types

SCHEMA = 'amz.ap.public-beta.yacht-observation-native-acceptance.v1'
ROOT = Path('/home/container/.amz')
OWNED = Path('/opt/amz-ap-public')
ENGINE = Path('/engine')
CANDIDATE = ROOT / 'observation-candidate'
MANIFEST = ROOT / 'observation-acceptance-input.json'
RESULT = ROOT / 'observation-acceptance-result.json'
LOG = ROOT / 'observation-acceptance-private.log'
DESCRIPTION_INPUT = ROOT / 'observation-seed-description-input.json'
DESCRIPTION_RESULT = ROOT / 'observation-seed-description.json'
DESCRIPTION_LOG = ROOT / 'observation-seed-description-private.log'
SEED = ROOT / 'public-seed.archipelago'
IMAGE_ID = 'sha256:1b9104acd36cb98950aee35e08c12a70ea3efa78b6a55b90ebaaa1d76ce6fc03'
CANDIDATE_COMMIT = '471de022f3bdbce542507175b06bcd2196b635d5'
ARTIFACT_SHA = '7ad3410e15d73d73698e2edb3ff153899d7da2438cbc24e19717a09e0bb7414b'
LOADER_SHA = 'd5afd585c3b4571275b8dad4696d4d7e0d64665eee7650a7ef7a8eda6e46285d'
ENGINE_INVENTORY_SHA = 'ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f'
WORLD_PROFILE_SHA = 'cb3653610aa43b893508a9f014e6a420ca6aea73e344a0738ee6722806bd2a4a'
HINTS_SHA = '68e714887bfe7a867a74bc9a73d759f2b4c2e67a2e67dd0a784fa43b75dd01cc'
CANDIDATE_PINS = {
    'profile.v1.json': '5a8a1bc1e85be2d6531bc30e8ba13042ccfe68830e75136db25627e9da85902d',
    'native_yacht_observations.py': 'a6dbe041e2ac40fc78eeffc8f33ffff00366ff3a30e72a0b14a65a288f8a00d2',
    'native_yacht_effects.py': 'a6630c05b97c4971251a66c8108da732dc301587101b44782b75566b2631cdf2',
}
SHA = re.compile(r'^[a-f0-9]{64}$')
UUID = re.compile(r'^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
STAGE = 'preflight'
DIAGNOSTIC_SOURCES = {}
DIAGNOSTIC_EXCEPTION_TYPES = frozenset(('AssertionError', 'AttributeError', 'BarrierError', 'FileExistsError',
    'FileNotFoundError', 'ImportError', 'IndexError', 'KeyError', 'MemoryError', 'ModuleNotFoundError',
    'NativeFilesError', 'OSError', 'OverflowError', 'PermissionError', 'RecursionError', 'Refused',
    'RuntimeError', 'SyntaxError', 'TypeError', 'UnicodeDecodeError', 'ValueError'))
PRODUCT_QUALIFICATION = {'cpRosterAuthority': False, 'currentWebsiteAuthorization': False,
                         'browserGameplay': False, 'imageQualified': False, 'productionAdmitted': False}


class Refused(RuntimeError): pass


def need(ok, code):
    if not ok: raise Refused(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def exact(value, keys): return type(value) is dict and set(value) == set(keys)


def strict_json(raw):
    def pairs(values):
        out = {}
        for key, value in values:
            need(key not in out, 'input_duplicate_key'); out[key] = value
        return out
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('input_nonfinite')))


def register_diagnostic_source(filename, raw, label):
    """Only captured/verified code metadata; never exception values or text."""
    need(type(raw) is bytes and 0 < len(raw) <= 1048576 and type(label) is str and
         re.fullmatch(r'(?:acceptance|foundation|candidate|engine)/[A-Za-z0-9_./-]{1,128}', label) and
         all(part not in ('', '.', '..') for part in label.split('/')), 'diagnostic_source')
    tree = ast.parse(raw, filename=str(filename))
    names = {'<module>'}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Lambda): names.add('<lambda>')
        elif isinstance(node, ast.GeneratorExp): names.add('<genexpr>')
        elif isinstance(node, ast.ListComp): names.add('<listcomp>')
        elif isinstance(node, ast.SetComp): names.add('<setcomp>')
        elif isinstance(node, ast.DictComp): names.add('<dictcomp>')
    record = (label, frozenset(names), len(raw.splitlines()), sha(raw))
    need(str(filename) not in DIAGNOSTIC_SOURCES or DIAGNOSTIC_SOURCES[str(filename)] == record, 'diagnostic_source_changed')
    DIAGNOSTIC_SOURCES[str(filename)] = record


def safe_exception_diagnostic(error):
    """Bounded metadata only. No formatting/access of exception data or locals."""
    name = type(error).__name__
    result = {'exceptionType': name if name in DIAGNOSTIC_EXCEPTION_TYPES else 'UnclassifiedException', 'frames': []}
    trace, count = error.__traceback__, 0
    while trace is not None and count < 256:
        count += 1
        code = trace.tb_frame.f_code
        source = DIAGNOSTIC_SOURCES.get(code.co_filename)
        if source is not None:
            label, names, lines, _ = source
            if code.co_name in names and 1 <= trace.tb_lineno <= lines:
                result['frames'].append({'file': label, 'function': code.co_name, 'line': trace.tb_lineno})
                result['frames'] = result['frames'][-16:]
        trace = trace.tb_next
    return result


def read_fixed(file, maximum, *, private=False, empty=False):
    for parent in (file.parent, *file.parent.parents):
        entry = parent.lstat()
        need(stat.S_ISDIR(entry.st_mode) and not stat.S_ISLNK(entry.st_mode) and parent.resolve() == parent,
             'input_path')
    if private:
        folder = file.parent.stat()
        need(folder.st_uid == os.getuid() and stat.S_IMODE(folder.st_mode) == 0o700, 'input_private_directory')
    before = file.lstat()
    need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_nlink == 1 and
         (0 <= before.st_size <= maximum if empty else 0 < before.st_size <= maximum), 'input_file')
    if private: need(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600, 'input_private_file')
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd); raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part: break
            raw.extend(part)
        after, named = os.fstat(fd), file.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(opened) == identity(after) == identity(named) and len(raw) == before.st_size,
             'input_changed')
        return bytes(raw)
    finally: os.close(fd)


def write_new(file, value):
    raw = canonical(value)
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view); need(count > 0, 'evidence_write'); view = view[count:]
        os.fsync(fd)
    finally: os.close(fd)
    directory = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)
    need(read_fixed(file, len(raw), private=True) == raw, 'evidence_readback')


def validate_manifest(value):
    need(exact(value, ('schema', 'candidateSourceCommit', 'foundationImageId', 'run', 'roster', 'identity', 'browserBuildSha256')) and
         value['schema'] == SCHEMA and value['candidateSourceCommit'] == CANDIDATE_COMMIT and
         value['foundationImageId'] == IMAGE_ID and type(value['browserBuildSha256']) is str and SHA.fullmatch(value['browserBuildSha256']),
         'manifest')
    need(type(value['run']) is dict and type(value['identity']) is dict and type(value['roster']) is list and
         len(value['roster']) == 2 and type(value['run'].get('seedArtifactSha256')) is str and
         SHA.fullmatch(value['run']['seedArtifactSha256']), 'manifest')
    return copy.deepcopy(value)


def validate_description_manifest(value):
    need(exact(value, ('schema', 'candidateSourceCommit', 'foundationImageId', 'seedSha256')) and
         value['schema'] == 'amz.ap.public-beta.yacht-observation-seed-description-input.v1' and
         value['candidateSourceCommit'] == CANDIDATE_COMMIT and value['foundationImageId'] == IMAGE_ID and
         type(value['seedSha256']) is str and SHA.fullmatch(value['seedSha256']), 'description_manifest')
    return copy.deepcopy(value)


def load_module(name, raw, filename):
    need(name not in sys.modules, 'module_already_loaded')
    module = types.ModuleType(name); module.__file__ = str(filename)
    sys.modules[name] = module
    exec(compile(raw, str(filename), 'exec', dont_inherit=True, optimize=0), module.__dict__)
    return module


def capture_inputs(*, describe=False):
    global STAGE
    need(sys.platform == 'linux' and os.getuid() == 65532 and sys.version_info[:2] == (3, 12) and
         Path('/.dockerenv').is_file() and sys.flags.isolated == 1 and sys.dont_write_bytecode,
         'isolated_exact_native_image_required')
    need(os.environ.get('AMZ_NATIVE_OBSERVATION_ACCEPTANCE') == 'private-owned-genuine-context-only', 'explicit_acceptance_required')
    register_diagnostic_source(__file__, read_fixed(Path(__file__), 262144, private=True), 'acceptance/qualify_native_context.py')
    need(os.statvfs(ENGINE).f_flag & os.ST_RDONLY and os.statvfs(OWNED).f_flag & os.ST_RDONLY, 'readonly_sources_required')
    for name in ('public-gateway-native.lock', 'public-gateway-journal.json', 'public-runtime.json', 'public-runtime-status.json',
                 'public-seed.apsave', 'public-yacht-observation-control.json', 'public-yacht-observation-ack.json', RESULT.name, LOG.name):
        file = ROOT / name; need(not file.exists() and not file.is_symlink(), 'existing_run_requires_reconciliation')
    if describe:
        need(not DESCRIPTION_RESULT.exists() and not DESCRIPTION_RESULT.is_symlink() and
             not DESCRIPTION_LOG.exists() and not DESCRIPTION_LOG.is_symlink(), 'existing_description_requires_reconciliation')
        manifest = validate_description_manifest(strict_json(read_fixed(DESCRIPTION_INPUT, 4096, private=True)))
    else:
        manifest = validate_manifest(strict_json(read_fixed(MANIFEST, 16384, private=True)))
    seed = read_fixed(SEED, 16777216, private=True)
    need(sha(seed) == (manifest['seedSha256'] if describe else manifest['run']['seedArtifactSha256']), 'seed_pin')
    loader_raw = read_fixed(OWNED / 'loader.py', 262144)
    need(sha(loader_raw) == LOADER_SHA, 'loader_pin')
    register_diagnostic_source(OWNED / 'loader.py', loader_raw, 'foundation/loader.py')
    # This verified source module imports only the standard library and starts
    # nothing. Engine imports happen only after the full verification below.
    loader = load_module('observation_acceptance_loader', loader_raw, OWNED / 'loader.py')
    artifact_raw = read_fixed(OWNED / 'public-server-runtime.v1.json', 1048576)
    artifact = loader.validate_artifact(artifact_raw, ARTIFACT_SHA)
    code = {}
    for row in artifact['ownedFiles']:
        raw = read_fixed(OWNED / row['path'], 262144)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'foundation_source_pin'); code[row['path']] = raw
        if row['path'].endswith('.py'):
            register_diagnostic_source(OWNED / row['path'], raw, 'foundation/' + row['path'])
    inventory_raw = read_fixed(OWNED / 'engine-manifest.json', 2097152)
    need(sha(inventory_raw) == ENGINE_INVENTORY_SHA, 'engine_inventory_pin')
    inventory = strict_json(inventory_raw)
    need(inventory['engineCommit'] == '54803be064fc7e80c4628777ed0b46a9390f255f' and len(inventory['files']) == 3539, 'engine_inventory')
    STAGE = 'full_engine_verification'; loader.verify_inventory(ENGINE, inventory)
    for name in ('MultiServer.py', 'NetUtils.py', 'Utils.py', 'apmw/multiserver/gamespackagecache.py'):
        raw = read_fixed(ENGINE / name, 1048576)
        row, = (row for row in inventory['files'] if row['path'] == name)
        checked = raw.replace(b'\r\n', b'\n') if row['algorithm'] == 'sha256-lf' else raw
        need(sha(checked) == row['sha256'], 'diagnostic_engine_source_pin')
        register_diagnostic_source(ENGINE / name, raw, 'engine/' + name)
    hints_raw = read_fixed(OWNED / 'world-hints.v1.json', 65536)
    need(sha(hints_raw) == HINTS_SHA, 'hints_pin')
    candidate = {}
    for name, pin in CANDIDATE_PINS.items():
        raw = read_fixed(CANDIDATE / name, 262144, private=True)
        need(sha(raw) == pin, 'candidate_source_pin'); candidate[name] = raw
        if name.endswith('.py'):
            register_diagnostic_source(CANDIDATE / name, raw, 'candidate/' + name)
    profile = strict_json(candidate['profile.v1.json'])
    need(profile['sourceOnly'] is True and all(enabled is False for enabled in profile['qualification'].values()), 'candidate_not_release')
    for row in profile['foundationFiles']:
        name = Path(row['path']).name
        need(sha(candidate[name] if name in candidate else code[name]) == row['sha256'], 'candidate_foundation_pin')
    native_source = read_fixed(ENGINE / 'MultiServer.py', 1048576).replace(b'\r\n', b'\n')
    net_source = read_fixed(ENGINE / 'NetUtils.py', 1048576).replace(b'\r\n', b'\n')
    need(sha(native_source) == profile['multiServerLfSha256'] and sha(net_source) == profile['netUtilsLfSha256'], 'native_abi_source_pin')
    return manifest, seed, loader, code, strict_json(hints_raw), candidate, native_source


def import_engine(loader):
    global STAGE
    os.environ.clear()
    os.environ.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME=str(ROOT), XDG_CONFIG_HOME=str(ROOT / 'config'),
                      XDG_CACHE_HOME=str(ROOT / 'cache'), APPDATA=str(ROOT), SKIP_REQUIREMENTS_UPDATE='1', PYTHONDONTWRITEBYTECODE='1')
    sys.path.insert(0, str(ENGINE))
    STAGE = 'verified_engine_import'
    import Utils
    import settings
    loader.initialize_core_settings(settings)
    for name, destination in (('user_path', ROOT), ('home_path', ROOT), ('cache_path', ROOT / 'cache'), ('output_path', ROOT / 'output')):
        getattr(Utils, name).cached_path = str(destination)
    import MultiServer
    return MultiServer


def describe_seed(captured):
    """Actual native decode after all captured inputs pass. Metadata only."""
    manifest, seed, loader, code, _, candidate, native_source = captured
    load_module('gateway_barrier', code['gateway_barrier.py'], OWNED / 'gateway_barrier.py')
    load_module('native_files', code['native_files.py'], OWNED / 'native_files.py')
    load_module('native_yacht_effects', candidate['native_yacht_effects.py'], CANDIDATE / 'native_yacht_effects.py')
    producer = load_module('native_yacht_observations', candidate['native_yacht_observations.py'], CANDIDATE / 'native_yacht_observations.py')
    native = import_engine(loader)
    producer.VerifiedYachtObservationABI(native, native_source)
    decoded = native.Context.decompress(seed)
    need(type(decoded) is dict and type(decoded.get('seed_name')) is str and 0 < len(decoded['seed_name']) <= 256 and
         all(ord(char) >= 32 and ord(char) != 127 for char in decoded['seed_name']) and
         type(decoded.get('slot_info')) is dict and len(decoded['slot_info']) == 2 and type(decoded.get('connect_names')) is dict,
         'description_seed_metadata')
    slots = []
    for slot, info in sorted(decoded['slot_info'].items()):
        need(type(slot) is int and 1 <= slot <= 16 and type(info) is native.NetworkSlot and
             type(info.name) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,16}', info.name) and
             info.game == 'Yacht Dice' and info.type is native.SlotType.player and not info.group_members,
             'description_seed_metadata')
        slots.append({'slotAlias': info.name, 'team': 0, 'slot': slot})
    need(decoded['connect_names'] == {row['slotAlias']: (0, row['slot']) for row in slots}, 'description_seed_metadata')
    return {'schema': 'amz.ap.public-beta.yacht-observation-seed-description.v1', 'state': 'described',
            'candidateSourceCommit': manifest['candidateSourceCommit'], 'seedSha256': sha(seed), 'seedBytes': len(seed),
            'seedName': decoded['seed_name'], 'slots': slots, 'engineCommit': '54803be064fc7e80c4628777ed0b46a9390f255f',
            'engineInventorySha256': ENGINE_INVENTORY_SHA, 'qualification': False, 'listenerStarted': False,
            'nativeContextConstructed': False, 'seedMetadataOnly': True, 'nativeContextOnly': False,
            'gameplay': False, 'productionDeployed': False, **PRODUCT_QUALIFICATION}


def expect_refused(action, error_type, code):
    try: action()
    except error_type as error:
        need(code in str(error), 'wrong_negative_result'); return True
    raise Refused('negative_case_was_admitted')


async def exercise(captured):
    global STAGE
    manifest, seed, loader, code, hints, candidate, native_source = captured
    barrier_module = load_module('gateway_barrier', code['gateway_barrier.py'], OWNED / 'gateway_barrier.py')
    hooks_module = load_module('gateway_hooks', code['gateway_hooks.py'], OWNED / 'gateway_hooks.py')
    files_module = load_module('native_files', code['native_files.py'], OWNED / 'native_files.py')
    load_module('checkpoint_custody', code['checkpoint_custody.py'], OWNED / 'checkpoint_custody.py')
    checkpoint = load_module('native_checkpoint', code['native_checkpoint.py'], OWNED / 'native_checkpoint.py')
    load_module('native_yacht_effects', candidate['native_yacht_effects.py'], CANDIDATE / 'native_yacht_effects.py')
    producer = load_module('native_yacht_observations', candidate['native_yacht_observations.py'], CANDIDATE / 'native_yacht_observations.py')
    scope, run, roster = barrier_module.identity(manifest['identity']), producer.run_binding(manifest['run']), producer.roster_binding(manifest['roster'])
    need(all(run[k] == scope[k] for k in ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')), 'run_identity')
    master, observation_key = secrets.token_urlsafe(48), secrets.token_bytes(32)
    configuration = loader.validate_configuration({'schema': 'amz.ap.public-beta.native-configuration.v1', 'profileId': 'public-disposable-beta-v1',
        'identity': scope, 'runtimeArtifactSha256': ARTIFACT_SHA, 'worldPackSha256': WORLD_PROFILE_SHA,
        'engineCommit': '54803be064fc7e80c4628777ed0b46a9390f255f', 'engineInventorySha256': ENGINE_INVENTORY_SHA,
        'seedArtifactSha256': run['seedArtifactSha256'], 'password': master, 'port': 7105,
        'journalMode': 'initialize', 'requiredCheckpointSha256': None})
    stop_redaction = hooks_module.install_log_redaction(master)
    owner = files_module.NativeFiles(); barrier = control = context = None
    try:
        owner.initialize(barrier_module.initial_state(scope))
        barrier = barrier_module.NativeBarrier(scope, master, owner.load_journal(), owner.commit_journal)
        MultiServer = import_engine(loader)
        # Use the already reviewed headless composition without calling main,
        # starting a listener, accepting a client or running command packets.
        state = loader.bind_native(MultiServer, configuration, hints, barrier, hooks_module,
                                   lambda ctx: checkpoint.NativeSnapshots(owner, ctx))
        STAGE = 'native_context_construct'
        context = MultiServer.Context('0.0.0.0', configuration['port'], '', master, 1, 10, False,
                                      release_mode='disabled', collect_mode='disabled', remaining_mode='disabled', log_network=False)
        STAGE = 'native_context_load'
        context.load(str(SEED), use_embedded_server_options=False)
        STAGE = 'native_context_init_save'
        context.init_save(True)
        STAGE = 'native_context_empty_checks'
        need(state['context'] is context and context.server is None and context.endpoints == [] and context.auto_saver_thread is None,
             'unintended_native_listener_or_thread')
        STAGE = 'native_barrier_initial_ready'
        barrier.mark_ready()  # Proven empty genuine Context, not serving-runtime qualification.
        STAGE = 'native_observation_abi'
        abi = producer.VerifiedYachtObservationABI(MultiServer, native_source)
        def new_control(**changes):
            options = dict(run=run, roster=roster, scope=scope, build_id=manifest['browserBuildSha256'], seed_bytes=seed,
                           independent_key=observation_key)
            options.update(changes)
            return producer.YachtObservationControl(owner, barrier, abi, context, **options)
        STAGE = 'native_observation_construct'
        control = new_control()
        STAGE = 'native_observation_initial_snapshots'
        before = {row['slot']: control.snapshot(row['actorUuid']) for row in roster}
        need(all(value['itemStream']['startInventoryCount'] >= 1 for value in before.values()), 'real_start_inventory_required')
        need(all(value['locationIds'] == sorted(context.locations[value['binding']['slot']]) and
                 producer.BASE + value['slotData']['goal_score'] not in value['locationIds'] for value in before.values()), 'sparse_network_locations')
        negatives = {}
        negatives['wrongSeedBytes'] = expect_refused(lambda: new_control(seed_bytes=seed + b'\0'), barrier_module.BarrierError, 'seed')
        wrong_run = dict(run, seedName=run['seedName'] + '_foreign')
        negatives['wrongSeedName'] = expect_refused(lambda: new_control(run=wrong_run), barrier_module.BarrierError, 'seed_roster')
        wrong_scope = dict(scope, runtimeLaunchId='00000000-0000-4000-8000-000000000099')
        need(wrong_scope != scope, 'negative_launch_collision')
        negatives['staleLaunch'] = expect_refused(lambda: new_control(scope=wrong_scope), barrier_module.BarrierError, 'native_not_ready')
        players = {row['slot']: row for row in roster}
        transfers, self_check = [], None
        STAGE = 'genuine_native_item_transfer'
        for source in sorted(players):
            choices = [(location, item, target, flags) for location, (item, target, flags) in context.locations[source].items()
                       if target in players and target != source and location not in context.location_checks[0, source]]
            need(choices, 'real_cross_slot_location_required')
            location, item, target, flags = sorted(choices)[0]
            prior = control.snapshot(players[target]['actorUuid'])
            MultiServer.register_location_checks(context, 0, source, [location])
            await asyncio.sleep(0)
            current = control.snapshot(players[target]['actorUuid'])
            old = prior['itemStream']['networkItems']; new = current['itemStream']['networkItems']
            need(new[:len(old)] == old and len(new) == len(old) + 1 and
                 new[-1] == {'item': item, 'location': location, 'player': source, 'flags': flags} and
                 location in context.location_checks[0, source], 'genuine_item_tail')
            transfers.append({'source': source, 'target': target, 'location': location, 'prefixPreserved': True,
                              'beforeItems': len(old), 'afterItems': len(new), 'descriptorSha256': sha(canonical(current))})
        for source in sorted(players):
            choices = [(location, item, target, flags) for location, (item, target, flags) in context.locations[source].items()
                       if target == source and location not in context.location_checks[0, source]]
            if choices:
                location, item, target, flags = sorted(choices)[0]
                prior = control.snapshot(players[target]['actorUuid']); remote_false = copy.deepcopy(context.received_items.get((0, target, False), []))
                MultiServer.register_location_checks(context, 0, source, [location]); await asyncio.sleep(0)
                current = control.snapshot(players[target]['actorUuid'])
                need(len(current['itemStream']['networkItems']) == len(prior['itemStream']['networkItems']) + 1 and
                     current['itemStream']['networkItems'][-1] == {'item': item, 'location': location, 'player': source, 'flags': flags} and
                     context.received_items.get((0, target, False), []) == remote_false, 'remote_true_semantics')
                self_check = {'slot': source, 'location': location, 'remoteFalseUnchanged': True, 'remoteTrueTailObserved': True}; break
        need(self_check is not None, 'real_self_item_location_required')
        STAGE = 'private_authenticated_observation'
        stamp = int(time.time() * 1000)
        request = {'schema': producer.CONTROL_SCHEMA, 'requestId': '00000000-0000-4000-8000-000000000100', 'identity': scope,
                   'actorUuid': roster[0]['actorUuid'], 'issuedAt': barrier_module.iso(stamp), 'expiresAt': barrier_module.iso(stamp + 5000)}
        request['requestMac'] = hmac.digest(observation_key, producer.CONTROL_SCHEMA.encode() + b'\n' + canonical(request), 'sha256').hex()
        write_new(ROOT / producer.CONTROL, request)
        ack = control.poll_once()
        unsigned = {key: value for key, value in ack.items() if key != 'responseMac'}
        need(hmac.compare_digest(ack['responseMac'], hmac.digest(observation_key, producer.ACK_SCHEMA.encode() + b'\n' + canonical(unsigned), 'sha256').hex()) and
             ack['descriptorSha256'] == sha(canonical(ack['descriptor'])) and not control.poll_once(), 'authenticated_observation')
        need(context.server is None and context.endpoints == [] and not any(context.clients[0].values()), 'unexpected_client_or_listener')
        await asyncio.sleep(0)
        pending = asyncio.all_tasks() - {asyncio.current_task()}
        if pending: await asyncio.wait_for(asyncio.gather(*pending), timeout=5)
        receipt = {'schema': SCHEMA, 'classification': 'private-component-acceptance', 'state': 'passed',
            'nativeContextOnly': True, **PRODUCT_QUALIFICATION,
            'bindingIdentities': 'synthetic-private-acceptance-only',
            'browserBuildEvidence': 'hash-binding-only-browser-not-exercised',
            'candidateSourceCommit': CANDIDATE_COMMIT, 'candidateProfileSha256': CANDIDATE_PINS['profile.v1.json'],
            'candidateModuleSha256': CANDIDATE_PINS['native_yacht_observations.py'], 'helperSha256': sha(Path(__file__).read_bytes()),
            'engineCommit': '54803be064fc7e80c4628777ed0b46a9390f255f', 'engineInventorySha256': ENGINE_INVENTORY_SHA,
            'foundationImageIdExpectedFromSupervisor': IMAGE_ID, 'foundationArtifactSha256': ARTIFACT_SHA,
            'seedArtifactSha256': sha(seed), 'players': 2, 'genuineMultiServerContext': True, 'genuineNativeSeedLoad': True,
            'startInventoryObserved': True, 'sparseNetworkLocationMaps': True, 'crossSlotTransfers': transfers,
            'selfItemHandling': self_check, 'privateMacAckVerified': True, 'negativeCases': negatives,
            'nativeSaveWritten': True, 'listenerStarted': False, 'nativeClientsConnected': 0,
            'notQualified': ['serving-runtime-readiness', 'new-runtime-image', 'website-or-browser-gameplay', 'game-completion',
                             'current-slot-authority', 'restart-custody-migration', 'save-resume', 'DMS-provider', 'public-cutover', 'durable-recovery']}
        return receipt, (master.encode(), observation_key.hex().encode(), base64.b64encode(observation_key))
    finally:
        if control is not None: control.close()
        try:
            if barrier is not None: barrier.shutdown()
        finally:
            try:
                if context is not None: context.exit_event.set()
                owner.close()
            finally: stop_redaction()


def main():
    global STAGE
    need(sys.argv[1:] in ([], ['--describe-seed']), 'arguments_not_accepted')
    describe = sys.argv[1:] == ['--describe-seed']
    captured = capture_inputs(describe=describe)
    blocked = []
    def no_external_io(event, args):
        if event in ('socket.bind', 'socket.connect', 'subprocess.Popen'):
            blocked.append(event); raise Refused('network_or_child_process_forbidden')
    sys.addaudithook(no_external_io)
    log_path, result_path = (DESCRIPTION_LOG, DESCRIPTION_RESULT) if describe else (LOG, RESULT)
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        if describe:
            receipt, secret_needles = describe_seed(captured), ()
        else:
            receipt, secret_needles = asyncio.run(exercise(captured))
        log.flush(); os.fsync(log.fileno())
    need(not blocked, 'unexpected_external_io_attempt')
    private_log = read_fixed(log_path, 1048576, private=True, empty=True)
    need(all(needle not in private_log for needle in secret_needles), 'secret_log_redaction')
    receipt.update(secretsAbsentFromLogs=True, networkAndChildProcessesForbidden=True,
                   privateLogSha256=sha(private_log), observedAt=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    if not describe: receipt['nativeOwnerClosed'] = True
    STAGE = 'receipt_readback'; write_new(result_path, receipt)
    if describe:
        print(json.dumps(receipt)); return
    print(json.dumps({'schema': SCHEMA, 'state': 'passed', 'receiptSha256': sha(canonical(receipt)),
                      'genuineNativeContext': True, 'listeners': 0, 'gameplay': False, 'productionDeployed': False}))


if __name__ == '__main__':
    try: main()
    except BaseException as error:
        print(json.dumps({'schema': SCHEMA, 'state': 'failed', 'stage': STAGE, 'code': 'native_observation_acceptance_refused',
                          'diagnostic': safe_exception_diagnostic(error)}), file=sys.stderr)
        raise SystemExit(1)

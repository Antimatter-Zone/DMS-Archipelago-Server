"""Fixed Public-only runtime composition. No engine import or timer on import.

The protected operator must independently admit the versioned artifact and
write the exact private configuration. This source is not that authorization.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types
import uuid

ENGINE = Path('/engine')
OWNED = Path('/opt/amz-ap-public')
PRIVATE = Path('/home/container/.amz')
CONFIG = PRIVATE / 'public-runtime.json'
SEED = PRIVATE / 'public-seed.archipelago'
SAVE = PRIVATE / 'public-seed.apsave'
STATUS = PRIVATE / 'public-runtime-status.json'
ENGINE_COMMIT = '54803be064fc7e80c4628777ed0b46a9390f255f'
ENGINE_SHA = 'ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f'
HINTS_SHA = '68e714887bfe7a867a74bc9a73d759f2b4c2e67a2e67dd0a784fa43b75dd01cc'
PROFILE_SHA = 'b551c4f467b1c4d0e80dd6f0e2874050fee794343f38fe2e3a2bc8c8712965e9'
WORLD_PACK_SHA = 'cb3653610aa43b893508a9f014e6a420ca6aea73e344a0738ee6722806bd2a4a'
RESTORE_PROFILE_SHA = 'e573463a5f570e607c0d14289a2e47e5f1715b9c7960d61546ddd147accdb414'
FOUNDATION_CANONICAL_SHA = '72b31594894b6e0d2ef0306adab965ff6e9c4fd4ec515149dc6767f356cd0a50'
ARCHIVE_SHA = '3b9c408cd43b09ab27691d5a0b8d18686cd113ebdd06fdd9606c229010648ef8'
STAGE = 'guard'
FILES = ('gateway_barrier.py', 'gateway_hooks.py', 'native_files.py', 'checkpoint_custody.py', 'native_checkpoint.py', 'loader.py', 'launcher.mjs',
         'native_restore.py', 'native-restore-profile.v1.json', 'fresh-runtime-profile.json',
         'portal-source-manifest.json', 'runtime-profile.json', 'source-transfer.v1.json')
UUID = re.compile(r'^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
SHA = re.compile(r'^[a-f0-9]{64}$')
IDENTITY = ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'externalId',
            'allocationRevision', 'serverId', 'attemptId', 'seedRevision', 'credentialEpoch', 'runtimeLaunchId')


class Refused(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def integer(value, low=0, high=9007199254740991):
    return type(value) is int and low <= value <= high


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'public_json_rejected')
            out[key] = value
        return out
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused('public_json_rejected')))
        need(type(value) is dict, 'public_json_rejected')
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise Refused('public_json_rejected') from None


def checked_directory(directory, private=False):
    need(directory.is_absolute(), 'public_path_rejected')
    for current in (directory, *directory.parents):
        info = current.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'public_path_rejected')
    need(directory.resolve() == directory, 'public_path_rejected')
    info = directory.stat()
    if private:
        need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'public_private_directory_rejected')


def read_fixed(file, maximum, private=False, allow_empty=False):
    checked_directory(file.parent, private=private)
    entry = file.lstat()
    need(stat.S_ISREG(entry.st_mode) and not stat.S_ISLNK(entry.st_mode) and entry.st_nlink == 1 and
         (0 <= entry.st_size <= maximum if allow_empty else 0 < entry.st_size <= maximum),
         'public_file_rejected')
    if private:
        need(entry.st_uid == os.getuid() and stat.S_IMODE(entry.st_mode) == 0o600, 'public_private_file_rejected')
    fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        before = os.fstat(fd)
        need((before.st_dev, before.st_ino) == (entry.st_dev, entry.st_ino), 'public_file_changed')
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after, final = os.fstat(fd), file.lstat()
        # Linux runtime requires the full change-time identity. On Windows
        # source fixtures, Python's path/fd stat APIs disagree on deprecated
        # st_ctime; the explicit birth-time field agrees between both APIs.
        identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns,
                              v.st_birthtime_ns if sys.platform == 'win32' else v.st_ctime_ns,
                              v.st_nlink, v.st_mode, v.st_uid)
        need(len(raw) == before.st_size and len(raw) <= maximum and identity(before) == identity(after) == identity(final), 'public_file_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def validate_configuration(value):
    need(exact(value, ('schema', 'profileId', 'identity', 'runtimeArtifactSha256', 'worldPackSha256', 'engineCommit',
                       'engineInventorySha256', 'seedArtifactSha256', 'password', 'port', 'journalMode', 'requiredCheckpointSha256',
                       'requiredMigrationSha256', 'oldStopReceiptSha256')),
         'public_configuration_rejected')
    need(value['schema'] == 'amz.ap.public-beta.native-restore-configuration.v1' and value['profileId'] == 'public-native-restricted-restore-v1' and
         value['engineCommit'] == ENGINE_COMMIT and value['engineInventorySha256'] == ENGINE_SHA and value['worldPackSha256'] == WORLD_PACK_SHA,
         'public_configuration_rejected')
    scope = value['identity']
    need(exact(scope, IDENTITY) and scope['appVariant'] == 'public-beta' and scope['policyId'] == 'public-disposable-beta-v1', 'public_identity_rejected')
    need(all(type(scope[k]) is str and UUID.fullmatch(scope[k]) for k in ('environmentId', 'dataEpoch', 'roomId', 'attemptId', 'runtimeLaunchId')) and
         all(integer(scope[k], 1, 1000000000) for k in ('allocationRevision', 'seedRevision', 'credentialEpoch')) and
         scope['externalId'] == f"ap-beta-{scope['roomId']}-r{scope['allocationRevision']}" and type(scope['serverId']) is str and
         re.fullmatch(r'[A-Za-z0-9_-]{1,80}', scope['serverId']), 'public_identity_rejected')
    need(all(type(value[k]) is str and SHA.fullmatch(value[k]) for k in ('runtimeArtifactSha256', 'seedArtifactSha256')) and
         type(value['password']) is str and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', value['password']) and integer(value['port'], 1, 65535), 'public_configuration_rejected')
    need(value['journalMode'] == 'migrate' and all(type(value[key]) is str and SHA.fullmatch(value[key])
         for key in ('requiredCheckpointSha256', 'requiredMigrationSha256', 'oldStopReceiptSha256')), 'public_restore_approval_required')
    return value


def validate_artifact(raw, expected):
    need(type(expected) is str and SHA.fullmatch(expected) and sha(raw) == expected, 'public_artifact_pin_changed')
    value = strict_json(raw)
    need(exact(value, ('schema', 'version', 'repository', 'sourceCommit', 'profileId', 'composition', 'imageRepository', 'engine', 'ownedFiles', 'toolchain', 'sourceTransfer', 'qualification',
                       'executionProfileSha256', 'nativeRestoreProfileSha256', 'sourceFoundation')) and
         value['schema'] == 'amz.ap.public-beta.server-runtime-restore.v1' and type(value['version']) is int and value['version'] == 1 and value['repository'] == 'Antimatter-Zone/DMS-Archipelago-Server' and
         type(value['sourceCommit']) is str and re.fullmatch(r'[a-f0-9]{40}', value['sourceCommit']) and value['profileId'] == 'public-native-restricted-restore-v1' and
         value['composition'] == 'server-headless-public-slot-gateway-v1' and value['imageRepository'] == 'docker.darkmatterservers.com/dms-public-beta/ap-runtime-public-beta', 'public_artifact_rejected')
    engine = value['engine']
    need(exact(engine, ('version', 'commit', 'archiveSha256', 'inventorySha256', 'worldPackSha256', 'headlessHintsSha256')) and engine['version'] == '0.6.8' and
         engine['commit'] == ENGINE_COMMIT and engine['archiveSha256'] == ARCHIVE_SHA and engine['inventorySha256'] == ENGINE_SHA and engine['worldPackSha256'] == WORLD_PACK_SHA and engine['headlessHintsSha256'] == HINTS_SHA and
         value['executionProfileSha256'] == PROFILE_SHA and value['nativeRestoreProfileSha256'] == RESTORE_PROFILE_SHA and
         sha(canonical(value['sourceFoundation'])) == FOUNDATION_CANONICAL_SHA,
         'public_engine_pin_changed')
    rows = value['ownedFiles']
    need(type(rows) is list and len(rows) == len(FILES) and [row.get('path') for row in rows if type(row) is dict] == sorted(FILES) and
         all(exact(row, ('path', 'sha256', 'bytes')) and type(row['sha256']) is str and SHA.fullmatch(row['sha256']) and integer(row['bytes'], 1, 262144) for row in rows), 'public_owned_inventory_rejected')
    need(exact(value['qualification'], ('sourceOnly', 'engineImported', 'imageBuilt', 'nativeAcceptance', 'restartBaselineMigration', 'restore', 'fenceReopen', 'gameplay', 'productionRegistered')) and
         value['qualification']['sourceOnly'] is True and all(enabled is False for key, enabled in value['qualification'].items() if key != 'sourceOnly'), 'public_qualification_rejected')
    return value


def verify_inventory(root, manifest):
    total = 0
    paths = set()
    for row in manifest['files']:
        name = row['path']
        need(type(name) is str and name not in paths and len(name) <= 256 and re.fullmatch(r"[A-Za-z0-9_. /!()'&-]+", name) and
             all(part not in ('', '.', '..') for part in name.split('/')), 'public_engine_path_rejected')
        paths.add(name)
        file = root.joinpath(*name.split('/'))
        need(file.resolve().is_relative_to(root.resolve()), 'public_engine_path_rejected')
        raw = read_fixed(file, 64 * 1024 * 1024, allow_empty=True)
        total += len(raw)
        need(total <= 256 * 1024 * 1024, 'public_engine_inventory_limit')
        if row['algorithm'] == 'sha256-lf':
            raw = raw.replace(b'\r\n', b'\n')
        else:
            need(row['algorithm'] == 'sha256', 'public_engine_algorithm_rejected')
        need(sha(raw) == row['sha256'], 'public_engine_source_changed')
    # An unlisted module can shadow a dependency even when every listed file
    # matches. Admit exactly the extracted inventory, including no links.
    actual, entries = set(), 0
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in (*folders, *files):
            entries += 1
            need(entries <= 10000, 'public_engine_inventory_limit')
            file = Path(directory) / name
            info = file.lstat()
            need(not stat.S_ISLNK(info.st_mode), 'public_engine_path_rejected')
            if name in folders:
                need(stat.S_ISDIR(info.st_mode), 'public_engine_path_rejected')
            else:
                need(stat.S_ISREG(info.st_mode), 'public_engine_path_rejected')
                actual.add(file.relative_to(root).as_posix())
    need(actual == paths, 'public_engine_unlisted_source')


def verify_inputs():
    global STAGE
    need(sys.platform == 'linux' and sys.version_info[:2] == (3, 12) and os.getuid() != 0 and Path('/.dockerenv').is_file(), 'public_container_required')
    STAGE = 'protected_configuration'
    checked_directory(PRIVATE, private=True)
    need(os.statvfs(ENGINE).f_flag & os.ST_RDONLY and os.statvfs(OWNED).f_flag & os.ST_RDONLY, 'public_readonly_sources_required')
    config = validate_configuration(strict_json(read_fixed(CONFIG, 16384, private=True)))
    STAGE = 'artifact'
    artifact = validate_artifact(read_fixed(OWNED / 'public-server-runtime-restore.v1.json', 1048576), config['runtimeArtifactSha256'])
    code = {}
    STAGE = 'owned_inventory'
    for row in artifact['ownedFiles']:
        raw = read_fixed(OWNED / row['path'], 262144)
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'public_owned_source_changed')
        code[row['path']] = raw
    need(sha(code['runtime-profile.json']) == PROFILE_SHA, 'public_profile_changed')
    need(sha(code['fresh-runtime-profile.json']) == WORLD_PACK_SHA and sha(code['native-restore-profile.v1.json']) == RESTORE_PROFILE_SHA,
         'public_restore_profile_changed')
    raw = read_fixed(OWNED / 'engine-manifest.json', 2 * 1024 * 1024)
    need(sha(raw) == ENGINE_SHA, 'public_engine_pin_changed')
    manifest = strict_json(raw)
    need(manifest['engineCommit'] == ENGINE_COMMIT and len(manifest['files']) == 3539, 'public_engine_pin_changed')
    hints = read_fixed(OWNED / 'world-hints.v1.json', 65536)
    need(sha(hints) == HINTS_SHA, 'public_hint_pin_changed')
    STAGE = 'engine_inventory'
    verify_inventory(ENGINE, manifest)
    STAGE = 'seed'
    seed = read_fixed(SEED, 16777216, private=True)
    need(sha(seed) == config['seedArtifactSha256'] and seed[0] == 3, 'public_seed_pin_changed')
    # Protected custody transfer supplies only the exact stopped journal,
    # capsule/migration/seed/config. Never clear old channels or stale locks.
    read_fixed(PRIVATE / 'public-gateway-journal.json', 2 * 1024 * 1024, private=True)
    need(sha(read_fixed(PRIVATE / 'public-native-custody.amzc', 16777216, private=True)) == config['requiredCheckpointSha256'], 'public_restore_custody_changed')
    raw_migration = read_fixed(PRIVATE / 'public-runtime-migration.json', 16384, private=True)
    need(sha(raw_migration) == config['requiredMigrationSha256'], 'public_restore_migration_changed')
    migration = strict_json(raw_migration)
    need(migration.get('newIdentity') == config['identity'] and migration.get('custodySha256') == config['requiredCheckpointSha256'] and
         migration.get('oldStopReceiptSha256') == config['oldStopReceiptSha256'] and
         migration.get('targetRuntimeArtifactSha256') == config['runtimeArtifactSha256'] and migration.get('targetWorldPackSha256') == WORLD_PACK_SHA,
         'public_restore_migration_changed')
    if SAVE.exists() or SAVE.is_symlink():
        need(sha(read_fixed(SAVE, 16777216, private=True)) == migration.get('nativeSaveSha256'), 'public_restore_existing_save_changed')
    for name in ('public-runtime-status.json', 'public-gateway-control.json', 'public-gateway-ack.json',
                 'public-runtime-control.json', 'public-runtime-ack.json', 'public-runtime-operation.json'):
        file = PRIVATE / name
        need(not file.exists() and not file.is_symlink(), 'public_existing_run_requires_migration')
    return config, code, strict_json(hints), migration, seed


def load_verified_module(name, raw):
    # Execute the exact already-verified bytes, not a second path-based read.
    need(name not in sys.modules, 'public_module_already_loaded')
    module = types.ModuleType(name)
    module.__file__ = str(OWNED / (name + '.py'))
    sys.modules[name] = module
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


class FixedStatus:
    def __init__(self):
        self.previous = None

    def publish(self, value):
        raw = canonical(value)
        need(len(raw) <= 65536, 'public_status_limit')
        checked_directory(PRIVATE, private=True)
        if self.previous is None:
            need(not STATUS.exists() and not STATUS.is_symlink(), 'public_status_changed')
        else:
            need(read_fixed(STATUS, 65536, private=True) == self.previous, 'public_status_changed')
        temporary = PRIVATE / ('.public-runtime-status.' + str(uuid.uuid4()) + '.pending')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                need(count > 0, 'public_status_write_failed')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, STATUS)
        directory = os.open(PRIVATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        need(read_fixed(STATUS, 65536, private=True) == raw, 'public_status_changed')
        self.previous = raw


def initialize_core_settings(module):
    module.no_gui = True
    module.skip_autosave = True
    module.get_settings._cache = module.Settings(None)


def native_listener_ready(context, port):
    if context is None or context.exit_event.is_set():
        return False
    try:
        server = context.server.ws_server
        sockets = tuple(server.sockets)
        return bool(server.is_serving() and sockets and all(sock.getsockname()[1] == port for sock in sockets))
    except (AttributeError, OSError, TypeError):
        return False


def bind_native(module, config, hints, files, barrier_module, hooks_module, checkpoint_module, restore_module, custody_module, code, seed, current):
    state = {'context': None, 'hooks': None, 'snapshots': None, 'barrier': None, 'restored': None}
    original = module.process_client_cmd, module.on_client_joined, module.on_client_disconnected
    def load_seed(context, filename, use_embedded_server_options=False):
        need(filename == str(SEED) and use_embedded_server_options is True, 'public_restore_seed_path_rejected')
        current()
        # Consume captured hash-verified bytes, never a later unbounded reread.
        context._load(checkpoint_module.decode_native(seed[1:], module.restricted_loads), True)
        context.data_filename = filename
        current()
    def world_data(context):
        need(hints['engineCommit'] == ENGINE_COMMIT and hints['worldPackSha256'] == ENGINE_SHA and
             set(context.played_games) <= {'Archipelago', 'Yacht Dice'} and hints['defaultBlacklist'] == [], 'public_game_not_admitted')
        for game in context.played_games:
            context.non_hintable_names[game] = frozenset(hints['overrides'].get(game, []))
    def initialize_save(context, enabled=True):
        need(enabled and state['context'] is None, 'public_restore_composition_reused')
        need(context.host == '0.0.0.0' and context.port == config['port'], 'public_listener_binding_rejected')
        need(1 <= len(context.connect_names) <= 16 and set(context.games.values()) == {'Yacht Dice'}, 'public_game_not_admitted')
        need(all(type(name) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,16}', name) and
                 type(pair) is tuple and len(pair) == 2 and pair[0] == 0 and integer(pair[1], 1, 16)
                 for name, pair in context.connect_names.items()), 'public_slot_binding_rejected')
        context.save_filename = str(SAVE)
        context.saving = True
        context.password, context.server_password, context.item_cheat, context.log_network = config['password'], '', False, False
        state['context'] = context
        state['snapshots'] = checkpoint_module.NativeSnapshots(files, context)
        restored = restore_module.restore_native(custody_module.CustodyFiles(files), state['snapshots'],
            profile=code['native-restore-profile.v1.json'], expected_profile_sha256=RESTORE_PROFILE_SHA,
            expected_manifest_sha256=config['requiredMigrationSha256'], seed=seed,
            expected_stop_receipt_sha256=config['oldStopReceiptSha256'], expected_runtime_artifact_sha256=config['runtimeArtifactSha256'],
            expected_world_pack_sha256=WORLD_PACK_SHA, expected_identity=config['identity'], new_master=config['password'],
            restricted_loads=module.restricted_loads, clock=current, monotonic=time.monotonic)
        state['restored'] = restored
        # Constructing a barrier advances the journal. It MUST follow restore's
        # exact target replay check, not invalidate it before native set_save.
        barrier = barrier_module.NativeBarrier(config['identity'], config['password'], restored.state, files.commit_journal)
        state['barrier'] = barrier
        hooks = hooks_module.PublicHooks(barrier, *original)
        hooks.bind_context(context)
        state['hooks'] = hooks
        module.process_client_cmd, module.on_client_joined, module.on_client_disconnected = hooks.process_client_cmd, hooks.on_client_joined, hooks.on_client_disconnected
        context._start_async_saving()
        current()
    def serialized_save(context, exit_save=False):
        need(state['context'] is context and state['snapshots'] is not None, 'public_checkpoint_composition_required')
        return state['snapshots'].save_now()
    def loop_saving(context, atexit_save=True):
        # The explicit loader loop replaces the native daemon/atexit writer.
        need(state['context'] is context and state['snapshots'] is not None and context.auto_saver_thread is None, 'public_native_save_thread_forbidden')
    module.Context._load_world_data = world_data
    module.Context.load = load_seed
    module.Context.init_save = initialize_save
    module.Context._save = serialized_save
    module.Context._start_async_saving = loop_saving
    return state


async def drain_native(state, barrier, owner, pump, monitor, native, timeout=10):
    """Close admission/listener and drain native handlers before the last save.

    websockets13 wait_closed() includes connection-handler completion. Unknown
    teardown keeps the native owner/journal for reconciliation, never a final
    save claim from a snapshot preceding an in-flight handler's last mutation.
    """
    need(type(timeout) in (int, float) and 0 < timeout <= 10, 'public_shutdown_bound_required')
    failure = None
    try:
        if barrier is not None:
            barrier.shutdown()  # No new Connect may enter before any await.
    except BaseException as error:
        failure = error
    monitor.cancel()
    context, server = state['context'], None
    try:
        if context is not None:
            context.exit_event.set()
            server = getattr(getattr(context, 'server', None), 'ws_server', None)
            if server is not None:
                server.close()
        async def settle():
            if pump is not None:
                await pump.close()
            if server is not None:
                await server.wait_closed()
            results = await asyncio.gather(monitor, native, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                    raise result
        await asyncio.wait_for(settle(), timeout)
        if failure is not None:
            raise failure
        if state['snapshots'] is not None:
            state['snapshots'].save_now()
    except BaseException:
        owner._uncertain, owner._durable = True, None
        if barrier is not None:
            barrier.state['ready'], barrier.state['uncertain'] = False, True
        raise


def install_stop_signals(loop, stop):
    """Explicit native-loop lifecycle, before the first native task is started.

    Pinned MultiServer later installs its own exit-event callbacks. Those also
    resolve native completion into the same drain path. No on-import handler.
    """
    installed = []
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop)
            installed.append(sig)
    except BaseException:
        for sig in installed: loop.remove_signal_handler(sig)
        raise
    def close():
        for sig in installed: loop.remove_signal_handler(sig)
    return close


def main():
    global STAGE
    config, code, hints, migration, seed = verify_inputs()
    barrier_module = load_verified_module('gateway_barrier', code['gateway_barrier.py'])
    hooks_module = load_verified_module('gateway_hooks', code['gateway_hooks.py'])
    files_module = load_verified_module('native_files', code['native_files.py'])
    custody_module = load_verified_module('checkpoint_custody', code['checkpoint_custody.py'])
    checkpoint_module = load_verified_module('native_checkpoint', code['native_checkpoint.py'])
    restore_module = load_verified_module('native_restore', code['native_restore.py'])
    stop_redaction = hooks_module.install_log_redaction(config['password'])
    os.umask(0o077)
    STAGE = 'journal'
    barrier, state = None, None
    wall_floor, mono_floor = int(time.time() * 1000), time.monotonic()
    need(barrier_module.instant(migration['issuedAt']) <= wall_floor < barrier_module.instant(migration['expiresAt']), 'public_restore_expired')
    deadline = mono_floor + min(300000, barrier_module.instant(migration['expiresAt']) - wall_floor) / 1000
    def current():
        nonlocal wall_floor, mono_floor
        wall, mono = int(time.time() * 1000), time.monotonic()
        need(wall >= wall_floor and barrier_module.instant(migration['issuedAt']) <= wall < barrier_module.instant(migration['expiresAt']) and
             mono_floor <= mono < deadline, 'public_restore_expired')
        wall_floor, mono_floor = wall, mono
        return wall
    current()
    files = files_module.NativeFiles()
    try:
        # No initialize/empty journal path. Validate the complete protected
        # old-stop/custody migration before allowing the first engine import.
        adopted = custody_module.migrate(custody_module.CustodyFiles(files),
            expected_manifest_sha256=config['requiredMigrationSha256'], seed=seed, expected_stop_receipt_sha256=config['oldStopReceiptSha256'],
            expected_runtime_artifact_sha256=config['runtimeArtifactSha256'], expected_world_pack_sha256=WORLD_PACK_SHA, clock=current)
        need(adopted['custodySha256'] == config['requiredCheckpointSha256'], 'public_restore_custody_changed')
        os.environ.clear()
        os.environ.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME=str(PRIVATE), XDG_CONFIG_HOME=str(PRIVATE / 'config'),
                          XDG_CACHE_HOME=str(PRIVATE / 'cache'), APPDATA=str(PRIVATE), SKIP_REQUIREMENTS_UPDATE='1', PYTHONDONTWRITEBYTECODE='1')
        sys.path.insert(0, str(ENGINE))
        # This is the first engine import, after every protected/config/source
        # check. The accepted Member headless settings technique stays separate.
        STAGE = 'core_import'
        import Utils
        import settings
        initialize_core_settings(settings)
        for name, destination in (('user_path', PRIVATE), ('home_path', PRIVATE), ('cache_path', PRIVATE / 'cache'), ('output_path', PRIVATE / 'output')):
            getattr(Utils, name).cached_path = str(destination)
        STAGE = 'native_import'
        import MultiServer
        STAGE = 'native_binding'
        state = bind_native(MultiServer, config, hints, files, barrier_module, hooks_module, checkpoint_module, restore_module, custody_module, code, seed, current)
        sys.argv = ['MultiServer.py', str(SEED), '--host', '0.0.0.0', '--port', str(config['port']), '--savefile', str(SAVE),
                    '--use_embedded_options', '--disable_item_cheat', '--auto_shutdown', '0', '--loglevel', 'warning']
        args = MultiServer.parse_args()
        args.password, args.server_password, args.log_network, args.cert, args.cert_key = config['password'], '', False, None, None
        async def run():
            status, revision, pump, runtime_control = FixedStatus(), 0, None, None
            stopping = asyncio.Event()
            remove_signals = install_stop_signals(asyncio.get_running_loop(), stopping.set)
            async def observe():
                nonlocal revision, pump, runtime_control, barrier
                while True:
                    context = state['context']
                    if native_listener_ready(context, config['port']):
                        if pump is None:
                            current()
                            barrier = state['barrier']
                            need(barrier is not None and state['restored'] is not None and
                                 {key: barrier.state[key] for key in ('generation', 'initialReadyAt', 'lastDisconnectAt')} ==
                                 {'generation': migration['idle']['connectionGeneration'], 'initialReadyAt': migration['idle']['provenInitialReadyAt'],
                                  'lastDisconnectAt': migration['idle']['provenLastDisconnectAt']}, 'public_restore_baseline_changed')
                            barrier.mark_ready()
                            current()
                            pump = hooks_module.ControlPump(files, barrier, state['hooks'])
                            runtime_control = checkpoint_module.RuntimeControl(files, barrier, state['snapshots'], config)
                        state['snapshots'].periodic()
                        await pump.poll_once()
                        runtime_control.poll_once()
                        actual = barrier._actual()
                        known = actual is not None and barrier.state['ready'] and not barrier.state['uncertain']
                        revision += 1
                        retained = barrier.state['gates'].get(migration['newHold']['gate']['id']) == migration['newHold']
                        known = known and retained
                        status.publish({'schema': 'amz.ap.public-beta.native-restore-status.v1', **config['identity'], 'state': 'held_ready' if known and retained else 'unknown',
                                        'admissionHeld': retained, 'restoreProfileSha256': RESTORE_PROFILE_SHA, 'migrationSha256': config['requiredMigrationSha256'],
                                        'runtimeArtifactSha256': config['runtimeArtifactSha256'], 'worldPackSha256': WORLD_PACK_SHA, 'seedArtifactSha256': config['seedArtifactSha256'],
                                        'observationRevision': revision, 'connectedGameClients': len(actual) if known else None,
                                        'connectionGeneration': barrier.state['generation'] if known else None,
                                        'provenInitialReadyAt': barrier.state['initialReadyAt'], 'provenLastDisconnectAt': barrier.state['lastDisconnectAt'],
                                        'observedAt': barrier_module.iso(barrier._now())})
                    await asyncio.sleep(0.25)
            native = asyncio.create_task(MultiServer.main(args))
            monitor = asyncio.create_task(observe())
            stop = asyncio.create_task(stopping.wait())
            try:
                done, _ = await asyncio.wait((native, monitor, stop), return_when=asyncio.FIRST_COMPLETED)
                if monitor in done:
                    await monitor
                if stop not in done:
                    await native
            finally:
                try:
                    stop.cancel()
                    await asyncio.gather(stop, return_exceptions=True)
                    await drain_native(state, state['barrier'], files, pump, monitor, native)
                finally:
                    remove_signals()
        STAGE = 'native_loop'
        asyncio.run(run())
    finally:
        try:
            owned_barrier = state['barrier'] if state is not None else None
            if owned_barrier is not None and owned_barrier.state['ready']:
                owned_barrier.shutdown()
        finally:
            try:
                files.close()
            finally:
                try:
                    if state is not None and state['restored'] is not None: state['restored'].close()
                finally: stop_redaction()


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # No exception text, config, packet, account identity or traceback.
        print(json.dumps({'schema': 'amz.ap.public-beta.runtime-failure.v1', 'stage': STAGE, 'code': 'public_runtime_refused'}), file=sys.stderr)
        raise SystemExit(1)

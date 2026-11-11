"""Public source fixtures only. Never imports an AP engine or starts a server."""
import asyncio
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
spec = importlib.util.spec_from_file_location('public_runtime_loader_fixture', ROOT / 'runtime/loader.py')
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)
spec = importlib.util.spec_from_file_location('public_runtime_builder_fixture', ROOT / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
from gateway_barrier import NativeBarrier, initial_state
import gateway_hooks


def configuration():
    uid = lambda: str(uuid.uuid4())
    room = uid()
    scope = {'appVariant': 'public-beta', 'policyId': 'public-disposable-beta-v1', 'environmentId': uid(), 'dataEpoch': uid(),
             'roomId': room, 'externalId': 'ap-beta-' + room + '-r1', 'allocationRevision': 1, 'serverId': 'synthetic_server',
             'attemptId': uid(), 'seedRevision': 1, 'credentialEpoch': 1, 'runtimeLaunchId': uid()}
    return {'schema': 'amz.ap.public-beta.native-configuration.v1', 'profileId': 'public-disposable-beta-v1', 'identity': scope,
            'runtimeArtifactSha256': 'a' * 64, 'worldPackSha256': loader.PROFILE_SHA, 'engineCommit': loader.ENGINE_COMMIT,
            'engineInventorySha256': loader.ENGINE_SHA, 'seedArtifactSha256': 'b' * 64, 'password': 'synthetic_private_master_' + 'x' * 40,
            'port': 38281, 'journalMode': 'initialize', 'requiredCheckpointSha256': None}


class SourceAndArtifact(unittest.TestCase):
    def test_exact_portal_raw_modules_and_fixture_only_relocation(self):
        transfer = json.loads((ROOT / 'source-transfer.v1.json').read_bytes())
        self.assertEqual(transfer['sourceCommit'], '29a39c3431a6607b2e9faade355a92f16d6fd74f')
        self.assertFalse(transfer['qualification']['oldMemberAcceptanceInherited'])
        for row in transfer['files']:
            raw = (ROOT / row['path']).read_bytes()
            self.assertEqual(loader.sha(raw), row['sha256'])
            if row['transformation']:
                before, after = (row['transformation'][k].encode() for k in ('before', 'after'))
                self.assertEqual(raw.count(after), 1)
                raw = raw.replace(after, before)
            self.assertEqual(loader.sha(raw), row['sourceSha256'])
            self.assertEqual(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), row['sourceBlob'])

    def test_new_artifact_pins_public_profile_and_keeps_all_runtime_acceptance_closed(self):
        _, manifest, dependencies, inputs, transfer, admitted = builder.reviewed_source()
        self.assertEqual(len(manifest['files']), 3539)
        self.assertTrue(all(re.fullmatch(r"[A-Za-z0-9_. /!()'&-]+", row['path']) for row in manifest['files']))
        artifact = builder.artifact_document('f' * 40, dependencies, inputs, transfer, admitted)
        raw = loader.canonical(artifact)
        self.assertEqual(loader.validate_artifact(raw, loader.sha(raw)), artifact)
        self.assertEqual(artifact['engine']['worldPackSha256'], loader.PROFILE_SHA)
        self.assertNotEqual(loader.PROFILE_SHA, loader.ENGINE_SHA)
        self.assertTrue(artifact['qualification']['sourceOnly'])
        self.assertTrue(all(not enabled for key, enabled in artifact['qualification'].items() if key != 'sourceOnly'))
        self.assertEqual(artifact['toolchain']['sourceHelperSha256'], builder.BASE_PINS['build.py'])
        self.assertEqual(json.loads(inputs['runtime-profile.json'])['allowedSlotGames'], ['Yacht Dice'])
        self.assertNotIn('MultiServer', sys.modules)

    def test_artifact_wrong_pin_path_inventory_member_schema_or_claim_refused(self):
        _, _, dependencies, inputs, transfer, admitted = builder.reviewed_source()
        artifact = builder.artifact_document('f' * 40, dependencies, inputs, transfer, admitted)
        raw = loader.canonical(artifact)
        with self.assertRaisesRegex(loader.Refused, 'artifact_pin'):
            loader.validate_artifact(raw, '0' * 64)
        for change in ('path', 'duplicate', 'member', 'production', 'extra', 'version_bool', 'claim_number'):
            value = copy.deepcopy(artifact)
            if change == 'path': value['ownedFiles'][0]['path'] = '../outside.py'
            elif change == 'duplicate': value['ownedFiles'][1] = value['ownedFiles'][0]
            elif change == 'member': value['schema'] = 'amz.ap.server-runtime.v1'
            elif change == 'production': value['qualification']['productionRegistered'] = True
            elif change == 'version_bool': value['version'] = True
            elif change == 'claim_number': value['qualification']['nativeAcceptance'] = 0
            else: value['callback'] = 'unavailable'
            raw = loader.canonical(value)
            with self.subTest(change=change), self.assertRaises(loader.Refused):
                loader.validate_artifact(raw, loader.sha(raw))

    def test_member_source_pins_and_offline_context_recipe_are_preserved(self):
        builder.reviewed_source()
        docker = (ROOT / 'Dockerfile').read_text()
        self.assertIn('--network=none', docker)
        self.assertIn('--no-index --find-links=/wheels --require-hashes --no-deps', docker)
        self.assertIn('USER 65532:65532', docker)
        self.assertIn('ENTRYPOINT ["node","/opt/amz-ap-public/launcher.mjs"]', docker)
        self.assertNotIn('git clone', docker)
        for name, expected in builder.BASE_PINS.items():
            self.assertEqual(loader.sha((ROOT.parent / name).read_bytes()), expected)

    def test_dirty_uncommitted_source_cannot_prepare_or_masquerade_as_git_identity(self):
        with patch.object(builder.subprocess, 'run', return_value=SimpleNamespace(stdout=b' M source.py\n')):
            with self.assertRaisesRegex(ValueError, 'clean_committed_source_required'):
                builder.clean_commit({})

    def test_captured_dirty_bytes_cannot_be_labeled_with_later_clean_git_blob(self):
        _, _, _, _, _, committed = builder.reviewed_source()
        def git(command, **options):
            self.assertEqual(options['env']['GIT_ALLOW_PROTOCOL'], '')
            args = command[3:]
            if args[0] == 'rev-parse': raw = b'f' * 40
            elif args[0] == 'status': raw = b''
            elif args[0] == 'ls-tree': raw = b'100644 blob ' + b'a' * 40 + b'\t' + args[-1].encode()
            else:
                self.assertEqual(args[0:2], ['cat-file', 'blob'])
                raw = committed[args[-1].split(':', 1)[1]]
            return SimpleNamespace(stdout=raw)
        # Working files are now clean, but the captured source was earlier
        # different. Verification must compare the captured bytes, not reread.
        dirty = dict(committed)
        dirty[builder.key(ROOT / 'runtime/loader.py')] += b'\n# earlier dirty bytes\n'
        with patch.object(builder.subprocess, 'run', side_effect=git), patch.object(builder, 'regular', side_effect=AssertionError('late source reread')):
            self.assertEqual(builder.clean_commit(committed), 'f' * 40)
            with self.assertRaisesRegex(ValueError, 'git_blob_mismatch'):
                builder.clean_commit(dirty)

    def test_toolchain_and_helper_metadata_use_only_the_captured_snapshot_after_verification(self):
        base, manifest, dependencies, inputs, transfer, admitted = builder.reviewed_source()
        with self.assertRaises(TypeError): admitted['foreign'] = b'changed'
        with patch.object(builder, 'regular', side_effect=AssertionError('source changed after capture')), patch.object(Path, 'read_bytes', side_effect=AssertionError('path read after capture')), patch.object(Path, 'read_text', side_effect=AssertionError('path read after capture')):
            self.assertEqual(base.reviewed_source()[0], manifest)
            artifact = builder.artifact_document('f' * 40, dependencies, inputs, transfer, admitted)
        self.assertEqual(artifact['toolchain']['builderSha256'], loader.sha(admitted[builder.key(ROOT / 'build.py')]))
        self.assertEqual(artifact['toolchain']['dockerfileSha256'], loader.sha(admitted[builder.key(ROOT / 'Dockerfile')]))

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'known.txt'
            file.write_bytes(b'preserve')
            with self.assertRaisesRegex(ValueError, 'public_output_exists'):
                builder.write_new(file, b'replacement')
            self.assertEqual(file.read_bytes(), b'preserve')


class Guard(unittest.TestCase):
    def test_exact_configuration_and_closed_restart_restore_boundary(self):
        self.assertEqual(loader.validate_configuration(configuration())['journalMode'], 'initialize')
        for changes in ({'profileId': 'member-pilot'}, {'port': True}, {'port': 0}, {'password': 'too-short'},
                        {'journalMode': 'existing'}, {'requiredCheckpointSha256': 'c' * 64}, {'callback': 'forbidden'}):
            with self.subTest(changes=list(changes)), self.assertRaises(loader.Refused):
                loader.validate_configuration({**configuration(), **changes})
        value = configuration(); value['identity']['externalId'] = value['identity']['externalId'].replace('ap-beta-', 'ap-lobby-')
        with self.assertRaises(loader.Refused): loader.validate_configuration(value)

    def test_duplicate_nonfinite_and_malformed_json_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{} trailing', b'[]', b'{"x":"\xff"}'):
            with self.subTest(raw=raw), self.assertRaises(loader.Refused): loader.strict_json(raw)

    def test_engine_verification_only_reads_exact_bytes_and_normalizes_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); file = root / 'synthetic.py'
            raw = b'raise AssertionError("engine must never execute")\r\r\n'
            file.write_bytes(raw)
            row = {'path': 'synthetic.py', 'algorithm': 'sha256-lf', 'sha256': loader.sha(raw.replace(b'\r\n', b'\n'))}
            loader.verify_inventory(root, {'files': [row]})
            notice = root / "en_Yoshi's Island!.md"; notice.write_bytes(b'Pinned synthetic notice')
            rows = [row, {'path': notice.name, 'algorithm': 'sha256', 'sha256': loader.sha(notice.read_bytes())}]
            loader.verify_inventory(root, {'files': rows})
            empty = root / 'empty.py'; empty.write_bytes(b'')
            rows.append({'path': 'empty.py', 'algorithm': 'sha256', 'sha256': loader.sha(b'')})
            loader.verify_inventory(root, {'files': rows})
            with self.assertRaises(loader.Refused): loader.read_fixed(empty, 256)
            file.write_bytes(raw + b'# changed')
            # Refuse either at stable-file identity or the exact digest gate;
            # neither path may accept modified source or execute it.
            with self.assertRaises(loader.Refused): loader.verify_inventory(root, {'files': rows})

    def test_unlisted_engine_module_cannot_shadow_a_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); file = root / 'source.py'; file.write_bytes(b'pinned')
            row = {'path': 'source.py', 'algorithm': 'sha256', 'sha256': loader.sha(file.read_bytes())}
            (root / 'extra_dependency.py').write_bytes(b'raise AssertionError("must not import")')
            with self.assertRaisesRegex(loader.Refused, 'unlisted_source'):
                loader.verify_inventory(root, {'files': [row]})

    def test_engine_traversal_duplicates_algorithms_and_hardlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); file = root / 'source.py'; file.write_bytes(b'public synthetic code')
            row = {'path': 'source.py', 'algorithm': 'sha256', 'sha256': loader.sha(file.read_bytes())}
            for rows in ([{**row, 'path': '../outside'}], [row, row], [{**row, 'algorithm': 'md5'}]):
                with self.subTest(rows=rows), self.assertRaises(loader.Refused): loader.verify_inventory(root, {'files': rows})
            os.link(file, root / 'second.py')
            with self.assertRaisesRegex(loader.Refused, 'file_rejected'): loader.verify_inventory(root, {'files': [row]})

    def test_bounded_regular_reads_and_linked_ancestors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); file = root / 'source.py'; file.write_bytes(b'x' * 129)
            with self.assertRaises(loader.Refused): loader.read_fixed(file, 128)
            try: (root / 'alias').symlink_to(root, target_is_directory=True)
            except OSError: self.skipTest('Creating a test directory symlink is unavailable on this platform')
            with self.assertRaises(loader.Refused): loader.read_fixed(root / 'alias/source.py', 256)

    def test_failed_guard_never_loads_owned_code_or_engine(self):
        with patch.object(loader, 'verify_inputs', side_effect=loader.Refused('synthetic_guard_failed')), patch.object(loader, 'load_verified_module') as imported:
            with self.assertRaisesRegex(loader.Refused, 'guard_failed'): loader.main()
            imported.assert_not_called()
        self.assertNotIn('MultiServer', sys.modules)

    def test_exact_verified_module_bytes_execute_without_a_second_path_read(self):
        name = 'synthetic_verified_' + uuid.uuid4().hex
        try:
            module = loader.load_verified_module(name, b'value = 7\n')
            self.assertEqual(module.value, 7)
            with self.assertRaisesRegex(loader.Refused, 'already_loaded'):
                loader.load_verified_module(name, b'value = 8\n')
        finally: sys.modules.pop(name, None)


class NativeComposition(unittest.TestCase):
    def test_actual_listener_must_be_serving_the_exact_port_before_initial_ready(self):
        context = SimpleNamespace(exit_event=SimpleNamespace(is_set=lambda: False), server=SimpleNamespace(ws_server=SimpleNamespace()))
        self.assertFalse(loader.native_listener_ready(context, 38281))
        context.server.ws_server = SimpleNamespace(is_serving=lambda: False, sockets=[SimpleNamespace(getsockname=lambda: ('127.0.0.1', 38281))])
        self.assertFalse(loader.native_listener_ready(context, 38281))
        context.server.ws_server.is_serving = lambda: True
        self.assertTrue(loader.native_listener_ready(context, 38281))
        self.assertFalse(loader.native_listener_ready(context, 38282))
        context.exit_event.is_set = lambda: True
        self.assertFalse(loader.native_listener_ready(context, 38281))

    def test_hooks_bind_exact_context_before_native_listener_without_replacing_class_identity(self):
        config = configuration(); saved = []
        barrier = NativeBarrier(config['identity'], config['password'], initial_state(config['identity']), saved.append)
        async def original(*_): pass
        class Context:
            host, port = '0.0.0.0', 38281
            connect_names, games, played_games = {'p_1': (0, 1)}, {1: 'Yacht Dice'}, {'Archipelago', 'Yacht Dice'}
            non_hintable_names = {}
            endpoints = []
            auto_saver_thread = None
            def _start_async_saving(self): self.saver_started = True
            def save(self, force): self.saved = force; return self._save() if force else True
        module = SimpleNamespace(Context=Context, process_client_cmd=original, on_client_joined=original, on_client_disconnected=original)
        hints = {'engineCommit': loader.ENGINE_COMMIT, 'worldPackSha256': loader.ENGINE_SHA, 'defaultBlacklist': [], 'overrides': {}}
        with tempfile.TemporaryDirectory() as directory, patch.object(loader, 'SAVE', Path(directory) / 'unused.apsave'):
            checkpoints, writes = [], []
            def factory(context):
                checkpoints.append(context)
                return SimpleNamespace(save_now=lambda: writes.append(context) or True)
            state = loader.bind_native(module, config, hints, barrier, gateway_hooks, factory)
            self.assertIs(module.Context, Context)
            context = Context(); context._load_world_data(); context.init_save()
            self.assertIs(state['context'], context)
            self.assertIs(state['hooks']._context, context)
            self.assertEqual(checkpoints, [context]); self.assertIsNone(context.auto_saver_thread)
            self.assertEqual(writes, [context]); self.assertFalse(hasattr(context, 'saver_started'))
            self.assertEqual(context.password, config['password']); self.assertFalse(context.item_cheat); self.assertFalse(context.log_network)
            self.assertFalse(barrier.state['ready']); self.assertIsNone(barrier.state['initialReadyAt'])
            self.assertEqual(context.non_hintable_names['Yacht Dice'], frozenset())
            context.played_games = {'APQuest'}
            with self.assertRaisesRegex(loader.Refused, 'game_not_admitted'): context._load_world_data()

    def test_core_settings_prevents_mutable_host_file_creation(self):
        core = SimpleNamespace(Settings=lambda value: ('fixed', value), get_settings=lambda: None)
        loader.initialize_core_settings(core)
        self.assertEqual(core.get_settings._cache, ('fixed', None)); self.assertTrue(core.no_gui and core.skip_autosave)

    @unittest.skipUnless(sys.platform == 'linux', 'Actual directory fsync/owner fixture requires Linux')
    def test_private_status_atomic_readback_rejects_foreign_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            with patch.object(loader, 'PRIVATE', root), patch.object(loader, 'STATUS', root / 'public-runtime-status.json'):
                status = loader.FixedStatus(); status.publish({'schema': 'synthetic', 'revision': 1}); status.publish({'schema': 'synthetic', 'revision': 2})
                self.assertEqual(loader.STATUS.stat().st_mode & 0o777, 0o600)
                loader.STATUS.write_bytes(b'{"foreign":true}')
                with self.assertRaisesRegex(loader.Refused, 'status_changed'): status.publish({'schema': 'synthetic', 'revision': 3})
                self.assertEqual(loader.STATUS.read_bytes(), b'{"foreign":true}')


class NativeShutdown(unittest.IsolatedAsyncioTestCase):
    async def test_stop_handlers_are_explicit_and_installed_before_native_startup(self):
        callbacks, removed, stopped = {}, [], asyncio.Event()
        loop = SimpleNamespace(add_signal_handler=lambda sig, callback: callbacks.update({sig: callback}),
                               remove_signal_handler=lambda sig: removed.append(sig))
        close = loader.install_stop_signals(loop, stopped.set)
        self.assertEqual(set(callbacks), {loader.signal.SIGTERM, loader.signal.SIGINT})
        self.assertFalse(stopped.is_set()); callbacks[loader.signal.SIGTERM]()
        await asyncio.wait_for(stopped.wait(), 0.1)
        close(); self.assertEqual(set(removed), set(callbacks))

    async def test_partial_signal_install_failure_restores_earlier_handler(self):
        removed = []
        def add(sig, _callback):
            if sig == loader.signal.SIGINT: raise RuntimeError('synthetic unavailable signal')
        loop = SimpleNamespace(add_signal_handler=add, remove_signal_handler=lambda sig: removed.append(sig))
        with self.assertRaises(RuntimeError): loader.install_stop_signals(loop, lambda: None)
        self.assertEqual(removed, [loader.signal.SIGTERM])

    async def test_final_snapshot_follows_real_handler_drain_instead_of_preceding_it(self):
        events, progress, close_requested = [], [0], asyncio.Event()
        exit_event = asyncio.Event()
        async def handler():
            await close_requested.wait()
            await asyncio.sleep(0)
            progress[0] = 1; events.append('handler_last_mutation')
        task = asyncio.create_task(handler())
        class Server:
            def close(self): events.append('listener_closed'); close_requested.set()
            async def wait_closed(self): await task; events.append('handlers_drained')
        class Barrier:
            state = {'ready': True, 'uncertain': False}
            def shutdown(self): self.state['ready'] = False; events.append('admission_closed')
        context = SimpleNamespace(exit_event=exit_event, server=SimpleNamespace(ws_server=Server()))
        state = {'context': context, 'snapshots': SimpleNamespace(save_now=lambda: events.append(('final_save', progress[0])))}
        owner = SimpleNamespace(_uncertain=False, _durable=object())
        native = asyncio.create_task(exit_event.wait()); monitor = asyncio.create_task(asyncio.sleep(3600))
        await loader.drain_native(state, Barrier(), owner, None, monitor, native)
        self.assertEqual(events, ['admission_closed', 'listener_closed', 'handler_last_mutation', 'handlers_drained', ('final_save', 1)])
        self.assertTrue(native.done() and monitor.done() and task.done()); self.assertFalse(owner._uncertain)

    async def test_unknown_handler_drain_has_no_final_snapshot_and_retains_owner(self):
        writes, exit_event = [], asyncio.Event()
        class Server:
            def close(self): pass
            async def wait_closed(self): await asyncio.Event().wait()
        barrier = SimpleNamespace(state={'ready': True, 'uncertain': False}, shutdown=lambda: None)
        owner = SimpleNamespace(_uncertain=False, _durable=object())
        state = {'context': SimpleNamespace(exit_event=exit_event, server=SimpleNamespace(ws_server=Server())),
                 'snapshots': SimpleNamespace(save_now=lambda: writes.append(True))}
        native = asyncio.create_task(exit_event.wait()); monitor = asyncio.create_task(asyncio.sleep(3600))
        with self.assertRaises(TimeoutError):
            await loader.drain_native(state, barrier, owner, None, monitor, native, timeout=0.01)
        self.assertEqual(writes, []); self.assertTrue(owner._uncertain); self.assertIsNone(owner._durable)
        self.assertEqual(barrier.state, {'ready': False, 'uncertain': True})
        await asyncio.gather(native, monitor, return_exceptions=True)


if __name__ == '__main__':
    unittest.main()

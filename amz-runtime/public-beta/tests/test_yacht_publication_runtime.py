"""Fresh source integration; no engine, image, listener or provider enrollment."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest.mock import patch

from test_native_publication import load
from test_native_publication_composition import NativeFixture
from test_yacht_action_runtime import configuration as old_configuration, keyfile

ROOT = Path(__file__).resolve().parents[2] / 'public-beta-yacht-publication'
loader = load(ROOT / 'runtime/loader.py', 'publication_loader_source_fixture')
builder = load(ROOT / 'build.py', 'publication_builder_source_fixture')
base = load(ROOT.parent / 'public-beta/runtime/loader.py', 'publication_foundation_source_fixture')


def configuration():
    return dict(old_configuration(), schema='amz.ap.public-beta.yacht-publication-configuration.v1',
                profileId=loader.PROFILE, executionProfileSha256=loader.PROFILE_SHA, publicationScopeSha256='d' * 64)


class PublicationRuntimeSourceTests(unittest.TestCase):
    def test_new_configuration_requires_independent_scope_pin_and_refuses_old_profiles_or_restore(self):
        config = configuration(); self.assertEqual(loader.validate_configuration(base, config), config)
        for change in ({'schema': 'amz.ap.public-beta.yacht-native-configuration.v1'}, {'profileId': 'public-yacht-actions-fresh-v1'},
                       {'publicationScopeSha256': None}, {'publicationScopeSha256': '../scope'}, {'journalMode': 'migrate'},
                       {'requiredCheckpointSha256': 'e' * 64}, {'roomSuppliedPath': '/tmp/scope'}):
            with self.assertRaises(Exception): loader.validate_configuration(base, dict(config, **change))
        without = {k: v for k, v in config.items() if k != 'publicationScopeSha256'}
        with self.assertRaises(Exception): loader.validate_configuration(base, without)

    def test_scope_must_match_exact_private_identity_artifact_profile_and_source_commit(self):
        config = configuration(); artifact = {'sourceCommit': '1' * 40}
        scope = {'identity': config['identity'], 'runtimeArtifactSha256': config['runtimeArtifactSha256'],
                 'runtimeProfileSha256': loader.PROFILE_SHA, 'runtimeSourceCommit': artifact['sourceCommit'],
                 'publisherSourceSha256': 'f7cf95840762e7e28194b5a589014ceb88fbe95cde05b6b1737aadc8f0be2ce2'}
        loader.validate_scope_binding(base, scope, config, artifact)
        for key in scope:
            with self.assertRaises(Exception): loader.validate_scope_binding(base, dict(scope, **{key: None}), config, artifact)
        self.assertEqual(config['publicationScopeSha256'], 'd' * 64)  # Validation never self-mints that pin.

    def test_same_run_keys_remain_independent_and_historical_action_source_is_unchanged(self):
        config = configuration(); keys = keyfile(config)
        self.assertEqual(loader.validate_keys(base, keys, config), (bytes(range(32)), bytes(range(32, 64))))
        with self.assertRaises(Exception): loader.validate_keys(base, dict(keys, effectsKey=keys['observationKey']), config)
        self.assertEqual(hashlib.sha256((ROOT.parent / 'public-beta-yacht-actions/runtime/loader.py').read_bytes()).hexdigest(),
                         loader.ACTION_LOADER_SHA)

    def test_captured_source_closure_contains_shared_types_and_excludes_tests_keys_or_live_authority(self):
        source = builder.reviewed_source(); inputs, provenance = source[4], source[7]
        self.assertEqual(set(inputs), set(loader.FILES)); self.assertEqual(len(inputs), 22)
        self.assertEqual(len(provenance['files']), 38)
        self.assertEqual(hashlib.sha256(inputs['native_composition.py']).hexdigest(), loader.COMPOSITION_SHA)
        artifact = builder.artifact_document('1' * 40, source)
        self.assertEqual(artifact['schema'], 'amz.ap.public-beta.yacht-publication-runtime.v1')
        self.assertEqual(artifact['executionProfileSha256'], loader.PROFILE_SHA)
        self.assertEqual(artifact['sourceFoundation'], provenance)
        self.assertFalse(any(v for k, v in artifact['qualification'].items() if k != 'sourceOnly'))
        self.assertFalse(any('test' in row['path'] or 'keys' in row['path'] for row in artifact['ownedFiles']))
        comp = loader.captured_module('fixture_verified_composition', inputs['native_composition.py'], loader.COMPOSITION_SHA)
        captured = comp.capture_native_sources({name: inputs[name + '.py'] for name in comp.SOURCE_PINS})
        modules = comp._sources(captured)['modules']
        self.assertIs(modules['native_yacht_effects'].NativeFiles, modules['native_files'].NativeFiles)
        self.assertIs(modules['native_yacht_observations'].NativeFiles, modules['native_files'].NativeFiles)
        self.assertIs(modules['native_checkpoint'].NativeFiles, modules['native_files'].NativeFiles)
        self.assertNotIn('MultiServer', sys.modules); self.assertNotIn('NetUtils', sys.modules)

    def test_bad_captured_composition_bytes_refuse_before_compile(self):
        raw = (ROOT.parent / 'public-beta-publication/runtime/native_composition.py').read_bytes()
        with patch.object(loader, 'compile', side_effect=AssertionError('compile forbidden'), create=True):
            with self.assertRaises(Exception): loader.captured_module('fixture', raw + b'\n', loader.COMPOSITION_SHA)

    def test_fixed_new_node_suite_runs_as_actual_bounded_subprocess_in_python_discovery(self):
        node = 'C:/Program Files/nodejs/node.exe' if os.name == 'nt' else 'node'
        result = subprocess.run([node, '--test', '--test-reporter=tap', str(Path(__file__).with_name('yacht-publication-launcher.test.mjs'))],
                                capture_output=True, timeout=20,
                                env={**os.environ, 'AMZ_YACHT_PUBLICATION_TEST_PYTHON': sys.executable})
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 2097152)
        self.assertEqual(result.returncode, 0, 'fixed new Node source subprocess failed: ' + result.stdout.decode(errors='replace')[-2000:])
        self.assertIn(b'# tests 4', result.stdout); self.assertIn(b'# pass 4', result.stdout); self.assertIn(b'# fail 0', result.stdout)
        self.assertEqual(result.stderr, b'')

    def test_source_default_is_inert_and_preparation_has_no_unclean_source_fallback(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'build.py')], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(json.loads(result.stdout), {'sourceOnly': True, 'ownedFiles': 22, 'pinnedWheels': 8,
                         'engineImported': False, 'imageBuilt': False, 'published': False})
        def dirty_git(argv, **kwargs):
            raw = b''
            if 'rev-parse' in argv: raw = b'1' * 40 + b'\n'
            if 'status' in argv: raw = b'?? uncommitted-source\n'
            return types.SimpleNamespace(returncode=0, stdout=raw, stderr=b'')
        with patch.object(builder.subprocess, 'run', side_effect=dirty_git):
            with self.assertRaises(Exception): builder.git_commit(builder.reviewed_source()[6])
        docker = (ROOT / 'Dockerfile').read_text()
        self.assertIn('--network=none', docker); self.assertIn('--require-hashes --no-deps', docker)
        profile = json.loads((ROOT / 'runtime/runtime-profile.json').read_bytes())
        self.assertFalse(profile['publication']['issuerEnrolled']); self.assertFalse(profile['publication']['physicalPermit'])


@unittest.skipUnless(sys.platform == 'linux', 'actual shared Linux native/publication FD/flock source fixture')
class PublicationLoaderLinuxTests(unittest.TestCase):
    def setUp(self):
        self.f = NativeFixture(); self.addCleanup(self.f.close)
        loader.install_control_guards(self.f.k, self.f.sources, self.f.guard)
        self.modules = self.f.k._sources(self.f.sources)['modules']

    def test_actual_effects_pending_scan_and_write_use_same_guard_with_no_extra_class(self):
        f, effects = self.f, self.modules['native_yacht_effects']
        config = configuration(); run = {**config['run'], **{k: f.base.binding[k] for k in
                ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')}}
        effects.initialize_effects(f.guard.files, run, config['roster'], f.base.binding)
        effects._no_pending(f.guard.files)
        effects._write(f.guard.files, 'public-yacht-effects-ack.json', {'sourceOnly': True}, 65536)
        self.assertEqual(f.guard.files._read('public-yacht-effects-ack.json', 65536)[0], {'sourceOnly': True})
        with self.assertRaises(Exception): effects._no_pending(object())
        self.assertFalse(f.guard.describe()['uncertain'])

    def test_copied_guard_or_other_namespace_cannot_install_control_wrappers(self):
        with self.assertRaises(Exception): loader.install_control_guards(self.f.k, self.f.sources, {})
        other = self.f.k.capture_native_sources(self.f.raw)
        with self.assertRaises(Exception): loader.install_control_guards(self.f.k, other, self.f.guard)

    def test_direct_observation_scan_and_read_wait_for_cross_process_staging_lock(self):
        f = self.f
        child = f.base.child('''with lock.hold(window()):
 pending=Path(root)/'.public-yacht-observation-control.json.pending-source-fixture'
 pending.write_bytes(b'partial');pending.chmod(0o600)
 (folder/'stage-ready').write_text('yes')
 while not (folder/'release-stage').exists():time.sleep(.002)
 pending.unlink()
lock.close();scope.close()
''')
        f.base.wait_file('stage-ready')
        observations = self.modules['native_yacht_observations']
        control = object.__new__(observations.YachtObservationControl)
        control.owner, control.last = f.guard.files, None
        control._check = lambda: None  # No synthetic native-ABI qualification; exercise actual poll scan/FD path only.
        errors, completed = [], threading.Event()
        def read():
            try: self.assertIsNone(control.poll_once())
            except BaseException as error: errors.append(error)
            finally: completed.set()
        thread = threading.Thread(target=read); thread.start()
        try:
            time.sleep(.03); self.assertFalse(completed.is_set())
        finally: (f.folder / 'release-stage').write_text('yes')
        thread.join(3); f.base.finish(child)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        self.assertFalse(f.guard.describe()['uncertain'])

    def test_save_precheck_is_guarded_but_snapshot_engine_serialization_has_no_publication_flock(self):
        f, checkpoint = self.f, self.modules['native_checkpoint']
        flags = []; state = f.k._COMPOSITIONS[f.guard]
        def unlocked():
            self.assertEqual(state['mutex'].depth, 0); flags.append('outside-publication')
        class Hooks:
            def __init__(self, *args): pass
            def bind_context(self, context): unlocked()
            def process_client_cmd(self, *args): pass
            def on_client_joined(self, *args): pass
            def on_client_disconnected(self, *args): pass
        class Context:
            host, port, auto_saver_thread = '0.0.0.0', 7105, None
            connect_names, games = {'Yacht_One': (0, 1)}, {1: 'Yacht Dice'}
            save_dirty = True
            def get_save(self): unlocked(); return {'fixture': 'engine-save-source-only'}
            def save(self, now): return self._save()
        module = types.SimpleNamespace(Context=Context, process_client_cmd=lambda: None,
                                       on_client_joined=lambda: None, on_client_disconnected=lambda: None)
        local_base = types.SimpleNamespace(**vars(base)); local_base.SAVE = f.root / 'public-seed.apsave'
        def snapshots(context):
            unlocked(); return checkpoint.NativeSnapshots(f.guard.files, context)
        loader.bind_native(local_base, module, configuration(), {}, object(), types.SimpleNamespace(PublicHooks=Hooks), snapshots, f.guard)
        context = Context(); context.init_save()
        self.assertGreaterEqual(len(flags), 3)
        self.assertIs(type(checkpoint.NativeSaveFiles(f.guard.files)), checkpoint.NativeSaveFiles)
        self.assertIsNotNone(checkpoint.NativeSaveFiles(f.guard.files).read())
        self.assertFalse(f.guard.describe()['uncertain'])


if __name__ == '__main__': unittest.main()

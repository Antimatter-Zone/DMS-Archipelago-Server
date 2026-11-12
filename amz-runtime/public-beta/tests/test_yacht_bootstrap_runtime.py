"""Bootstrap source/real-owned-FD tests, not image/provider/issuer qualification."""
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_native_publication import load

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'public-beta-yacht-bootstrap/runtime/bootstrap.py'
PROFILE = ROOT / 'public-beta-yacht-bootstrap/runtime/runtime-profile.json'
BUILD = ROOT / 'public-beta-yacht-bootstrap/build.py'
worker = load(SOURCE, 'actual_bootstrap_worker_source_fixture')
builder = load(BUILD, 'actual_bootstrap_builder_source_fixture')


class BootstrapSourceTests(unittest.TestCase):
    def test_profile_preserves_native_foundation_and_default_issuer_is_closed(self):
        raw = PROFILE.read_bytes(); profile = json.loads(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), worker.PROFILE_SHA)
        self.assertEqual(profile['trust'], {'defaultMode': 'unconfigured', 'runnableMode': 'synthetic-qa-only'})
        self.assertEqual(profile['native']['artifactSha256'], '7c65cc7984339622d1c515cdc7648af8220c3ade26a076292cc16fbcf3b2411c')
        self.assertEqual(hashlib.sha256((ROOT / 'public-beta-yacht-publication/runtime/loader.py').read_bytes()).hexdigest(),
                         profile['native']['loaderSha256'])
        self.assertEqual(profile['native']['ownedFiles'], 22)
        self.assertEqual(profile['bootstrap']['workspaceBytes'], 65536)
        self.assertEqual(profile['bootstrap']['startupMilliseconds'], 30000)

    def test_import_parser_and_exact_private_brands_cannot_become_native_permission(self):
        for raw in (b'\xef\xbb\xbf{}', b'{} ', b'{}{}', b'{"a":1,"a":1}', b'{"x":NaN}', b'[]'):
            with self.assertRaises((ValueError, RuntimeError)): worker.decode(raw, 32768)
        for value in ({}, object.__new__(worker.SealedSnapshot)):
            with patch.object(worker, 'compile', side_effect=AssertionError('no native execution'), create=True):
                with self.assertRaises(RuntimeError): worker.run_native_loader(value)
                self.assertEqual(worker._DIAGNOSTIC_STAGE, 'native_inputs')
        with self.assertRaises(RuntimeError): worker.SealedSnapshot()
        with self.assertRaises(RuntimeError): worker.VerifiedSeal()
        self.assertEqual(list(inspect.signature(worker.run_native_loader).parameters), ['snapshot'])
        self.assertNotIn('cryptography', SOURCE.read_text())
        self.assertNotIn('create_server', SOURCE.read_text())

    def test_original_startup_and_seal_monotonic_budgets_cannot_follow_a_stalled_wall(self):
        wall = time.time_ns() // 1000000
        with patch.object(worker.time, 'time_ns', return_value=wall * 1000000), \
             patch.object(worker.time, 'monotonic_ns', side_effect=[1000000000, 31000000000]):
            budget = worker.Budget(30000)
            with self.assertRaises(RuntimeError): budget.current()
        startup = worker.Budget(30000)
        anchor = (time.monotonic_ns() - 6000000000, time.time_ns() // 1000000)
        short = worker.Budget(5000, parent=startup, issued=worker.iso(anchor[1]),
                              expires=worker.iso(anchor[1] + 5000), anchor=anchor)
        with self.assertRaises(RuntimeError): short.current()

    def test_builder_accepts_only_public_explicit_qa_trust_and_never_private_keys(self):
        # Public RFC8032-format vector only; no signing key or approval is used.
        der = bytes.fromhex('302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        pem = '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode() + '\n-----END PUBLIC KEY-----\n'
        value = {'schema': 'amz.ap.public-beta.bootstrap-trust.v1', 'mode': 'synthetic-qa-only',
                 'rootPublicKeyPem': pem, 'rootSpkiSha256': hashlib.sha256(der).hexdigest()}
        raw = builder.canonical(value); self.assertEqual(builder.public_trust(raw, builder.sha(raw)), raw)
        for edit in ({'mode': 'production'}, {'privateKey': 'forbidden'}, {'rootPublicKeyPem': pem.replace('PUBLIC', 'PRIVATE')},
                     {'rootSpkiSha256': '0' * 64}):
            changed = builder.canonical({**value, **edit})
            with self.assertRaises(ValueError): builder.public_trust(changed, builder.sha(changed))
        with patch.object(builder, 'prepare', side_effect=AssertionError('no prepare')):
            self.assertEqual(builder.main(['--deploy']), 1)

    def test_artifact_source_and_producer_are_separate_from_unchanged_native_component(self):
        profile = json.loads(PROFILE.read_bytes())
        files = {'bootstrap.py': SOURCE.read_bytes(), 'launcher.mjs': (SOURCE.parent / 'launcher.mjs').read_bytes(),
                 'runtime-profile.json': PROFILE.read_bytes(),
                 'trust-profile.json': builder.canonical({'schema': 'amz.ap.public-beta.bootstrap-trust.v1',
                    'mode': 'unconfigured', 'rootPublicKeyPem': None, 'rootSpkiSha256': None})}
        raw = builder.artifact('a' * 40, profile, files); value = json.loads(raw)
        self.assertEqual(value['producerCommit'], 'a' * 40)
        self.assertEqual(value['native'], profile['native'])
        self.assertEqual([r['path'] for r in value['ownedFiles']], sorted(files))
        for row in value['ownedFiles']:
            self.assertEqual((row['sha256'], row['bytes']), (builder.sha(files[row['path']]), len(files[row['path']])))
        self.assertEqual(value['qualification'], profile['qualification'])
        docker = (SOURCE.parents[1] / 'Dockerfile').read_text()
        self.assertIn('ARG PARENT_NATIVE_IMAGE\nFROM ${PARENT_NATIVE_IMAGE}', docker)
        self.assertNotIn('RUN ', docker)
        self.assertIn('/opt/amz-ap-bootstrap/launcher.mjs', docker)

    def test_real_parent_checks_and_genuine_constructor_sites_remain_in_the_admitted_sources(self):
        parent = (ROOT / 'public-beta-yacht-publication/runtime/loader.py').read_text()
        self.assertIn('config, code, hints, seed, keys, key_raw, config_raw, scope_raw, artifact = verify_inputs(base)', parent)
        self.assertIn('with guard.transaction():', parent)
        self.assertIn('files.initialize(barrier_module.initial_state', parent)
        self.assertIn('install_control_guards(composition, sources, guard)', parent)
        source = SOURCE.read_text()
        self.assertIn('result = original_verify(base)', source)
        self.assertIn('original_initialize(value)', source)
        self.assertIn("type(guard.files) is genuine['modules']['native_files'].NativeFiles", source)
        self.assertIn('original_install(composition, sources, guard)', source)
        self.assertNotIn('sys.modules[', source)

    def test_actual_node_crypto_and_private_pipe_suite_uses_the_running_python_executable(self):
        node = shutil.which('node'); self.assertIsNotNone(node)
        environment = {'PATH': str(Path(node).parent) + os.pathsep + os.defpath,
                       'AMZ_BOOTSTRAP_TEST_PYTHON': sys.executable, 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
        if sys.platform == 'win32': environment['SystemRoot'] = 'C:\\Windows'
        result = subprocess.run([node, '--test', str(Path(__file__).with_name('yacht-bootstrap-launcher.test.mjs'))],
                                capture_output=True, env=environment, timeout=25)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace') + result.stdout.decode(errors='replace'))
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 65536)

    def test_worker_failure_marker_has_static_only_fields_and_no_exception_input(self):
        self.assertEqual(list(inspect.signature(worker.failure_marker).parameters), [])
        previous = worker._DIAGNOSTIC_STAGE
        try:
            for stage in worker.FAILURE_STAGES:
                worker.diagnostic_stage(stage)
                raw = worker.failure_marker()
                self.assertLessEqual(len(raw), 256)
                self.assertEqual(raw, worker.canonical({'schema': worker.FAILURE_SCHEMA,
                    'stage': stage, 'code': 'bootstrap_refused'}) + b'\n')
            for value in ('/private/fixture-key', object(), ['native_init'], None):
                with self.assertRaises(RuntimeError): worker.diagnostic_stage(value)
            self.assertEqual(worker._DIAGNOSTIC_STAGE, stage)
        finally: worker.diagnostic_stage(previous)

    def test_actual_early_worker_refusal_emits_only_static_phase_without_engine_or_keys(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(SOURCE)], capture_output=True,
                                env={'SystemRoot': 'C:\\Windows'} if sys.platform == 'win32' else {}, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, worker.canonical({'schema': worker.FAILURE_SCHEMA,
                         'stage': 'capture_inputs', 'code': 'bootstrap_refused'}) + b'\n')


@unittest.skipUnless(sys.platform == 'linux', 'Real owned Linux FD/fsync cases, no Windows or provider simulation')
class BootstrapOwnedFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amz-bootstrap-source-')
        self.folder = Path(self.temp.name)
        source = SOURCE.read_text()
        replacements = {'info.st_uid == 65532': 'info.st_uid == ' + str(os.geteuid()),
                        'info.st_gid == 65532': 'info.st_gid == ' + str(os.getegid())}
        for old, new in replacements.items():
            self.assertEqual(source.count(old), 2); source = source.replace(old, new)
        self.fixture = self.folder / 'fixture_worker.py'; self.fixture.write_text(source)
        self.k = load(self.fixture, 'isolated_bootstrap_owned_file_fixture')
        self.root = self.folder / 'private'; self.root.mkdir(mode=0o700)
        self.k.BOOT = self.root  # Explicit isolated fixed-root source fixture.
        self.fd = self.k.root(self.root)

    def tearDown(self): os.close(self.fd); self.temp.cleanup()

    def test_actual_fixed_metadata_publication_is_exclusive_complete_and_bounded(self):
        budget = self.k.Budget(3000)
        self.k.publish_metadata(self.fd, 'challenge.json', b'{"sourceOnly":true}', budget)
        self.assertEqual(self.k.read_at(self.fd, 'challenge.json', 4096)[0], b'{"sourceOnly":true}')
        with self.assertRaises(FileExistsError): self.k.publish_metadata(self.fd, 'challenge.json', b'{"different":true}', budget)
        self.assertTrue((self.root / '.challenge.json.pending').exists())
        self.assertEqual((self.root / 'challenge.json').read_bytes(), b'{"sourceOnly":true}')

    def test_actual_private_read_detects_changed_inode_mode_hardlink_and_retains_unknown_metadata(self):
        self.k.publish_metadata(self.fd, 'challenge.json', b'{}', self.k.Budget(3000))
        raw, expected, fd = self.k.read_at(self.fd, 'challenge.json', 4096, keep=True)
        try:
            target = self.root / 'challenge.json'; target.rename(self.root / 'old-owned')
            target.write_bytes(raw); target.chmod(0o600)
            self.assertNotEqual(self.k.private(target.stat(), 4096), expected)
            with self.assertRaises(RuntimeError): self.k.audit_boot(self.fd, self.k.Budget(3000))
            self.assertTrue((self.root / 'old-owned').exists())
        finally: os.close(fd)

    def test_bootstrap_workspace_never_discards_pending_unknown_or_oversize_inputs(self):
        for name, raw in (('unexpected', b'x'), ('.seal.json.pending', b'x' * 16385)):
            path = self.root / name; path.write_bytes(raw); path.chmod(0o600)
            with self.assertRaises(RuntimeError): self.k.audit_boot(self.fd, self.k.Budget(3000))
            self.assertEqual(path.read_bytes(), raw)
            path.unlink()  # Explicit cleanup of this isolated test fixture only.
        self.k.publish_metadata(self.fd, 'challenge.json', b'{}', self.k.Budget(3000))
        detached = self.folder / 'detached'; real_listdir = self.k.os.listdir
        def swap_after_names(fd):
            names = real_listdir(fd)
            self.root.rename(detached); self.root.mkdir(mode=0o700)
            return names
        with patch.object(self.k.os, 'listdir', side_effect=swap_after_names):
            with self.assertRaises(RuntimeError): self.k.audit_boot(self.fd, self.k.Budget(3000))
        with self.assertRaises(RuntimeError):
            self.k.publish_metadata(self.fd, 'consumed.json', b'{}', self.k.Budget(3000))
        self.assertEqual((detached / 'challenge.json').read_bytes(), b'{}')
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse((detached / 'consumed.json').exists())


if __name__ == '__main__': unittest.main()

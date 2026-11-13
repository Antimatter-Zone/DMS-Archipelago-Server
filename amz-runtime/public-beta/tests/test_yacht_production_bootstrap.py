"""Source/crypto and explicitly UID-adapted owned-FS fixtures, no enrollment."""
import base64
import hashlib
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
import uuid

from test_native_publication import load

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'public-beta-yacht-production-bootstrap'
publisher = load(PACKAGE / 'issuer/publisher.py', 'production_publisher_source_tests')
builder = load(PACKAGE / 'build.py', 'production_builder_source_tests')
worker = load(PACKAGE / 'runtime/bootstrap.py', 'production_worker_source_tests')


class ProductionBootstrapSourceTests(unittest.TestCase):
    def test_actual_profile_pin_separate_public_roots_and_native_foundation(self):
        raw = (PACKAGE / 'runtime/runtime-profile.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), worker.PROFILE_SHA)
        self.assertEqual(worker.PROFILE_SHA, publisher.PROFILE_SHA)
        self.assertEqual(worker.PROFILE_SHA, builder.PROFILE_SHA)
        value = json.loads(raw)
        self.assertEqual(value['native']['artifactSha256'], publisher.NATIVE['artifactSha256'])
        self.assertEqual(value['native']['ownedFiles'], 22)
        self.assertEqual(value['bootstrap']['startupMilliseconds'], 30000)
        self.assertEqual(value['bootstrap']['sealMilliseconds'], 5000)
        self.assertEqual(value['qualification']['issuerEnrolled'], False)
        self.assertEqual(value['trust']['defaultMode'], 'unconfigured')

    def test_protected_prepare_accepts_only_independent_public_purpose_roots(self):
        def entry(purpose, tail):
            der = bytes.fromhex('302a300506032b6570032100' + tail)
            return {'keyId': purpose, 'rootPublicKeyPem': '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode() + '\n-----END PUBLIC KEY-----\n',
                    'rootSpkiSha256': hashlib.sha256(der).hexdigest()}
        value = {'schema': 'amz.ap.public-beta.production-bootstrap-trust.v1',
                 'issuer': entry(publisher.DOMAIN, 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
                 'provider': entry(publisher.LAUNCH, '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')}
        raw = builder.canonical(value)
        self.assertEqual(builder.public_trust(raw, builder.sha(raw)), raw)
        for edit in ({'mode': 'production'}, {'issuer': None}, {'provider': dict(value['issuer'], keyId=publisher.LAUNCH)}):
            changed = builder.canonical(dict(value, **edit))
            with self.assertRaises((ValueError, TypeError)): builder.public_trust(changed, builder.sha(changed))
        with self.assertRaises(ValueError): builder.public_trust(raw, 'a' * 64)
        with patch.object(builder, 'prepare', side_effect=AssertionError('no prepare')):
            self.assertEqual(builder.main(['--deploy']), 1)

    def test_no_public_json_or_copied_object_can_enter_the_native_loader(self):
        for value in ({}, object.__new__(worker.SealedSnapshot)):
            with self.assertRaises(RuntimeError): worker.run_native_loader(value)
        with self.assertRaises(RuntimeError): worker.SealedSnapshot()
        for raw in (b'{}\n', b'{"a":1,"a":2}', b'[]', b'{"x":NaN}', b'\xef\xbb\xbf{}'):
            with self.assertRaises((RuntimeError, ValueError)): publisher.decode(raw)

    def test_actual_node_signature_and_cross_binding_cases_are_discovered_once(self):
        node = shutil.which('node'); self.assertIsNotNone(node)
        environment = {'PATH': str(Path(node).parent) + os.pathsep + os.defpath, 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
        if sys.platform == 'win32': environment['SystemRoot'] = 'C:\\Windows'
        result = subprocess.run([node, '--test', str(Path(__file__).with_name('yacht-production-bootstrap.test.mjs'))],
                                capture_output=True, env=environment, timeout=15)
        self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 65536)

    def test_actual_publisher_early_refusal_has_no_output_keys_or_protected_file_access(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(PACKAGE / 'issuer/publisher.py'), '--server-uuid', str(uuid.uuid4())],
                                capture_output=True, env={'SystemRoot': 'C:\\Windows'} if sys.platform == 'win32' else {}, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')

    def test_original_publisher_mono_window_cannot_renew_after_prewrite(self):
        wall = time.time_ns() // 1000000
        with patch.object(publisher, 'process_start', return_value='1'), \
             patch.object(publisher.time, 'time_ns', return_value=wall * 1000000), \
             patch.object(publisher.time, 'monotonic_ns', side_effect=[1000000000, 1000000000, 1000000000, 7000000000]):
            budget = publisher.Budget()
            budget.cap(publisher.iso(wall), publisher.iso(wall + 5000), 5000)
            with self.assertRaises(RuntimeError): budget.current()


@unittest.skipUnless(sys.platform == 'linux', 'Actual Linux FD/fsync/O_TMPFILE fixture; no Windows/provider simulation')
class ProductionPublisherOwnedFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amz-production-bootstrap-source-')
        self.folder = Path(self.temp.name)
        # Explicit source-fixture UID adaptation, never a production admission
        # seam. main() stays fixed-entry/root-peer protected and is not invoked.
        source = (PACKAGE / 'issuer/publisher.py').read_text()
        source = source.replace('info.st_uid == 65532', 'info.st_uid == os.geteuid()')
        source = source.replace('info.st_gid == 65532', 'info.st_gid == os.getegid()')
        source = source.replace('uid=65532, gid=65532', 'uid=os.geteuid(), gid=os.getegid()')
        adapted = self.folder / 'explicit_owned_fixture.py'; adapted.write_text(source)
        self.k = load(adapted, 'production_publisher_explicit_owned_fixture')
        self.k.HOST = self.folder / 'volumes'; self.k.HOST.mkdir(mode=0o700)
        self.server = str(uuid.uuid4()); self.volume = self.k.HOST / self.server; self.volume.mkdir(mode=0o700)
        self.native = self.volume / '.amz'; self.native.mkdir(mode=0o700)
        self.boot = self.volume / '.amz-bootstrap'; self.boot.mkdir(mode=0o700)
        now = time.time_ns() // 1000000
        challenge = {'schema': 'amz.ap.public-beta.production-bootstrap-challenge.v1', 'nonce': 'a' * 64,
                     'process': {'pid1StartTicks': '1', 'workerStartTicks': '2', 'workerPid': 3},
                     'bootstrapArtifactSha256': 'b' * 64, 'profileSha256': self.k.PROFILE_SHA,
                     'nativeRoot': self.k.root_value(self.native.stat()), 'bootstrapRoot': self.k.root_value(self.boot.stat()),
                     'issuedAt': self.k.iso(now), 'expiresAt': self.k.iso(now + 30000)}
        path = self.boot / 'challenge.json'; path.write_bytes(self.k.canonical(challenge)); path.chmod(0o600)
        self.k.ROOT_FDS = (os.open(self.native, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC),
                           os.open(self.boot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        self.namespace = self.k.Namespace(self.server, self.k.Budget())

    def tearDown(self):
        self.namespace.close(); self.temp.cleanup()

    def five(self):
        for name, _ in self.k.FILES: self.namespace.write(name, b'\x03x' if name.endswith('.archipelago') else b'{}')

    def test_actual_five_file_create_fsync_named_readback_and_exclusive_seal(self):
        self.five(); rows = self.namespace.rows()
        for row in rows:
            path = self.native / row['name']; info = path.stat()
            self.assertEqual(row['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(row['inode'], str(info.st_ino)); self.assertEqual(row['uid'], info.st_uid)
            self.assertEqual(info.st_nlink, 1); self.assertEqual(info.st_mode & 0o777, 0o600)
        raw = bytearray(b'{"syntheticFilesystemTest":true}')
        self.namespace.seal(raw)
        self.assertEqual((self.boot / 'seal.json').read_bytes(), raw)
        self.assertEqual((self.boot / 'seal.json').stat().st_nlink, 1)
        self.assertEqual(set(p.name for p in self.boot.iterdir()), {'challenge.json', 'seal.json'})
        original = (self.boot / 'seal.json').stat().st_ino
        with self.assertRaises(RuntimeError): self.namespace.seal(b'{"other":true}')
        self.assertEqual((self.boot / 'seal.json').stat().st_ino, original)
        # Genuine native journal creation can race publisher acknowledgment;
        # it grants no Ready/full-namespace claim from the publisher itself.
        journal = self.native / 'public-native-journal.json'; journal.write_bytes(b'{}'); journal.chmod(0o600)
        self.namespace.current()

    def test_actual_namespace_swap_and_immutable_input_replacement_refuse_without_repair(self):
        self.five(); original = self.native / self.k.FILES[0][0]
        retired = self.native / 'retained-original'; original.rename(retired); original.write_bytes(b'{}'); original.chmod(0o600)
        with self.assertRaises(RuntimeError): self.namespace.current()
        self.assertTrue(retired.exists()); self.assertTrue(original.exists())
        moved = self.volume / 'retained-native'; self.native.rename(moved); self.native.mkdir(mode=0o700)
        with self.assertRaises(RuntimeError): self.namespace.current()
        self.assertTrue((moved / 'retained-original').exists())
        self.assertEqual(list(self.native.iterdir()), [])

    def test_actual_write_fsync_failure_retains_created_inode_and_all_known_fds_close_once(self):
        real_fsync = self.k.os.fsync
        with patch.object(self.k.os, 'fsync', side_effect=OSError('synthetic fsync refusal')):
            with self.assertRaises(OSError): self.namespace.write(self.k.FILES[0][0], b'{}')
        path = self.native / self.k.FILES[0][0]; self.assertEqual(path.read_bytes(), b'{}')
        handles = list(self.namespace.handles); self.namespace.close()
        for fd in handles:
            with self.assertRaises(OSError): os.fstat(fd)
        self.assertTrue(path.exists()); self.assertTrue(callable(real_fsync))

    def test_same_fd_bounded_input_growth_refuses_and_wipes_allocated_partial_buffer(self):
        path = self.folder / 'private-input'; path.write_bytes(b'private-fixture'); path.chmod(0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        captures = []; original_read = self.k.os.pread; grew = False
        def allocate(*args):
            value = bytearray(*args); captures.append(value); return value
        def grow(actual, size, offset):
            nonlocal grew
            raw = original_read(actual, size, offset)
            if actual == fd and not grew:
                grew = True
                with path.open('ab') as output: output.write(b'after-admission')
            return raw
        try:
            with patch.object(self.k, 'bytearray', side_effect=allocate, create=True), patch.object(self.k.os, 'pread', side_effect=grow):
                with self.assertRaises(RuntimeError): self.k.bounded(fd, 64, self.k.Budget())
            self.assertTrue(grew); self.assertGreater(len(captures), 0)
            self.assertTrue(all(not any(value) for value in captures))
        finally: os.close(fd)


if __name__ == '__main__': unittest.main()

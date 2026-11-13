"""Source protocol/owned-file tests; never starts MultiServer or a listener."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

PACKAGE = Path(__file__).resolve().parents[2] / 'public-beta-yacht-first-start'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


worker = load(PACKAGE / 'runtime/bootstrap.py', 'first_start_test_worker')
builder = load(PACKAGE / 'build.py', 'first_start_test_builder')
control = load(PACKAGE / 'runtime/first_start.py', 'first_start_test_control')


class FirstStartProtocolTests(unittest.TestCase):
    def test_actual_public_encoding_accepts_independent_purposes_and_null_activation_default(self):
        def entry(purpose, tail):
            der = bytes.fromhex('302a300506032b6570032100' + tail)
            return {'keyId': purpose, 'rootPublicKeyPem': '-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode() + '\n-----END PUBLIC KEY-----\n',
                    'rootSpkiSha256': hashlib.sha256(der).hexdigest()}
        value = {'schema': 'amz.ap.public-beta.yacht-first-start-trust.v1',
            'issuer': entry('amz.ap.public-beta.production-bootstrap-seal.v1', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
            'provider': entry('amz.ap.public-beta.yacht-provider-launch.v1', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'),
            'launchCommand': None}
        raw = builder.canonical(value)
        self.assertEqual(builder.public_trust(raw, builder.sha(raw)), raw)
        purpose = 'amz.ap.public-beta.yacht-first-start-activation.v1'
        bad = dict(value, launchCommand=dict(value['provider'], keyId=purpose))
        raw = builder.canonical(bad)
        with self.assertRaises(ValueError): builder.public_trust(raw, builder.sha(raw))
        with self.assertRaises(ValueError): builder.public_trust(raw, '0' * 64)

    def test_canonical_control_rejects_duplicates_nonfinite_and_noncanonical_bytes(self):
        for raw in (b'{}\n', b'{"a":1,"a":2}', b'[]', b'{"x":NaN}', b'\xef\xbb\xbf{}'):
            with self.assertRaises((RuntimeError, ValueError)): worker.decode(raw, 4096)
        self.assertEqual(worker.decode(b'{"a":1}', 4096), {'a': 1})
        with self.assertRaises(RuntimeError): worker.decode(b'{' + b'x' * 4096, 4096)

    def test_private_snapshots_and_first_start_objects_cannot_be_copied_or_constructed(self):
        with self.assertRaises(RuntimeError): control.FirstStart()
        for value in ({}, object.__new__(control.FirstStart)):
            with self.assertRaises(RuntimeError): control._current(value)
        for value in ({}, object.__new__(worker.SealedSnapshot)):
            with self.assertRaises(RuntimeError): worker.run_native_loader(value)
        with self.assertRaises(RuntimeError): worker.VerifiedSeal()

    def test_original_startup_and_short_monotonic_caps_do_not_renew(self):
        wall = time.time_ns() // 1000000
        with patch.object(worker.time, 'time_ns', return_value=wall * 1000000), \
             patch.object(worker.time, 'monotonic_ns', return_value=1000000000):
            startup = worker.Budget(30000)
            short = worker.Budget(5000, parent=startup, issued=worker.iso(wall), expires=worker.iso(wall + 4000))
        with patch.object(worker.time, 'time_ns', return_value=(wall + 4000) * 1000000), \
             patch.object(worker.time, 'monotonic_ns', return_value=5000000000):
            with self.assertRaises(RuntimeError): short.current()
        with patch.object(worker.time, 'time_ns', return_value=(wall + 1) * 1000000), \
             patch.object(worker.time, 'monotonic_ns', return_value=31000000000):
            with self.assertRaises(RuntimeError): startup.current()


@unittest.skipUnless(sys.platform == 'linux', 'Actual Linux owned directory/FD/block accounting; no Windows simulation')
class FirstStartOwnedFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amz-first-start-source-')
        self.folder = Path(self.temp.name); self.boot = self.folder / 'boot'; self.boot.mkdir(mode=0o700)
        # Explicit filesystem-only source fixture. No main/engine/CP sender is
        # invoked, and no accepted native-ready or activation brand is minted.
        source = (PACKAGE / 'runtime/bootstrap.py').read_text()
        source = source.replace('info.st_uid == 65532', 'info.st_uid == os.geteuid()')
        source = source.replace('info.st_gid == 65532', 'info.st_gid == os.getegid()')
        adapted = self.folder / 'owned_bootstrap.py'; adapted.write_text(source)
        self.w = load(adapted, 'explicit_first_start_owned_bootstrap')
        self.w.BOOT = self.boot; self.fd = self.w.root(self.boot); self.budget = self.w.Budget(30000)

    def tearDown(self):
        os.close(self.fd); self.temp.cleanup()

    def write(self, name, raw):
        path = self.boot / name; path.write_bytes(raw); path.chmod(0o600); return path

    def test_real_block_accounting_includes_all_current_pending_reserves_and_two_kib_ack(self):
        ack = self.write('first-start-ack.json', b'x' * 2048)
        self.assertGreaterEqual(ack.stat().st_blocks * 512, 4096)
        self.w.audit_boot(self.fd, self.budget, sealed=True)
        self.assertEqual(4096 + sum(self.w.BOOT_CAPS.values()), 69632)
        self.write('foreign.json', b'{}')
        with self.assertRaises(RuntimeError): self.w.audit_boot(self.fd, self.budget)
        self.assertEqual(ack.read_bytes(), b'x' * 2048)

    def test_pending_symlink_and_hardlink_never_become_completed_control(self):
        pending = self.write('.first-start-control.json.pending', b'{}')
        self.w.audit_boot(self.fd, self.budget)
        self.w.audit_boot(self.fd, self.budget, sealed=True)
        with self.assertRaises(FileNotFoundError): self.w.read_at(self.fd, 'first-start-control.json', 4096)
        other = self.write('.first-start-ack.json.pending', b'{}')
        with self.assertRaises(RuntimeError): self.w.audit_boot(self.fd, self.budget, sealed=True)
        other.unlink()
        pending.unlink(); original = self.write('first-start-control.json', b'{}')
        retained = self.folder / 'retained-control'; os.link(original, retained)
        with self.assertRaises(RuntimeError): self.w.read_at(self.fd, 'first-start-control.json', 4096)
        original.unlink(); original.symlink_to(retained)
        with self.assertRaises((RuntimeError, OSError)): self.w.read_at(self.fd, 'first-start-control.json', 4096)
        self.assertEqual(retained.read_bytes(), b'{}')

    def test_same_named_boot_directory_substitution_preserves_both_original_and_replacement(self):
        self.write('challenge.json', b'{}'); moved = self.folder / 'retained-boot'; self.boot.rename(moved)
        self.boot.mkdir(mode=0o700)
        with self.assertRaises(RuntimeError): self.w.audit_boot(self.fd, self.budget)
        self.assertEqual((moved / 'challenge.json').read_bytes(), b'{}')
        self.assertEqual(list(self.boot.iterdir()), [])

    def test_real_metadata_fsync_failure_retains_owned_pending_and_does_not_publish(self):
        with patch.object(self.w.os, 'fsync', side_effect=OSError('owned fixture failure')):
            with self.assertRaises(OSError): self.w.publish_metadata(self.fd, 'consumed.json', b'{}', self.budget)
        self.assertEqual((self.boot / '.consumed.json.pending').read_bytes(), b'{}')
        self.assertFalse((self.boot / 'consumed.json').exists())

    def test_actual_native_files_journal_stays_unready_without_a_bound_native_observer(self):
        base = PACKAGE.parent / 'public-beta/runtime'
        files_module = load(base / 'native_files.py', 'first_start_actual_native_files')
        barrier_module = load(base / 'gateway_barrier.py', 'first_start_actual_native_barrier')
        native = self.folder / 'native'; native.mkdir(mode=0o700); files_module.ROOT = native
        room = str(uuid.uuid4())
        scope = {'appVariant': 'public-beta', 'policyId': 'public-disposable-beta-v1', 'environmentId': str(uuid.uuid4()),
            'dataEpoch': str(uuid.uuid4()), 'roomId': room, 'externalId': 'ap-beta-' + room + '-r1', 'allocationRevision': 1,
            'serverId': 'owned-fixture', 'attemptId': str(uuid.uuid4()), 'seedRevision': 1, 'credentialEpoch': 1,
            'runtimeLaunchId': str(uuid.uuid4())}
        owner = files_module.NativeFiles()
        try:
            owner.initialize(barrier_module.initial_state(scope))
            barrier = barrier_module.NativeBarrier(scope, 'a' * 32, owner.load_journal(), owner.commit_journal)
            self.assertFalse(barrier.state['ready'])
            with self.assertRaises(barrier_module.BarrierError): barrier.mark_ready()
            self.assertFalse(owner.load_journal()['ready'])
            self.assertEqual(owner.load_journal()['preparations'], {})
        finally: owner.close()


if __name__ == '__main__': unittest.main()

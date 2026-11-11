"""Synthetic custody fixtures. No AP engine, native serializer or provider."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import checkpoint_custody as custody
import native_files
from gateway_barrier import NativeBarrier, BarrierError, canonical, initial_state, iso

NOW = 1794400000000
MASTER = 'synthetic_private_master_' + 'x' * 40


def uid(): return str(uuid.uuid4())


def scope():
    room = uid()
    return {'appVariant': 'public-beta', 'policyId': 'public-disposable-beta-v1', 'environmentId': uid(), 'dataEpoch': uid(),
            'roomId': room, 'externalId': 'ap-beta-' + room + '-r1', 'allocationRevision': 1, 'serverId': 'synthetic_server',
            'attemptId': uid(), 'seedRevision': 1, 'credentialEpoch': 1, 'runtimeLaunchId': uid()}


def hold(identity, state, operation=None):
    operation = operation or uid()
    request = {**identity, 'schema': 'amz.ap.public-beta.idle-fence.v1', 'action': 'idle_sleep', 'operationId': operation,
               'expectedObservationRevision': 1, 'expectedConnectionGeneration': state['generation'],
               'provenInitialReadyAt': state['initialReadyAt'], 'provenLastDisconnectAt': state['lastDisconnectAt']}
    gate = {'id': uid(), 'operationId': operation, 'kind': 'idle',
            'requestSha256': hashlib.sha256((request['schema'] + '\n').encode() + canonical(request)).hexdigest()}
    return {'gate': gate, 'request': request}


class Owner:
    def __init__(self): self.value = None; self.fail = False; self._mutex = threading.RLock()
    def load_journal(self):
        if self.value is None: raise BarrierError('native_journal_missing')
        return copy.deepcopy(self.value)
    def commit_journal(self, value):
        self.value = copy.deepcopy(value)
        if self.fail: raise BarrierError('synthetic_lost_ack')


def fixture(connected=False):
    identity, owner = scope(), Owner()
    barrier = NativeBarrier(identity, MASTER, initial_state(identity), owner.commit_journal, clock=lambda: NOW)
    barrier.bind_observer(lambda: [])
    barrier.mark_ready()
    if connected:
        # Synthetic historic accepted connect/disconnect, not a native proof.
        barrier.state.update(generation=2, everConnected=True, initialReadyAt=None, lastDisconnectAt=iso(NOW - 1234))
        barrier._save()
    gate = hold(identity, barrier.state)
    barrier.control({'schema': 'amz.ap.public-beta.gateway-control.v2', 'operationId': uid(), 'command': 'idle_fence', 'identity': identity,
                     'gate': gate['gate'], 'payload': gate['request'], 'issuedAt': iso(NOW), 'expiresAt': iso(NOW + 7000)})
    files = object.__new__(custody.CustodyFiles)
    files.owner, files.raw = owner, None
    files.publish = lambda raw: setattr(files, 'raw', raw)
    files.read = lambda: files.raw
    seed, native = b'synthetic seed', b'synthetic native state'
    def capture(snapshot=lambda: native):
        return custody.capture(files, barrier, gate['gate'], checkpoint_id=uid(), seed_sha256=custody.sha(seed),
                               runtime_artifact_sha256='a' * 64, world_pack_sha256='b' * 64, native_snapshot=snapshot)
    return identity, owner, barrier, files, seed, native, gate, capture


def migration(f):
    identity, _, _, files, seed, _, _, _ = f
    header, _, journal = custody.decode_checkpoint(files.raw, custody.sha(files.raw))
    new = {**identity, 'runtimeLaunchId': uid(), 'credentialEpoch': 2}
    operation = uid()
    value = {'schema': custody.MIGRATION_SCHEMA, 'operationId': operation, 'oldIdentity': identity, 'newIdentity': new,
             'custodySha256': custody.sha(files.raw), 'seedArtifactSha256': custody.sha(seed),
             'nativeSaveSha256': header['nativeSaveSha256'], 'barrierSha256': header['barrierSha256'], 'idle': header['idle'],
             'stoppedBarrierSha256': custody.sha(canonical(files.owner.value)), 'stoppedBarrierRevision': files.owner.value['revision'], 'stoppedBarrierClockFloor': files.owner.value['clockFloor'],
             'runtimeArtifactSha256': header['runtimeArtifactSha256'], 'worldPackSha256': header['worldPackSha256'],
             'targetRuntimeArtifactSha256': 'c' * 64, 'targetWorldPackSha256': 'd' * 64, 'oldStopReceiptSha256': 'e' * 64,
             'newHold': hold(new, journal, operation), 'issuedAt': iso(NOW), 'expiresAt': iso(NOW + 300000)}
    return value


def resume(f, manifest=None, **changes):
    value = manifest or migration(f)
    f[3].migration = lambda expected: copy.deepcopy(value)
    options = {'expected_manifest_sha256': custody.sha(canonical(value)), 'seed': f[4], 'expected_stop_receipt_sha256': 'e' * 64,
               'expected_runtime_artifact_sha256': 'c' * 64, 'expected_world_pack_sha256': 'd' * 64, 'clock': lambda: NOW}
    options.update(changes)
    return custody.migrate(f[3], **options)


class CustodyProtocol(unittest.TestCase):
    def test_terminal_capture_closes_admission_and_binds_seed_save_barrier_and_original_idle(self):
        for connected in (False, True):
            f = fixture(connected); receipt = f[-1]()
            header, native, journal = custody.decode_checkpoint(f[3].raw, receipt['sha256'])
            self.assertEqual(native, f[5]); self.assertEqual(header['identity'], f[0])
            self.assertFalse(f[2].state['ready']); self.assertFalse(journal['ready'])
            self.assertEqual(header['idle'], custody.idle_basis(journal))
            self.assertEqual(header['gate'], f[6]['gate'])
            self.assertTrue(receipt['admissionHeld']); self.assertNotIn(MASTER, str(receipt))

    def test_failed_snapshot_leaves_durable_gate_and_admission_closed(self):
        f = fixture()
        with self.assertRaisesRegex(RuntimeError, 'snapshot failed'):
            f[-1](lambda: (_ for _ in ()).throw(RuntimeError('snapshot failed')))
        self.assertFalse(f[1].value['ready']); self.assertIn(f[6]['gate']['id'], f[1].value['gates'])
        self.assertIsNone(f[3].raw)

    def test_unknown_observer_or_pending_state_never_calls_serializer(self):
        for mutate in (lambda b: setattr(b, '_observe', lambda: None), lambda b: b._inflight.add(object()),
                       lambda b: b.state.update(uncertain=True), lambda b: b.state.update(ready=False)):
            f = fixture(); mutate(f[2]); calls = []
            with self.assertRaises(BarrierError): f[-1](lambda: calls.append(True) or b'bad')
            self.assertEqual(calls, []); self.assertIsNone(f[3].raw)

    def test_snapshot_cannot_change_generation_or_clock_history_mid_capture(self):
        f = fixture()
        def changed(): f[2].state['generation'] += 1; return b'changed'
        with self.assertRaises(BarrierError): f[-1](changed)
        self.assertFalse(f[2].state['ready']); self.assertIsNone(f[3].raw)

    def test_serializer_cannot_replace_the_durable_journal_behind_the_barrier(self):
        f = fixture()
        def changed(): f[1].value['revision'] += 1; return b'changed'
        with self.assertRaisesRegex(BarrierError, 'state_changed'): f[-1](changed)
        self.assertFalse(f[2].state['ready']); self.assertIsNone(f[3].raw)

    def test_tampered_truncated_extra_bytes_or_noncanonical_container_refuses(self):
        f = fixture(); f[-1](); raw = f[3].raw
        for bad in (raw[:-1], raw + b'x', b'OTHER' + raw, raw[:8] + b'broken' + raw[14:]):
            with self.assertRaises(BarrierError): custody.decode_checkpoint(bad, custody.sha(bad))
        with self.assertRaises(BarrierError): custody.decode_checkpoint(raw, '0' * 64)
        with self.assertRaises(BarrierError): custody.encode_checkpoint({}, b'x' * custody.MAXIMUM, {})

    def test_explicit_migration_preserves_both_idle_histories_and_new_hold_without_admission(self):
        for connected in (False, True):
            f = fixture(connected); f[-1](); manifest = migration(f); result = resume(f, manifest)
            state = result['state']; self.assertEqual(state['identity'], manifest['newIdentity'])
            self.assertEqual(custody.idle_basis(state), manifest['idle']); self.assertFalse(state['ready'] or state['uncertain'])
            self.assertEqual(state['preparations'], {}); self.assertEqual(state['controls'], {})
            self.assertEqual(state['gates'], {manifest['newHold']['gate']['id']: manifest['newHold']})
            self.assertEqual(result['nativeSave'], f[5]); self.assertTrue(result['admissionHeld'])
            # Exact lost-ACK replay is idempotent; current progress is not.
            self.assertEqual(resume(f, manifest)['state'], state)
            f[1].value['revision'] += 1
            with self.assertRaisesRegex(BarrierError, 'journal_changed'): resume(f, manifest)

    def test_wrong_epoch_run_seed_stop_pin_target_pin_or_original_idle_cannot_migrate(self):
        changes = [lambda v: v.update(oldStopReceiptSha256='f' * 64), lambda v: v['newIdentity'].update(dataEpoch=uid()),
                   lambda v: v['newIdentity'].update(attemptId=uid()), lambda v: v['newIdentity'].update(seedRevision=2),
                   lambda v: v['newIdentity'].update(credentialEpoch=1), lambda v: v.update(seedArtifactSha256='f' * 64),
                   lambda v: v.update(targetWorldPackSha256='f' * 64), lambda v: v.update(nativeSaveSha256='f' * 64),
                   lambda v: v['idle'].update(provenInitialReadyAt=iso(NOW + 1)), lambda v: v.update(expiresAt=iso(NOW))]
        for change in changes:
            f = fixture(); f[-1](); old = copy.deepcopy(f[1].value); value = migration(f); change(value)
            with self.subTest(change=changes.index(change)), self.assertRaises(BarrierError): resume(f, value)
            self.assertEqual(f[1].value, old)

    def test_graceful_stop_successor_needs_its_own_exact_pin_and_cannot_change_native_progress(self):
        f = fixture(True); f[-1](); before_stop = migration(f)
        f[2].shutdown()  # Exact native shutdown advances only terminal journal.
        with self.assertRaisesRegex(BarrierError, 'journal_changed'): resume(f, before_stop)
        after_stop = migration(f)
        self.assertTrue(resume(f, after_stop)['admissionHeld'])
        f = fixture(True); f[-1](); f[1].value['generation'] += 1
        changed = migration(f)
        with self.assertRaises(BarrierError): resume(f, changed)

    def test_missing_journal_never_initializes_and_unknown_commit_never_returns_success(self):
        f = fixture(); f[-1](); value = migration(f); original = copy.deepcopy(f[1].value)
        f[1].value = None
        with self.assertRaisesRegex(BarrierError, 'journal_missing'): resume(f, value)
        self.assertIsNone(f[1].value)
        f[1].value = original; f[1].fail = True
        with self.assertRaisesRegex(BarrierError, 'lost_ack'): resume(f, value)
        f[1].fail = False
        self.assertTrue(resume(f, value)['admissionHeld'])

    def test_approval_expiry_during_read_prevents_commit_and_expiry_during_commit_returns_no_proof(self):
        f = fixture(); f[-1](); value = migration(f); original = copy.deepcopy(f[1].value); time = [NOW]
        def delayed_read(): time[0] = NOW + 300000; return f[3].raw
        f[3].read = delayed_read
        with self.assertRaisesRegex(BarrierError, 'expired_or_clock_changed'): resume(f, value, clock=lambda: time[0])
        self.assertEqual(f[1].value, original)
        f = fixture(); f[-1](); value = migration(f); time[0] = NOW
        commit = f[1].commit_journal
        def delayed_commit(state): commit(state); time[0] = NOW + 300000
        f[1].commit_journal = delayed_commit
        with self.assertRaisesRegex(BarrierError, 'expired_or_clock_changed'): resume(f, value, clock=lambda: time[0])
        self.assertFalse(f[1].value['ready']); self.assertTrue(f[1].value['gates'])

    def test_clock_rollback_after_read_never_reopens_the_journal(self):
        f = fixture(); f[-1](); value = migration(f); original = copy.deepcopy(f[1].value); time = [NOW]
        def rollback_read(): time[0] = NOW - 1; return f[3].raw
        f[3].read = rollback_read
        with self.assertRaisesRegex(BarrierError, 'expired_or_clock_changed'): resume(f, value, clock=lambda: time[0])
        self.assertEqual(f[1].value, original)


@unittest.skipUnless(sys.platform == 'linux', 'Custody directory fsync/ownership fixtures require Linux')
class CustodyFilesystem(unittest.TestCase):
    def test_fixed_binary_publication_and_protected_migration_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            with patch.object(native_files, 'ROOT', root):
                owner = native_files.NativeFiles()
                try:
                    files = custody.CustodyFiles(owner); raw = b'synthetic private custody'
                    self.assertEqual(files.publish(raw), custody.sha(raw)); self.assertEqual(files.read(), raw)
                    self.assertEqual((root / custody.CUSTODY).stat().st_mode & 0o777, 0o600)
                    value = {'schema': 'synthetic-protected-manifest'}; encoded = canonical(value)
                    (root / custody.MIGRATION).write_bytes(encoded); (root / custody.MIGRATION).chmod(0o600)
                    self.assertEqual(files.migration(custody.sha(encoded)), value)
                    with self.assertRaises(BarrierError): files.migration('0' * 64)
                finally: owner.close()

    def test_uncertain_directory_fsync_retains_owner_and_pending_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            with patch.object(native_files, 'ROOT', root):
                owner = native_files.NativeFiles(); files = custody.CustodyFiles(owner)
                try:
                    with patch.object(custody.os, 'fsync', side_effect=OSError('synthetic fsync failure')):
                        with self.assertRaises(OSError): files.publish(b'private synthetic bytes')
                    self.assertTrue(owner._uncertain)
                    self.assertTrue(list(root.glob('.' + custody.CUSTODY + '.pending-*')))
                finally:
                    with self.assertRaises(Exception): owner.close()
                self.assertTrue((root / native_files.LOCK).exists())


if __name__ == '__main__': unittest.main()

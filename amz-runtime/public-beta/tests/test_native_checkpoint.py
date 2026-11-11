"""Local codec/control fixtures; no engine, real game or provider operations."""
import copy
import json
from pathlib import Path
import pickle
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import native_checkpoint as checkpoint
import native_files
from gateway_barrier import BarrierError, canonical, iso
from test_checkpoint_custody import fixture, NOW, uid


def snapshots(f):
    writes, values = [], []
    class Context:
        auto_saver_thread, save_dirty = None, True
        def get_save(self):
            values.append(True)
            return {'version': 1, 'connect_names': {'p_1': (0, 1)}, 'received_items': {(0, 1): [1, 2]}, 'native_synthetic': True}
    value = object.__new__(checkpoint.NativeSnapshots)
    value.owner, value.context = f[1], Context()
    value.files = type('SyntheticPrivateWriter', (), {'write': lambda self, raw: writes.append(raw)})()
    value.thread, value.sealed, value.due = threading.get_ident(), False, 60
    time = [0.0]; value.monotonic = lambda: time[0]
    return value, writes, values, time


def control_fixture():
    f = fixture(); saver, writes, values, monotonic = snapshots(f)
    owner, records, events, wall = f[1], {}, [], [NOW]
    owner._active = lambda: None
    owner._read = lambda name, maximum, optional=False: None if name not in records else (copy.deepcopy(records[name]), (), bytes.fromhex(checkpoint.sha(canonical(records[name]))))
    def replace(name, raw, maximum, previous):
        events.append((name, json.loads(raw)))
        records[name] = json.loads(raw)
    owner._replace = replace
    control = object.__new__(checkpoint.RuntimeControl)
    control.owner, control.barrier, control.snapshots, control.custody = owner, f[2], saver, f[3]
    control.config = {'seedArtifactSha256': checkpoint.sha(f[4]), 'runtimeArtifactSha256': 'a' * 64, 'worldPackSha256': 'b' * 64}
    control.clock, control.last = lambda: wall[0], None
    control.monotonic = lambda: monotonic[0]
    control.deadline, control.monotonic_floor, control.command_sha = None, None, None
    records[checkpoint.CONTROL] = {'schema': checkpoint.SCHEMA, 'operationId': uid(), 'command': 'checkpoint_and_hold', 'identity': f[0],
                                  'gate': f[6]['gate'], 'issuedAt': iso(NOW), 'expiresAt': iso(NOW + 8000)}
    return f, control, records, events, writes, values, wall


class Codec(unittest.TestCase):
    def test_native_default_pickle_zlib_bytes_and_explicit_restricted_decoder(self):
        value = {'version': 1, 'tuple': (1, 2), 'set': {3, 4}, 'nested': {('p', 1): b'private synthetic data'}}
        raw = checkpoint.encode_native(value)
        self.assertEqual(zlib.decompress(raw), pickle.dumps(value))
        seen = []
        def restricted(data): seen.append(data); return pickle.loads(data)  # Synthetic stdlib types only.
        self.assertEqual(checkpoint.decode_native(raw, restricted), value)
        self.assertEqual(seen, [pickle.dumps(value)])

    def test_bomb_trailing_truncated_and_wrong_schema_never_reach_decoder(self):
        calls = []
        valid = checkpoint.encode_native({'native': True})
        for raw in (valid[:-1], valid + b'extra', zlib.compress(pickle.dumps({}) + b'extra'), zlib.compress(b'x' * 2048)):
            with patch.object(checkpoint, 'MAX_EXPANDED', 1024), self.assertRaises(BarrierError):
                checkpoint.decode_native(raw, lambda data: calls.append(data) or {})
        self.assertEqual(calls, [])
        with self.assertRaises(BarrierError): checkpoint.decode_native(valid, None)
        with self.assertRaises(BarrierError): checkpoint.decode_native(valid, lambda _: [])
        with patch.object(checkpoint, 'MAX_EXPANDED', 16), self.assertRaises(BarrierError): checkpoint.encode_native({'value': 'x' * 32})
        with patch.object(checkpoint, 'MAX_SAVE', 16), self.assertRaises(BarrierError): checkpoint.encode_native({'value': bytes(range(64))})


class SerializedPeriodicSave(unittest.TestCase):
    def test_active_dirty_periodic_save_is_retained_at_60_seconds_without_threads_or_timers(self):
        f = fixture(); saver, writes, values, clock = snapshots(f)
        self.assertTrue(saver.save_now()); self.assertEqual(len(writes), 1); self.assertFalse(saver.context.save_dirty)
        saver.context.save_dirty = True; clock[0] = 59.999
        self.assertFalse(saver.periodic()); self.assertEqual(len(values), 1)
        clock[0] = 60; self.assertTrue(saver.periodic()); self.assertEqual(len(values), 2)
        clock[0] = 120; self.assertFalse(saver.periodic()); self.assertIsNone(saver.context.auto_saver_thread)

    def test_native_thread_or_cross_thread_save_is_refused(self):
        f = fixture(); saver, writes, _, _ = snapshots(f)
        saver.context.auto_saver_thread = object()
        with self.assertRaises(BarrierError): saver.save_now()
        saver.context.auto_saver_thread = None; saver.thread += 1
        with self.assertRaises(BarrierError): saver.save_now()
        self.assertEqual(writes, [])

    def test_periodic_save_stays_dirty_on_failure_and_terminal_capture_suppresses_further_writes(self):
        f = fixture(); saver, writes, _, clock = snapshots(f)
        saver.context.save_dirty = False  # Native save(now=True) clears it first.
        with patch.object(saver.files, 'write', side_effect=OSError('synthetic write failure')):
            with self.assertRaises(OSError): saver.save_now()
        self.assertTrue(saver.context.save_dirty)
        result = saver.checkpoint(f[3], f[2], f[6]['gate'], checkpoint_id=uid(), seed_sha256=checkpoint.sha(f[4]), runtime_artifact_sha256='a' * 64, world_pack_sha256='b' * 64)
        self.assertTrue(result['admissionHeld']); self.assertTrue(saver.sealed); self.assertFalse(f[2].state['ready'])
        count = len(writes); saver.context.save_dirty = True; clock[0] = 1000
        self.assertFalse(saver.periodic()); self.assertTrue(saver.save_now()); self.assertEqual(len(writes), count)


class TerminalControl(unittest.TestCase):
    def test_durable_intent_precedes_native_snapshot_and_ack_contains_metadata_only(self):
        f, control, records, events, writes, values, _ = control_fixture()
        original = control.snapshots.context.get_save
        def snapshot():
            self.assertEqual(records[checkpoint.OPERATION]['phase'], 'preparing')
            self.assertFalse(f[2].state['ready']); return original()
        control.snapshots.context.get_save = snapshot
        self.assertTrue(control.poll_once()); self.assertEqual(len(values), 1); self.assertEqual(len(writes), 1)
        self.assertEqual([name for name, _ in events], [checkpoint.OPERATION, checkpoint.OPERATION, checkpoint.ACK])
        self.assertEqual(records[checkpoint.OPERATION]['phase'], 'sealed')
        ack = records[checkpoint.ACK]; self.assertEqual(ack['result']['state'], 'sealed'); self.assertTrue(ack['result']['admissionHeld'])
        self.assertNotIn('native_synthetic', str(ack)); self.assertFalse(control.poll_once())

    def test_lost_ack_replays_exact_durable_outcome_without_rerunning_snapshot(self):
        _, control, records, _, _, values, _ = control_fixture()
        replace = control.owner._replace
        def lost(name, *args):
            if name == checkpoint.ACK: raise OSError('synthetic lost ack')
            return replace(name, *args)
        control.owner._replace = lost
        with self.assertRaises(OSError): control.poll_once()
        self.assertEqual(records[checkpoint.OPERATION]['phase'], 'sealed'); self.assertEqual(len(values), 1)
        control.owner._replace = replace; self.assertTrue(control.poll_once()); self.assertEqual(len(values), 1)
        self.assertEqual(records[checkpoint.ACK]['result']['state'], 'sealed')

    def test_failed_snapshot_is_unknown_held_and_never_automatically_retried(self):
        f, control, records, _, _, values, _ = control_fixture()
        with patch.object(control.snapshots.files, 'write', side_effect=OSError('synthetic IO failure')):
            with self.assertRaises(OSError): control.poll_once()
        self.assertEqual(records[checkpoint.OPERATION]['phase'], 'unknown'); self.assertFalse(f[2].state['ready'])
        self.assertNotIn(checkpoint.ACK, records); self.assertEqual(len(values), 1)
        self.assertTrue(control.poll_once()); self.assertEqual(len(values), 1)
        self.assertEqual(records[checkpoint.ACK]['result']['state'], 'unknown')

    def test_expiry_after_snapshot_cannot_publish_a_sealed_ack(self):
        f, control, records, _, _, _, wall = control_fixture()
        publish = f[3].publish
        def delayed(raw): publish(raw); wall[0] = NOW + 8000
        f[3].publish = delayed
        with self.assertRaisesRegex(BarrierError, 'expired'): control.poll_once()
        self.assertEqual(records[checkpoint.OPERATION]['phase'], 'unknown')
        self.assertNotIn(checkpoint.ACK, records); self.assertFalse(f[2].state['ready'])

    def test_slow_snapshot_cannot_extend_lifetime_when_wall_clock_stays_in_window(self):
        f, control, records, _, _, _, wall = control_fixture()
        publish = f[3].publish
        def delayed(raw):
            publish(raw); wall[0] = NOW + 2000; control.monotonic = lambda: 10.0
        f[3].publish = delayed
        with self.assertRaisesRegex(BarrierError, 'expired'): control.poll_once()
        self.assertEqual(records[checkpoint.OPERATION]['phase'], 'unknown')
        self.assertNotIn(checkpoint.ACK, records); self.assertFalse(f[2].state['ready'])

    def test_lost_ack_replay_retains_original_monotonic_deadline(self):
        f, control, records, _, _, values, wall = control_fixture()
        replace = control.owner._replace
        def lost(name, *args):
            if name == checkpoint.ACK: raise OSError('synthetic lost ack')
            return replace(name, *args)
        control.owner._replace = lost
        with self.assertRaises(OSError): control.poll_once()
        self.assertEqual(control.deadline, 8.0)
        control.owner._replace = replace; control.monotonic = lambda: 8.0; wall[0] = NOW + 1000
        with self.assertRaisesRegex(BarrierError, 'expired'): control.poll_once()
        self.assertEqual(control.deadline, 8.0); self.assertEqual(len(values), 1)
        self.assertEqual(records[checkpoint.OPERATION]['phase'], 'sealed')
        self.assertNotIn(checkpoint.ACK, records); self.assertFalse(f[2].state['ready'])

    def test_wrong_scope_conflicting_id_or_expired_control_makes_no_mutation(self):
        for change in (lambda c: c.update(command='resume'), lambda c: c['identity'].update(dataEpoch=uid()), lambda c: c.update(expiresAt=iso(NOW))):
            _, control, records, events, writes, values, _ = control_fixture(); change(records[checkpoint.CONTROL])
            with self.assertRaises(BarrierError): control.poll_once()
            self.assertEqual((events, writes, values), ([], [], []))


@unittest.skipUnless(sys.platform == 'linux', 'Actual atomic native save fsync/ownership requires Linux')
class BinarySaveFilesystem(unittest.TestCase):
    def test_native_save_publication_readback_and_uncertain_write_retains_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            with patch.object(native_files, 'ROOT', root):
                owner = native_files.NativeFiles()
                try:
                    files = checkpoint.NativeSaveFiles(owner); raw = checkpoint.encode_native({'native': 'synthetic'})
                    files.write(raw); self.assertEqual(files.read()[0], raw)
                    self.assertEqual((root / checkpoint.SAVE).stat().st_mode & 0o777, 0o600)
                    with patch.object(checkpoint.os, 'fsync', side_effect=OSError('synthetic fsync failure')):
                        with self.assertRaises(OSError): files.write(raw)
                    self.assertTrue(owner._uncertain)
                finally:
                    with self.assertRaises(Exception): owner.close()
                self.assertTrue((root / native_files.LOCK).exists())


if __name__ == '__main__': unittest.main()

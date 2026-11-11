"""Held restore composition fixtures. No engine, server, provider or listener."""
import copy
import logging
from pathlib import Path
import pickle
import sys
import threading
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import native_restore as restore
from gateway_barrier import BarrierError
from native_checkpoint import NativeSnapshots, encode_native, decode_native
from native_files import NativeFiles
from test_checkpoint_custody import fixture, migration, NOW, MASTER

PROFILE = (Path(__file__).resolve().parents[1] / 'runtime/native-restore-profile.v1.json').read_bytes()
NEW_MASTER = 'synthetic_rotated_master_' + 'y' * 40


def restore_fixture(connected=True):
    f = fixture(connected)
    owner = object.__new__(NativeFiles)
    owner._mutex, owner._uncertain, owner._durable = f[1]._mutex, False, object()
    def active():
        if owner._uncertain: raise BarrierError('synthetic_owner_unknown')
    owner._active = active
    owner.commit_journal, owner.load_journal = f[1].commit_journal, f[1].load_journal
    options = dict(hint_cost=10, location_check_points=1, server_password='', password=MASTER,
                   release_mode='goal', remaining_mode='goal', collect_mode='disabled', countdown_mode='disabled', item_cheat=True, compatibility=1)
    value = dict(version=2, connect_names={'Alice': (0, 1)}, received_items={(0, 1, True): [(42, 7, 1, 0)]}, hints_used={}, hints={},
                 location_checks={(0, 1): {7}}, name_aliases={}, client_game_state={(0, 1): 10}, client_activity_timers=(),
                 client_connection_timers=(), random_state=(3, (1, 2), None), group_collected={}, stored_data={'progress': [1, 2]}, game_options=options)
    f[-1](lambda: encode_native(value))
    manifest = migration(f)
    f[3].owner = owner
    f[3].migration = lambda expected: copy.deepcopy(manifest)
    counts, writes, wall, mono = [], [], [NOW], [10.0]
    class Context:
        save_version, auto_saver_thread, server, item_cheat, log_network, save_dirty = 2, None, None, False, False, True
        password, server_password = NEW_MASTER, ''
        connect_names, games, endpoints, clients = {'Alice': (0, 1)}, {1: 'Yacht Dice'}, [], {}
        exit_event = SimpleNamespace(is_set=lambda: False)
        current = None
        def set_save(self, value):
            counts.append(copy.deepcopy(value)); self.current = copy.deepcopy(value)
            self.password, self.server_password, self.item_cheat = (value['game_options'][field] for field in ('password', 'server_password', 'item_cheat'))
        def get_save(self):
            return copy.deepcopy(self.current)
    class SaveFiles:
        def write(self, raw): writes.append(bytes(raw))
        def read(self): return writes[-1], ()
    snapshots = object.__new__(NativeSnapshots)
    snapshots.owner, snapshots.context, snapshots.files = owner, Context(), SaveFiles()
    snapshots.thread, snapshots.sealed, snapshots.monotonic, snapshots.due = threading.get_ident(), False, lambda: mono[0], 60
    decoded = []
    def restricted(raw):
        # Synthetic stdlib values only. Actual verified Utils.restricted_loads
        # is mandatory in the later engine composition, never imported here.
        decoded.append(True); return pickle.loads(raw)
    params = dict(profile=PROFILE, expected_profile_sha256=restore.PROFILE_SHA256,
                  expected_manifest_sha256=restore.sha(restore.canonical(manifest)), seed=f[4],
                  expected_stop_receipt_sha256='e' * 64, expected_runtime_artifact_sha256='c' * 64,
                  expected_world_pack_sha256='d' * 64, expected_identity=manifest['newIdentity'], new_master=NEW_MASTER,
                  restricted_loads=restricted, clock=lambda: wall[0], monotonic=lambda: mono[0])
    return SimpleNamespace(f=f,owner=owner,snapshots=snapshots,manifest=manifest,value=value,counts=counts,writes=writes,decoded=decoded,
                           wall=wall,mono=mono,params=params,run=lambda **changes: restore.restore_native(f[3], snapshots, **{**params, **changes}))


class RestrictedHeldRestore(unittest.TestCase):
    def test_explicit_separate_profile_binds_exact_fresh_source_and_keeps_all_acceptance_closed(self):
        import json
        profile = json.loads(PROFILE)
        self.assertEqual(restore.sha(PROFILE), restore.PROFILE_SHA256)
        self.assertEqual(profile['freshRuntimeSourceCommit'], '79e2b0d293d9d6f1f12ee05d6bfe8cb13fd6392e')
        self.assertEqual(profile['multiServerLfSha256'], 'e157abab8a56351d58f1cf5a84c6c2a9144d295956d6be08cbd5811c7a2932de')
        self.assertTrue(profile['sourceOnly']); self.assertTrue(all(value is False for value in profile['qualification'].values()))
        x = restore_fixture()
        with self.assertRaisesRegex(BarrierError, 'profile_required'): x.run(expected_profile_sha256='f' * 64)
        self.assertFalse(x.owner._uncertain); self.assertEqual(x.counts, [])

    def test_restricted_decode_native_set_save_and_atomic_writer_preserve_progress_but_rotate_secrets(self):
        for connected in (False, True):
            x = restore_fixture(connected)
            result = x.run()
            try:
                self.assertEqual(len(x.counts), 1); self.assertEqual(len(x.writes), 1); self.assertEqual(len(x.decoded), 2)
                loaded = decode_native(x.writes[0], pickle.loads)
                for field in restore.SAVE_FIELDS:
                    if field != 'game_options': self.assertEqual(loaded[field], x.value[field])
                self.assertEqual(loaded['game_options']['password'], NEW_MASTER)
                self.assertEqual(loaded['game_options']['server_password'], '')
                self.assertIs(loaded['game_options']['item_cheat'], False)
                self.assertEqual(x.value['game_options']['password'], MASTER)  # Captured object was not rewritten.
                self.assertEqual(result.state['identity'], x.manifest['newIdentity'])
                self.assertEqual(result.receipt['idle'], x.manifest['idle'])
                self.assertEqual(result.receipt['migrationSha256'], x.params['expected_manifest_sha256'])
                self.assertEqual(result.receipt['oldStopReceiptSha256'], x.params['expected_stop_receipt_sha256'])
                self.assertEqual(result.receipt['runtimeArtifactSha256'], x.params['expected_runtime_artifact_sha256'])
                self.assertEqual(result.receipt['worldPackSha256'], x.params['expected_world_pack_sha256'])
                self.assertFalse(result.state['ready'] or result.state['uncertain'])
                self.assertEqual(result.state['gates'], {x.manifest['newHold']['gate']['id']: x.manifest['newHold']})
                self.assertTrue(result.receipt['admissionHeld']); self.assertEqual(result.receipt['state'], 'restored_held')
                self.assertNotIn(MASTER, str(result.receipt)); self.assertNotIn(NEW_MASTER, str(result.receipt))
                state = result.state; state['ready'] = True
                self.assertFalse(result.state['ready']); self.assertFalse(x.owner.load_journal()['ready'])
                with self.assertRaisesRegex(BarrierError, 'composition_required'): x.run()
                self.assertEqual(len(x.counts), 1)
            finally: result.close()

    def test_no_missing_journal_stop_seed_identity_or_master_fallback(self):
        for mode in ('journal', 'stop', 'seed', 'epoch', 'master'):
            x = restore_fixture()
            changes = {}
            if mode == 'journal': x.f[1].value = None
            elif mode == 'stop': changes['expected_stop_receipt_sha256'] = 'f' * 64
            elif mode == 'seed': changes['seed'] = b'other seed'
            elif mode == 'epoch':
                changes['expected_identity'] = {**x.params['expected_identity'], 'seedRevision': 2}
            elif mode == 'master':
                changes['new_master'] = MASTER; x.snapshots.context.password = MASTER
            with self.subTest(mode=mode), self.assertRaisesRegex(BarrierError, '^native_restore_refused$'): x.run(**changes)
            self.assertEqual(x.counts, []); self.assertEqual(x.writes, [])
            self.assertTrue(x.owner._uncertain and x.snapshots.sealed)

    def test_native_listener_client_or_saver_precludes_restore_before_any_decode(self):
        for change in (lambda c: setattr(c, 'server', object()), lambda c: c.endpoints.append(object()),
                       lambda c: setattr(c, 'auto_saver_thread', object()), lambda c: c.clients.update({0: {1: [object()]}})):
            x = restore_fixture(); x.snapshots.context.endpoints = []; x.snapshots.context.clients = {}; change(x.snapshots.context)
            with self.assertRaisesRegex(BarrierError, '^native_restore_refused$'): x.run()
            self.assertEqual((x.decoded, x.counts, x.writes), ([], [], [])); self.assertTrue(x.owner._uncertain)

    def test_wrong_slot_version_or_schema_never_reaches_native_set_save(self):
        for field, changed in (('version', 3), ('connect_names', {'Other': (0, 1)}), ('unexpected', True)):
            x = restore_fixture()
            def wrong(_raw): return {**x.value, field: changed}
            with self.assertRaisesRegex(BarrierError, '^native_restore_refused$'): x.run(restricted_loads=wrong)
            self.assertEqual(x.counts, []); self.assertFalse(x.owner.load_journal()['ready']); self.assertTrue(x.owner._uncertain)

    def test_partial_native_or_save_failure_retains_migrated_hold_without_success_or_retry(self):
        for mode in ('native', 'writer'):
            x = restore_fixture()
            def fail(_value): raise RuntimeError('synthetic private failure ' + MASTER + NEW_MASTER)
            if mode == 'native': x.snapshots.context.set_save = fail
            else: x.snapshots.files.write = fail
            with self.assertRaisesRegex(BarrierError, '^native_restore_refused$') as error: x.run()
            self.assertNotIn(MASTER, str(error.exception)); self.assertNotIn(NEW_MASTER, str(error.exception))
            self.assertTrue(x.owner._uncertain and x.snapshots.sealed); self.assertFalse(x.owner.load_journal()['ready'])
            self.assertEqual(x.owner.load_journal()['gates'], {x.manifest['newHold']['gate']['id']: x.manifest['newHold']})
            with self.assertRaisesRegex(BarrierError, 'composition_required'): x.run()

    def test_expiry_after_native_or_write_io_and_monotonic_overrun_returns_no_restore_receipt(self):
        for mode in ('native', 'writer', 'monotonic'):
            x = restore_fixture()
            target, original = (x.snapshots.context, x.snapshots.context.set_save) if mode != 'writer' else (x.snapshots.files, x.snapshots.files.write)
            def delayed(value):
                original(value)
                if mode == 'monotonic': x.mono[0] += 300
                else: x.wall[0] += 300000
            if mode == 'writer': target.write = delayed
            else: target.set_save = delayed
            with self.assertRaisesRegex(BarrierError, '^native_restore_refused$'): x.run()
            self.assertTrue(x.owner._uncertain and x.snapshots.sealed); self.assertFalse(x.owner.load_journal()['ready'])
            if mode != 'writer': self.assertEqual(x.writes, [])

    def test_both_master_values_are_redacted_before_native_restore_can_log_or_throw(self):
        x = restore_fixture(); messages = []
        original = x.snapshots.context.set_save
        def logging_restore(value):
            record = logging.getLogRecordFactory()('fixture', logging.WARNING, 'synthetic', 1,
                                                   'private %s / %s', (MASTER, NEW_MASTER), None)
            messages.append(record.getMessage()); original(value)
        x.snapshots.context.set_save = logging_restore
        before = logging.getLogRecordFactory(); result = x.run()
        try:
            self.assertEqual(messages, ['private [REDACTED] / [REDACTED]'])
        finally: result.close(); result.close()
        self.assertIs(logging.getLogRecordFactory(), before)


if __name__ == '__main__': unittest.main()

"""Explicit held native restore primitive; no engine import or entrypoint.

The separately reviewed restore composition must verify all source/engine,
protected configuration, seed and old-process stop inputs before calling this.
The existing fresh loader never imports or registers this separate profile.
"""
import copy
import hashlib
import hmac
import math
import re
import threading
import weakref

from checkpoint_custody import CustodyFiles, migrate
from gateway_barrier import BarrierError, canonical, identity, instant, integer, require
from gateway_hooks import install_log_redaction
from native_checkpoint import NativeSnapshots, decode_native
from native_files import NativeFiles

PROFILE_SHA256 = 'e573463a5f570e607c0d14289a2e47e5f1715b9c7960d61546ddd147accdb414'
SAVE_FIELDS = ('version', 'connect_names', 'received_items', 'hints_used', 'hints', 'location_checks', 'name_aliases',
               'client_game_state', 'client_activity_timers', 'client_connection_timers', 'random_state',
               'group_collected', 'stored_data', 'game_options')
OPTION_FIELDS = ('hint_cost', 'location_check_points', 'server_password', 'password', 'release_mode',
                 'remaining_mode', 'collect_mode', 'countdown_mode', 'item_cheat', 'compatibility')
_attempts = weakref.WeakSet()


def sha(raw): return hashlib.sha256(raw).hexdigest()


class RestoredNative:
    """Private result, held throughout. Keep old-secret redaction until drain.

    This is not an operator stop, native listener, Play or reopen authority.
    Returned state copies cannot mutate the durable journal behind the owner.
    """
    def __init__(self, state, receipt, stop_redaction):
        self._state, self._receipt = copy.deepcopy(state), copy.deepcopy(receipt)
        self._stop_redaction = stop_redaction

    @property
    def state(self): return copy.deepcopy(self._state)

    @property
    def receipt(self): return copy.deepcopy(self._receipt)

    def close(self):
        if self._stop_redaction is not None:
            self._stop_redaction(); self._stop_redaction = None


def restore_native(files, snapshots, *, profile, expected_profile_sha256, expected_manifest_sha256,
                   seed, expected_stop_receipt_sha256, expected_runtime_artifact_sha256,
                   expected_world_pack_sha256, expected_identity, new_master, restricted_loads, clock, monotonic):
    """Protected synchronous startup only, before listener/handlers exist.

    No missing-journal bootstrap, native init_save fallback, injected serializer,
    automatic retry or reopen. The restricted decoder is the actual verified
    Utils.restricted_loads selected by the future verified-source composition.
    Failure retains unknown owner state; it does not undo a durable migration.
    """
    require(type(profile) is bytes and expected_profile_sha256 == PROFILE_SHA256 and sha(profile) == PROFILE_SHA256,
            'native_restore_profile_required')
    require(type(files) is CustodyFiles and type(files.owner) is NativeFiles and type(snapshots) is NativeSnapshots and
            snapshots.owner is files.owner and snapshots not in _attempts and not snapshots.sealed and
            threading.get_ident() == snapshots.thread and callable(restricted_loads) and callable(clock) and callable(monotonic),
            'native_restore_composition_required')
    expected_identity = identity(expected_identity)
    require(type(new_master) is str and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', new_master), 'native_restore_master_required')
    context, owner, stop_redaction = snapshots.context, files.owner, None
    _attempts.add(snapshots)
    try:
        with owner._mutex:
            stop_new_redaction = install_log_redaction(new_master)
            stop_redaction = stop_new_redaction
            owner._active()
            require(context.auto_saver_thread is None and callable(context.set_save) and context.server is None and
                    not context.endpoints and not context.exit_event.is_set() and
                    all(not clients for slots in context.clients.values() for clients in slots.values()) and
                    hmac.compare_digest(context.password, new_master) and context.server_password == '' and
                    context.item_cheat is False and context.log_network is False, 'native_restore_not_quiescent')
            require(type(context.connect_names) is dict and 1 <= len(context.connect_names) <= 16 and
                    all(type(alias) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,16}', alias) and type(slot) is tuple and len(slot) == 2 and
                        slot[0] == 0 and integer(slot[1], 1, 16) for alias, slot in context.connect_names.items()) and
                    set(context.games.values()) == {'Yacht Dice'}, 'native_restore_seed_binding')
            manifest = files.migration(expected_manifest_sha256)
            # The existing migrator independently rereads/hash-verifies this
            # fixed manifest; both observations must match the external pin.
            require(sha(canonical(manifest)) == expected_manifest_sha256 and manifest['newIdentity'] == expected_identity,
                    'native_restore_migration_changed')
            floor, mono_floor = clock(), monotonic()
            require(integer(floor, 1) and type(mono_floor) in (int, float) and math.isfinite(mono_floor) and
                    instant(manifest['issuedAt']) <= floor < instant(manifest['expiresAt']) and
                    0 < instant(manifest['expiresAt']) - instant(manifest['issuedAt']) <= 300000, 'native_restore_expired')
            deadline = mono_floor + (instant(manifest['expiresAt']) - floor) / 1000
            def current():
                nonlocal floor, mono_floor
                observed, mono = clock(), monotonic()
                require(integer(observed, floor) and instant(manifest['issuedAt']) <= observed < instant(manifest['expiresAt']) and
                        type(mono) in (int, float) and math.isfinite(mono) and mono_floor <= mono < deadline,
                        'native_restore_expired')
                floor, mono_floor = observed, mono
                owner._active()
                return observed
            current()
            restored = migrate(files, expected_manifest_sha256=expected_manifest_sha256, seed=seed,
                               expected_stop_receipt_sha256=expected_stop_receipt_sha256,
                               expected_runtime_artifact_sha256=expected_runtime_artifact_sha256,
                               expected_world_pack_sha256=expected_world_pack_sha256, clock=current)
            current()
            state = restored['state']
            require(state['identity'] == expected_identity and not state['ready'] and not state['uncertain'] and
                    canonical(owner.load_journal()) == canonical(state), 'native_restore_journal_changed')
            # Bounded zlib/pickle parsing happens only after the protected
            # migration established a durable new-identity idle hold.
            saved = decode_native(restored['nativeSave'], restricted_loads)
            current()
            require(type(saved) is dict and set(saved) == set(SAVE_FIELDS) and type(saved['version']) is int and
                    saved['version'] == context.save_version and saved['connect_names'] == context.connect_names and
                    type(saved['game_options']) is dict and set(saved['game_options']) == set(OPTION_FIELDS), 'native_restore_save_schema')
            old_master = saved['game_options']['password']
            require(type(old_master) is str and re.fullmatch(r'[A-Za-z0-9_-]{32,128}', old_master) and
                    not hmac.compare_digest(old_master, new_master) and saved['game_options']['server_password'] == '',
                    'native_restore_master_rotation_required')
            stop_old_redaction = install_log_redaction(old_master)
            def stop_redaction():
                stop_old_redaction(); stop_new_redaction()
            # Never pass an old backend/admin credential into native set_save.
            # Do not mutate the protected captured payload or any game progress.
            sanitized = dict(saved)
            sanitized['game_options'] = {**saved['game_options'], 'password': new_master, 'server_password': '', 'item_cheat': False}
            current()
            context.set_save(sanitized)
            current()
            require(hmac.compare_digest(context.password, new_master) and context.server_password == '' and context.item_cheat is False and
                    context.auto_saver_thread is None and context.server is None and not context.endpoints and
                    not context.exit_event.is_set() and not context.log_network and canonical(owner.load_journal()) == canonical(state),
                    'native_restore_context_changed')
            require(snapshots.save_now() is True, 'native_restore_save_unproven')
            current()
            published = snapshots.files.read()[0]
            loaded = decode_native(published, restricted_loads)
            current()
            require(loaded['connect_names'] == context.connect_names and loaded['game_options']['password'] == new_master and
                    loaded['game_options']['server_password'] == '' and loaded['game_options']['item_cheat'] is False and
                    canonical(owner.load_journal()) == canonical(state), 'native_restore_save_changed')
            receipt = {'schema': 'amz.ap.public-beta.native-restore-receipt.v1', 'operationId': manifest['operationId'],
                       'profileSha256': PROFILE_SHA256, 'identity': expected_identity, 'custodySha256': restored['custodySha256'],
                       'migrationSha256': expected_manifest_sha256, 'oldStopReceiptSha256': expected_stop_receipt_sha256,
                       'runtimeArtifactSha256': expected_runtime_artifact_sha256, 'worldPackSha256': expected_world_pack_sha256,
                       'seedArtifactSha256': sha(seed), 'capturedNativeSaveSha256': sha(restored['nativeSave']),
                       'restoredNativeSaveSha256': sha(published), 'restoredNativeSaveBytes': len(published),
                       'idle': copy.deepcopy(manifest['idle']), 'state': 'restored_held', 'admissionHeld': True}
            return RestoredNative(state, receipt, stop_redaction)
    except BaseException:
        owner._uncertain, owner._durable, snapshots.sealed = True, None, True
        if stop_redaction is not None: stop_redaction()
        # Native/decoder exception text can contain private save data. Return
        # no raw error, trace or old/new credential to the composition caller.
        raise BarrierError('native_restore_refused') from None

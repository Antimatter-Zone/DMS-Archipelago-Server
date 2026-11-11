"""Explicit Public native checkpoint custody; no engine import or auto-start.

The protected operator supplies an independently pinned migration approval and
an exact old-process stop receipt. This module checks that binding, not Panel
or process liveness. Loader restore/reopen remains closed until composed with
the separately reviewed native serializer and protected operator.
"""
import copy
import hashlib
import json
import os
import struct
import uuid

from gateway_barrier import (NativeBarrier, canonical, exact, gate_input,
                             identity, initial_state, instant, integer, iso,
                             material, require, SHA, UUID)
from native_files import NativeFiles

CUSTODY = 'public-native-custody.amzc'
MIGRATION = 'public-runtime-migration.json'
MAGIC = b'AMZC1\x00'
MAXIMUM = 16 * 1024 * 1024
HEADER_MAXIMUM = 16384
SCHEMA = 'amz.ap.public-beta.native-custody.v1'
MIGRATION_SCHEMA = 'amz.ap.public-beta.native-migration.v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return type(value) is str and SHA.fullmatch(value)


def canonical_object(raw):
    try:
        value = json.loads(raw.decode('utf-8'))
        require(type(value) is dict and canonical(value) == raw, 'native_custody_encoding')
        return value
    except (UnicodeError, ValueError, RecursionError):
        require(False, 'native_custody_encoding')


def idle_basis(state):
    initial, last = state['initialReadyAt'], state['lastDisconnectAt']
    require((not state['everConnected'] and state['generation'] == 0 and initial is not None and last is None) or
            (state['everConnected'] and state['generation'] > 0 and initial is None and last is not None), 'native_custody_idle_unknown')
    instant(initial if initial is not None else last)
    return {'connectionGeneration': state['generation'], 'provenInitialReadyAt': initial, 'provenLastDisconnectAt': last}


def stopped_journal(value, scope):
    """Validate only a positively quiesced journal; never adopt unknown rows."""
    require(exact(value, initial_state(scope)) and value['schema'] == initial_state(scope)['schema'] and value['identity'] == scope and
            value['ready'] is False and value['uncertain'] is False and type(value['everConnected']) is bool and
            integer(value['revision'], 1) and integer(value['generation']) and integer(value['clockFloor'], 1), 'native_custody_journal_unknown')
    require(all(type(value[name]) is dict and len(value[name]) <= maximum for name, maximum in (('preparations', 64), ('gates', 64), ('controls', 256))), 'native_custody_journal_unknown')
    for key, row in value['preparations'].items():
        require(exact(row, ('material', 'credentialSha256', 'status', 'accepted')) and type(row['material']) is dict and key == row['material'].get('reservationId') and
                row['status'] == 'closed' and type(row['accepted']) is bool and digest(row['credentialSha256']), 'native_custody_pending')
        material(row['material'], scope)
    for key, row in value['gates'].items():
        require(exact(row, ('gate', 'request')) and type(row['gate']) is dict and key == row['gate'].get('id'), 'native_custody_gate_changed')
        gate_input(row['gate'], row['request'], scope)
    for key, row in value['controls'].items():
        require(type(key) is str and UUID.fullmatch(key) and exact(row, ('sha256', 'expiresAt')) and digest(row['sha256']), 'native_custody_journal_unknown')
        instant(row['expiresAt'])
    idle_basis(value)
    return copy.deepcopy(value)


def held(barrier, gate):
    require(type(barrier) is NativeBarrier and exact(gate, ('id', 'operationId', 'requestSha256', 'kind')) and gate['kind'] == 'idle', 'native_custody_gate_required')
    row = barrier.state['gates'].get(gate['id'])
    require(row is not None and row['gate'] == gate, 'native_custody_gate_changed')
    checked = gate_input(gate, row['request'], barrier.identity)
    state, request = barrier.state, checked['request']
    require(not state['uncertain'] and not barrier._inflight and barrier._actual() == [] and
            all(item['status'] == 'closed' for item in state['preparations'].values()) and
            request['expectedConnectionGeneration'] == state['generation'] and request['provenInitialReadyAt'] == state['initialReadyAt'] and
            request['provenLastDisconnectAt'] == state['lastDisconnectAt'], 'native_custody_idle_unknown')
    idle_basis(state)
    return checked


def encode_checkpoint(header, native_save, journal):
    require(type(native_save) is bytes and 0 < len(native_save) <= MAXIMUM, 'native_custody_size')
    raw_journal = canonical(journal)
    value = {**header, 'nativeSaveSha256': sha(native_save), 'nativeSaveBytes': len(native_save),
             'barrierSha256': sha(raw_journal), 'barrierBytes': len(raw_journal)}
    raw_header = canonical(value)
    require(len(raw_header) <= HEADER_MAXIMUM, 'native_custody_size')
    raw = MAGIC + struct.pack('>I', len(raw_header)) + raw_header + native_save + raw_journal
    require(len(raw) <= MAXIMUM, 'native_custody_size')
    return raw


def decode_checkpoint(raw, expected):
    require(type(raw) is bytes and digest(expected) and sha(raw) == expected and len(MAGIC) + 4 < len(raw) <= MAXIMUM and raw.startswith(MAGIC), 'native_custody_pin_changed')
    size = struct.unpack('>I', raw[len(MAGIC):len(MAGIC) + 4])[0]
    offset = len(MAGIC) + 4
    require(0 < size <= HEADER_MAXIMUM and offset + size < len(raw), 'native_custody_size')
    header = canonical_object(raw[offset:offset + size]); offset += size
    require(exact(header, ('schema', 'checkpointId', 'identity', 'runtimeArtifactSha256', 'worldPackSha256', 'seedArtifactSha256',
                           'gate', 'idle', 'capturedAt', 'nativeSaveSha256', 'nativeSaveBytes', 'barrierSha256', 'barrierBytes')) and
            header['schema'] == SCHEMA and type(header['checkpointId']) is str and UUID.fullmatch(header['checkpointId']) and
            all(digest(header[key]) for key in ('runtimeArtifactSha256', 'worldPackSha256', 'seedArtifactSha256', 'nativeSaveSha256', 'barrierSha256')) and
            integer(header['nativeSaveBytes'], 1, MAXIMUM) and integer(header['barrierBytes'], 1, 2 * 1024 * 1024), 'native_custody_encoding')
    scope = identity(header['identity']); instant(header['capturedAt'])
    end = offset + header['nativeSaveBytes']
    native_save, raw_journal = raw[offset:end], raw[end:]
    require(len(raw_journal) == header['barrierBytes'] and sha(native_save) == header['nativeSaveSha256'] and sha(raw_journal) == header['barrierSha256'], 'native_custody_payload_changed')
    journal = stopped_journal(canonical_object(raw_journal), scope)
    require(type(header['gate']) is dict and type(header['gate'].get('id')) is str, 'native_custody_gate_changed')
    row = journal['gates'].get(header['gate']['id'])
    require(row is not None and row['gate'] == header['gate'] and header['gate']['kind'] == 'idle' and idle_basis(journal) == header['idle'], 'native_custody_gate_changed')
    require(instant(header['capturedAt']) >= journal['clockFloor'], 'native_clock_rollback')
    return header, native_save, journal


class CustodyFiles:
    """Fixed files under the existing NativeFiles owner; no path argument.

    Reuses the exact pinned owner/lock and its directory FD. An uncertain write
    poisons that owner and retains all pending evidence, just like its journal.
    """
    def __init__(self, owner):
        require(type(owner) is NativeFiles, 'native_custody_owner_required')
        self.owner = owner
        with owner._mutex:
            owner._active()
            with os.scandir(owner._directory) as entries:
                for count, entry in enumerate(entries):
                    require(count < 1024 and not entry.name.startswith('.' + CUSTODY + '.pending-'), 'native_custody_reconciliation_required')

    def _read(self, optional=False):
        owner = self.owner; owner._active(); before = owner._entry(CUSTODY)
        if optional and before is None:
            return None
        require(before is not None and 0 < before.st_size <= MAXIMUM, 'native_custody_missing')
        expected = owner._regular(before)
        fd = os.open(CUSTODY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=owner._directory)
        try:
            require(owner._regular(os.fstat(fd)) == expected, 'native_custody_file_changed')
            raw = bytearray()
            while len(raw) <= MAXIMUM:
                part = os.read(fd, min(65536, MAXIMUM + 1 - len(raw)))
                if not part: break
                raw.extend(part)
            require(len(raw) == before.st_size and len(raw) <= MAXIMUM and owner._regular(os.fstat(fd)) == expected and owner._regular(owner._entry(CUSTODY)) == expected, 'native_custody_file_changed')
            owner._active()
            return bytes(raw), expected
        finally:
            os.close(fd)

    def read(self):
        with self.owner._mutex:
            return self._read()[0]

    def migration(self, expected):
        with self.owner._mutex:
            self.owner._active()
            value, _, actual = self.owner._read(MIGRATION, HEADER_MAXIMUM)
            require(digest(expected) and actual.hex() == expected, 'native_migration_pin_changed')
            return value

    def publish(self, raw):
        require(type(raw) is bytes and 0 < len(raw) <= MAXIMUM, 'native_custody_size')
        owner, fd = self.owner, None
        with owner._mutex:
            previous = self._read(optional=True)
            temporary = '.' + CUSTODY + '.pending-' + uuid.uuid4().hex
            try:
                owner._active()
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=owner._directory)
                owner._write_all(fd, raw); os.fsync(fd)
                pending = owner._regular(os.fstat(fd)); owner._active()
                require(owner._regular(owner._entry(temporary)) == pending and self._read(optional=True) == previous, 'native_custody_file_changed')
                os.replace(temporary, CUSTODY, src_dir_fd=owner._directory, dst_dir_fd=owner._directory); os.fsync(owner._directory)
                result = self._read()
                require(result[0] == raw and result[1] == owner._regular(os.fstat(fd)), 'native_custody_file_changed')
                return sha(raw)
            except BaseException:
                owner._uncertain, owner._durable = True, None
                raise
            finally:
                if fd is not None: os.close(fd)


def capture(files, barrier, gate, *, checkpoint_id, seed_sha256, runtime_artifact_sha256, world_pack_sha256, native_snapshot):
    """Terminal held custody. The caller must quiesce the exact native writer.

    native_snapshot is a trusted synchronous native serializer, never selected
    by a packet. No default/native-engine stand-in is provided. This function
    leaves admission closed even if snapshot or publication fails.
    """
    require(type(files) is CustodyFiles, 'native_custody_owner_required')
    with files.owner._mutex:
        return _capture_locked(files, barrier, gate, checkpoint_id, seed_sha256, runtime_artifact_sha256, world_pack_sha256, native_snapshot)


def _capture_locked(files, barrier, gate, checkpoint_id, seed_sha256, runtime_artifact_sha256, world_pack_sha256, native_snapshot):
    require(type(checkpoint_id) is str and UUID.fullmatch(checkpoint_id) and
            all(digest(value) for value in (seed_sha256, runtime_artifact_sha256, world_pack_sha256)) and callable(native_snapshot), 'native_custody_input')
    require(barrier.state['ready'], 'native_custody_idle_unknown')
    held(barrier, gate)
    barrier.shutdown()
    held(barrier, gate)
    before = canonical(barrier.state)
    require(canonical(files.owner.load_journal()) == before, 'native_custody_journal_changed')
    native_save = native_snapshot()
    held(barrier, gate)
    require(canonical(barrier.state) == before and canonical(files.owner.load_journal()) == before, 'native_custody_state_changed')
    journal = stopped_journal(barrier.state, barrier.identity)
    now = barrier._now()
    raw = encode_checkpoint({'schema': SCHEMA, 'checkpointId': checkpoint_id, 'identity': barrier.identity,
                             'runtimeArtifactSha256': runtime_artifact_sha256, 'worldPackSha256': world_pack_sha256,
                             'seedArtifactSha256': seed_sha256, 'gate': copy.deepcopy(gate), 'idle': idle_basis(journal), 'capturedAt': iso(now)}, native_save, journal)
    files.publish(raw)
    held(barrier, gate)
    require(not barrier.state['ready'] and canonical(barrier.state) == canonical({**journal, 'clockFloor': now}) and canonical(files.owner.load_journal()) == before, 'native_custody_state_changed')
    return {'schema': SCHEMA, 'checkpointId': checkpoint_id, 'sha256': sha(raw), 'bytes': len(raw), 'admissionHeld': True}


def migrate(files, *, expected_manifest_sha256, seed, expected_stop_receipt_sha256, expected_runtime_artifact_sha256, expected_world_pack_sha256, clock):
    """Explicit protected migration only; never empty-journal recovery.

    The stop-receipt pin is supplied by protected composition after positive
    exact-process/provider checks. A matching hash alone does not perform them.
    Returned bytes are private native state, not a gameplay/restore receipt.
    """
    require(type(files) is CustodyFiles, 'native_custody_owner_required')
    with files.owner._mutex:
        return _migrate_locked(files, expected_manifest_sha256, seed, expected_stop_receipt_sha256, expected_runtime_artifact_sha256, expected_world_pack_sha256, clock)


def _migrate_locked(files, expected_manifest_sha256, seed, expected_stop_receipt_sha256, expected_runtime_artifact_sha256, expected_world_pack_sha256, clock):
    require(digest(expected_manifest_sha256) and callable(clock), 'native_migration_rejected')
    sampled = clock()
    require(integer(sampled, 1), 'native_clock_rollback')
    manifest = files.migration(expected_manifest_sha256)
    now = clock()
    require(sha(canonical(manifest)) == expected_manifest_sha256 and
            exact(manifest, ('schema', 'operationId', 'oldIdentity', 'newIdentity', 'custodySha256', 'seedArtifactSha256', 'nativeSaveSha256', 'barrierSha256',
                            'stoppedBarrierSha256', 'stoppedBarrierRevision', 'stoppedBarrierClockFloor', 'idle',
                            'runtimeArtifactSha256', 'worldPackSha256', 'targetRuntimeArtifactSha256', 'targetWorldPackSha256', 'oldStopReceiptSha256', 'newHold', 'issuedAt', 'expiresAt')) and
            manifest['schema'] == MIGRATION_SCHEMA and type(manifest['operationId']) is str and UUID.fullmatch(manifest['operationId']) and
            integer(now, sampled) and instant(manifest['issuedAt']) <= now < instant(manifest['expiresAt']) and 0 < instant(manifest['expiresAt']) - instant(manifest['issuedAt']) <= 300000 and
            all(digest(manifest[key]) for key in ('custodySha256', 'seedArtifactSha256', 'nativeSaveSha256', 'barrierSha256', 'stoppedBarrierSha256', 'runtimeArtifactSha256', 'worldPackSha256', 'targetRuntimeArtifactSha256', 'targetWorldPackSha256', 'oldStopReceiptSha256')) and
            integer(manifest['stoppedBarrierRevision'], 1) and integer(manifest['stoppedBarrierClockFloor'], 1) and
            digest(expected_stop_receipt_sha256) and expected_stop_receipt_sha256 == manifest['oldStopReceiptSha256'] and type(seed) is bytes and 0 < len(seed) <= MAXIMUM and sha(seed) == manifest['seedArtifactSha256'], 'native_migration_rejected')
    require(digest(expected_runtime_artifact_sha256) and digest(expected_world_pack_sha256) and manifest['targetRuntimeArtifactSha256'] == expected_runtime_artifact_sha256 and
            manifest['targetWorldPackSha256'] == expected_world_pack_sha256, 'native_migration_pin_changed')
    manifest = copy.deepcopy(manifest)
    def current():
        nonlocal now
        observed = clock()
        require(integer(observed, now) and instant(manifest['issuedAt']) <= observed < instant(manifest['expiresAt']), 'native_migration_expired_or_clock_changed')
        now = observed
    old, new = identity(manifest['oldIdentity']), identity(manifest['newIdentity'])
    require(all(old[key] == new[key] for key in ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')) and
            new['runtimeLaunchId'] != old['runtimeLaunchId'] and new['credentialEpoch'] > old['credentialEpoch'] and new['allocationRevision'] >= old['allocationRevision'] and
            (new['allocationRevision'] > old['allocationRevision'] or new['serverId'] == old['serverId']), 'native_migration_identity_changed')
    header, native_save, journal = decode_checkpoint(files.read(), manifest['custodySha256'])
    current()
    require(header['identity'] == old and all(header[key] == manifest[key] for key in ('seedArtifactSha256', 'nativeSaveSha256', 'barrierSha256', 'idle', 'runtimeArtifactSha256', 'worldPackSha256')) and
            instant(manifest['issuedAt']) >= instant(header['capturedAt']) and now >= journal['clockFloor'], 'native_migration_pin_changed')
    hold = manifest['newHold']
    require(exact(hold, ('gate', 'request')), 'native_migration_hold_required')
    checked = gate_input(hold['gate'], hold['request'], new)
    request = checked['request']
    require(hold['gate']['kind'] == 'idle' and hold['gate']['id'] != header['gate']['id'] and hold['gate']['operationId'] == manifest['operationId'] and
            request['action'] == journal['gates'][header['gate']['id']]['request']['action'] and request['expectedConnectionGeneration'] == journal['generation'] and
            request['provenInitialReadyAt'] == journal['initialReadyAt'] and request['provenLastDisconnectAt'] == journal['lastDisconnectAt'], 'native_migration_idle_changed')
    target = initial_state(new)
    require(manifest['stoppedBarrierRevision'] >= journal['revision'] and manifest['stoppedBarrierClockFloor'] >= journal['clockFloor'] and
            instant(manifest['issuedAt']) >= manifest['stoppedBarrierClockFloor'], 'native_clock_rollback')
    target.update(revision=manifest['stoppedBarrierRevision'] + 1, clockFloor=instant(manifest['issuedAt']), generation=journal['generation'], everConnected=journal['everConnected'],
                  initialReadyAt=journal['initialReadyAt'], lastDisconnectAt=journal['lastDisconnectAt'], gates={hold['gate']['id']: checked})
    # Graceful shutdown can advance revision/clock/control history after capture.
    # The protected manifest must pin that exact terminal journal as well. It
    # cannot change native progress, preparations, gates or original idle basis.
    observed_journal = files.owner.load_journal()
    current()
    if canonical(observed_journal) != canonical(target):
        require(sha(canonical(observed_journal)) == manifest['stoppedBarrierSha256'], 'native_migration_journal_changed')
        stopped_journal(observed_journal, old)
        require(observed_journal['revision'] == manifest['stoppedBarrierRevision'] and
                observed_journal['clockFloor'] == manifest['stoppedBarrierClockFloor'] and
                all(observed_journal[name] == journal[name] for name in ('schema', 'identity', 'ready', 'uncertain', 'generation', 'everConnected', 'initialReadyAt', 'lastDisconnectAt', 'preparations', 'gates')),
                'native_migration_journal_changed')
    current()
    files.owner.commit_journal(target)
    current()
    require(files.owner.load_journal() == target, 'native_migration_journal_changed')
    current()
    return {'state': copy.deepcopy(target), 'nativeSave': native_save, 'custodySha256': manifest['custodySha256'], 'admissionHeld': True}

"""Public native codec, serialized save owner and terminal capture control.

No engine import, background thread, timer or automatic lifecycle on import.
Composition supplies the exact already-verified native Context.get_save.
"""
import hashlib
import math
import os
import pickle
import pickletools
import threading
import time
import uuid
import zlib

from gateway_barrier import canonical, exact, identity, instant, integer, iso, require, SHA, UUID
from native_files import NativeFiles
from checkpoint_custody import CustodyFiles, capture, decode_checkpoint, held

SAVE = 'public-seed.apsave'
CONTROL = 'public-runtime-control.json'
ACK = 'public-runtime-ack.json'
OPERATION = 'public-runtime-operation.json'
SCHEMA = 'amz.ap.public-beta.runtime-control.v1'
ACK_SCHEMA = 'amz.ap.public-beta.runtime-ack.v1'
OP_SCHEMA = 'amz.ap.public-beta.runtime-operation.v1'
MAX_SAVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_MESSAGE = 65536


def sha(raw): return hashlib.sha256(raw).hexdigest()


class Deflater:
    def __init__(self):
        self.total, self.output, self.compressor = 0, bytearray(), zlib.compressobj()

    def append(self, raw):
        require(len(self.output) + len(raw) <= MAX_SAVE, 'native_save_compressed_limit')
        self.output.extend(raw)

    def write(self, raw):
        self.total += len(raw)
        require(self.total <= MAX_EXPANDED, 'native_save_expanded_limit')
        self.append(self.compressor.compress(raw))
        return len(raw)


def encode_native(value):
    require(type(value) is dict, 'native_save_schema')
    stream = Deflater()
    pickle.Pickler(stream, protocol=pickle.DEFAULT_PROTOCOL).dump(value)
    stream.append(stream.compressor.flush())
    require(stream.output, 'native_save_schema')
    return bytes(stream.output)


def decode_native(raw, restricted_loads):
    """Only the verified native restricted loader; never pickle.loads fallback."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_SAVE and callable(restricted_loads), 'native_restore_input')
    stream = zlib.decompressobj()
    try:
        expanded = stream.decompress(raw, MAX_EXPANDED + 1)
        require(len(expanded) <= MAX_EXPANDED and stream.eof and not stream.unused_data and not stream.unconsumed_tail, 'native_restore_compression')
        expanded += stream.flush(MAX_EXPANDED + 1 - len(expanded))
        require(len(expanded) <= MAX_EXPANDED, 'native_restore_expanded_limit')
        last, count = None, 0
        for opcode, _, position in pickletools.genops(expanded):
            count += 1
            require(count <= 1000000, 'native_restore_operation_limit')
            last = opcode.name, position
        require(last == ('STOP', len(expanded) - 1), 'native_restore_trailing_data')
    except (ValueError, zlib.error):
        require(False, 'native_restore_encoding')
    value = restricted_loads(expanded)
    require(type(value) is dict, 'native_restore_schema')
    return value


class NativeSaveFiles:
    """The single fixed private binary save, under the existing native owner."""
    def __init__(self, owner):
        require(type(owner) is NativeFiles, 'native_save_owner_required')
        self.owner = owner
        with owner._mutex:
            owner._active()
            with os.scandir(owner._directory) as entries:
                for count, entry in enumerate(entries):
                    require(count < 1024 and not entry.name.startswith('.' + SAVE + '.pending-'), 'native_save_reconciliation_required')

    def read(self, optional=False):
        owner = self.owner
        with owner._mutex:
            owner._active(); entry = owner._entry(SAVE)
            if optional and entry is None: return None
            require(entry is not None and 0 < entry.st_size <= MAX_SAVE, 'native_save_missing')
            expected = owner._regular(entry)
            fd = os.open(SAVE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=owner._directory)
            try:
                require(owner._regular(os.fstat(fd)) == expected, 'native_save_changed')
                raw = bytearray()
                while len(raw) <= MAX_SAVE:
                    part = os.read(fd, min(65536, MAX_SAVE + 1 - len(raw)))
                    if not part: break
                    raw.extend(part)
                require(len(raw) == entry.st_size and len(raw) <= MAX_SAVE and owner._regular(os.fstat(fd)) == expected and owner._regular(owner._entry(SAVE)) == expected, 'native_save_changed')
                owner._active(); return bytes(raw), expected
            finally: os.close(fd)

    def write(self, raw):
        require(type(raw) is bytes and 0 < len(raw) <= MAX_SAVE, 'native_save_compressed_limit')
        owner, fd = self.owner, None
        with owner._mutex:
            previous = self.read(optional=True)
            name = '.' + SAVE + '.pending-' + uuid.uuid4().hex
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=owner._directory)
                owner._write_all(fd, raw); os.fsync(fd)
                expected = owner._regular(os.fstat(fd)); owner._active()
                require(owner._regular(owner._entry(name)) == expected and self.read(optional=True) == previous, 'native_save_changed')
                os.replace(name, SAVE, src_dir_fd=owner._directory, dst_dir_fd=owner._directory); os.fsync(owner._directory)
                observed = self.read()
                require(observed[0] == raw and observed[1] == owner._regular(os.fstat(fd)), 'native_save_changed')
            except BaseException:
                owner._uncertain, owner._durable = True, None
                raise
            finally:
                if fd is not None: os.close(fd)


class NativeSnapshots:
    """Explicit loop-owned replacement for native thread/atexit file writing.

    Every call must run on the native event loop. Snapshot creation and bounded
    serialization contain no await, so native handlers cannot interleave.
    Initial save, dirty periodic save and terminal capture share this writer.
    """
    def __init__(self, owner, context, monotonic=None):
        require(type(owner) is NativeFiles and callable(context.get_save) and context.auto_saver_thread is None, 'native_save_composition')
        self.owner, self.context, self.files = owner, context, NativeSaveFiles(owner)
        self.thread = threading.get_ident()
        self.monotonic, self.sealed = monotonic or time.monotonic, False
        self.due = self.monotonic() + 60

    def save_now(self):
        require(threading.get_ident() == self.thread, 'native_save_thread_forbidden')
        if self.sealed: return True
        require(self.context.auto_saver_thread is None, 'native_save_thread_forbidden')
        try:
            raw = encode_native(self.context.get_save())
            self.files.write(raw)
        except BaseException:
            # Native save(now=True) clears dirty before calling _save. Restore
            # it on failure as well as preserving ordinary periodic dirtiness.
            self.context.save_dirty = True
            raise
        self.context.save_dirty = False
        return True

    def periodic(self):
        require(threading.get_ident() == self.thread, 'native_save_thread_forbidden')
        current = self.monotonic()
        if self.sealed or current < self.due: return False
        self.due = current + 60
        if self.context.save_dirty:
            self.save_now(); return True
        return False

    def checkpoint(self, custody, barrier, gate, *, checkpoint_id, seed_sha256, runtime_artifact_sha256, world_pack_sha256):
        require(threading.get_ident() == self.thread, 'native_save_thread_forbidden')
        require(not self.sealed, 'native_checkpoint_already_terminal')
        def snapshot():
            require(self.context.auto_saver_thread is None, 'native_save_thread_forbidden')
            raw = encode_native(self.context.get_save())
            self.files.write(raw); self.context.save_dirty = False
            return raw
        try:
            return capture(custody, barrier, gate, checkpoint_id=checkpoint_id, seed_sha256=seed_sha256,
                           runtime_artifact_sha256=runtime_artifact_sha256, world_pack_sha256=world_pack_sha256, native_snapshot=snapshot)
        finally:
            # Failure after closure cannot restart active periodic writes.
            if not barrier.state['ready']: self.sealed = True


class RuntimeControl:
    """Single terminal operation with durable intent/ACK, never auto-retried."""
    def __init__(self, owner, barrier, snapshots, configuration, clock=None, monotonic=None):
        require(type(owner) is NativeFiles and type(snapshots) is NativeSnapshots, 'native_control_composition')
        self.owner, self.barrier, self.snapshots, self.custody = owner, barrier, snapshots, CustodyFiles(owner)
        self.config, self.clock = dict(configuration), clock or (lambda: int(time.time() * 1000))
        self.monotonic = monotonic or time.monotonic
        self.deadline, self.monotonic_floor, self.command_sha = None, None, None
        self.last = None
        with owner._mutex:
            owner._active()
            with os.scandir(owner._directory) as entries:
                for count, entry in enumerate(entries):
                    require(count < 1024 and not entry.name.startswith(('.' + ACK + '.pending-', '.' + OPERATION + '.pending-')), 'native_control_reconciliation_required')

    def _read(self, name):
        self.owner._active()
        return self.owner._read(name, MAX_MESSAGE, optional=True)

    def _write(self, name, value):
        previous = self._read(name)
        self.owner._replace(name, canonical(value), MAX_MESSAGE, previous)

    def poll_once(self):
        with self.owner._mutex:
            packet = self._read(CONTROL)
            if packet is None: return False
            command = packet[0]; encoded = canonical(command); command_sha = sha(SCHEMA.encode() + b'\n' + encoded)
            if command_sha == self.last: return False
            require(exact(command, ('schema', 'operationId', 'command', 'identity', 'gate', 'issuedAt', 'expiresAt')) and command['schema'] == SCHEMA and
                    command['command'] == 'checkpoint_and_hold' and type(command['operationId']) is str and UUID.fullmatch(command['operationId']) and
                    identity(command['identity']) == self.barrier.identity and len(encoded) <= MAX_MESSAGE, 'native_runtime_control_rejected')
            def current():
                native_now = self.barrier._now()
                now = self.clock()
                require(integer(now, native_now) and instant(command['issuedAt']) <= now < instant(command['expiresAt']) and
                        0 < instant(command['expiresAt']) - instant(command['issuedAt']) <= 8000, 'native_runtime_control_expired')
                mono = self.monotonic()
                require(type(mono) in (int, float) and math.isfinite(mono), 'native_runtime_control_expired')
                if self.deadline is None:
                    # Capture the remaining TTL once. Wall-clock adjustments or
                    # in-process lost-ACK replay must never extend it.
                    self.deadline = mono + (instant(command['expiresAt']) - now) / 1000
                    self.monotonic_floor, self.command_sha = mono, command_sha
                require(self.command_sha == command_sha, 'native_runtime_operation_conflict')
                require(self.monotonic_floor <= mono < self.deadline, 'native_runtime_control_expired')
                self.monotonic_floor = mono
                return now
            current(); held(self.barrier, command['gate'])
            existing = self._read(OPERATION)
            if existing is not None:
                record = existing[0]
                require(exact(record, ('schema', 'operationId', 'commandSha256', 'identity', 'phase', 'custodySha256', 'bytes')) and record['schema'] == OP_SCHEMA and
                        record['phase'] in ('preparing', 'sealed', 'unknown') and record['operationId'] == command['operationId'] and
                        record['commandSha256'] == command_sha and record['identity'] == self.barrier.identity and
                        (record['phase'] == 'sealed' and type(record['custodySha256']) is str and SHA.fullmatch(record['custodySha256']) and integer(record['bytes'], 1, MAX_SAVE) or
                         record['phase'] != 'sealed' and record['custodySha256'] is None and record['bytes'] is None), 'native_runtime_operation_conflict')
                # Never rerun a serializer after a lost outcome or process crash.
                result = {'state': 'unknown', 'custodySha256': None, 'bytes': None, 'admissionHeld': True}
                if record.get('phase') == 'sealed':
                    raw = self.custody.read()
                    header, _, _ = decode_checkpoint(raw, record['custodySha256'])
                    require(header['checkpointId'] == command['operationId'] and header['identity'] == self.barrier.identity and
                            header['gate'] == command['gate'] and record['bytes'] == len(raw) and not self.barrier.state['ready'], 'native_runtime_custody_changed')
                    result.update(state='sealed', custodySha256=record['custodySha256'], bytes=len(raw))
            else:
                require(self.barrier.state['ready'], 'native_runtime_not_ready')
                record = {'schema': OP_SCHEMA, 'operationId': command['operationId'], 'commandSha256': command_sha,
                          'identity': self.barrier.identity, 'phase': 'preparing', 'custodySha256': None, 'bytes': None}
                self._write(OPERATION, record); current()
                # Intent is fsynced before any closure, snapshot or save write.
                try:
                    receipt = self.snapshots.checkpoint(self.custody, self.barrier, command['gate'], checkpoint_id=command['operationId'],
                              seed_sha256=self.config['seedArtifactSha256'], runtime_artifact_sha256=self.config['runtimeArtifactSha256'], world_pack_sha256=self.config['worldPackSha256'])
                    current(); held(self.barrier, command['gate'])
                    record.update(phase='sealed', custodySha256=receipt['sha256'], bytes=receipt['bytes'])
                    self._write(OPERATION, record)
                    result = {'state': 'sealed', 'custodySha256': receipt['sha256'], 'bytes': receipt['bytes'], 'admissionHeld': True}
                except BaseException:
                    # Best effort unknown intent never removes the held gate.
                    record.update(phase='unknown', custodySha256=None, bytes=None)
                    self._write(OPERATION, record)
                    raise
            current(); held(self.barrier, command['gate'])
            acknowledgement = {'schema': ACK_SCHEMA, 'operationId': command['operationId'], 'commandSha256': command_sha,
                               'identity': self.barrier.identity, 'observedAt': iso(self.clock()), 'result': result}
            self._write(ACK, acknowledgement); current(); held(self.barrier, command['gate'])
            self.last = command_sha
            return True

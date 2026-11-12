"""Source-only fixtures; no native engine, image, listener, or host enrollment."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

SOURCE = Path(__file__).resolve().parents[2] / 'public-beta-publication/runtime/publication.py'


def load(file, name):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kernel = load(SOURCE, 'unchanged_publication_source_fixture')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def iso(milliseconds):
    return datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def dates(duration=4500):
    now = time.time_ns() // 1000000
    return iso(now), iso(now + duration)


def identity():
    value = {k: str(uuid.uuid4()) for k in ('environmentId', 'dataEpoch', 'roomId', 'attemptId', 'runtimeLaunchId')}
    value.update(appVariant='public-beta', policyId='public-disposable-beta-v1', allocationRevision=1,
                 serverId='source-fixture', seedRevision=1, credentialEpoch=1)
    value['externalId'] = 'ap-beta-' + value['roomId'] + '-r1'
    return value


def observation(binding, pair=None):
    pair = pair or dates()
    operation = str(uuid.uuid4())
    value = {'schema': 'amz.ap.public-beta.yacht-observation-control.v1', 'requestId': operation,
             'identity': binding, 'actorUuid': str(uuid.uuid4()), 'issuedAt': pair[0], 'expiresAt': pair[1],
             'requestMac': '0' * 64}  # Synthetic syntax only, not a genuine native MAC.
    return operation, canonical(value), pair


class PurePublicationTests(unittest.TestCase):
    def test_import_has_no_activation_transport_or_bootstrap(self):
        source = SOURCE.read_text()
        self.assertNotIn('import subprocess', source)
        self.assertNotIn('argparse', source)
        self.assertNotIn('if __name__', source)
        self.assertNotIn('def enroll', source)
        self.assertEqual(kernel.CONTROLS, {'gateway': 'public-gateway-control.json',
                         'yacht-observation': 'public-yacht-observation-control.json',
                         'yacht-effects': 'public-yacht-effects-control.json'})
        self.assertEqual(kernel.EXTERNAL_RESERVE, 384 * 1024)

    def test_scope_and_window_cannot_be_created_from_json_or_unregistered_instances(self):
        window = kernel.capture_window(*dates())
        for value in ({}, object.__new__(kernel.PublicationScope)):
            with self.assertRaisesRegex(kernel.PublicationRefused, 'scope_brand'):
                kernel.PublicationLock(value, window)
        with self.assertRaises(kernel.PublicationRefused):
            kernel.PublicationScope()
        with self.assertRaises(kernel.PublicationRefused):
            kernel.PublicationWindow()
        with self.assertRaisesRegex(kernel.PublicationRefused, 'window_brand'):
            kernel._current_window(object.__new__(kernel.PublicationWindow))
        with self.assertRaisesRegex(kernel.PublicationRefused, 'server_uuid'):
            kernel.capture_host_scope('../../member', 'a' * 64, window)

    def test_subclasses_are_refused_before_any_scope_or_descriptor_io(self):
        class BadLock(kernel.PublicationLock):
            pass
        class BadPublisher(kernel.FixedControlPublisher):
            pass
        with patch.object(kernel, '_scope_current', side_effect=AssertionError('scope IO forbidden')):
            with self.assertRaisesRegex(kernel.PublicationRefused, 'lock_type'):
                BadLock(None, None)
            with self.assertRaisesRegex(kernel.PublicationRefused, 'publisher_type'):
                BadPublisher(None, None, None)

    def test_original_window_refuses_expired_extended_and_cancelled_requests(self):
        now = time.time_ns() // 1000000
        for pair in ((iso(now - 5000), iso(now - 1)), (iso(now), iso(now + 5001)), ('bad', iso(now + 1000))):
            with self.assertRaises(kernel.PublicationRefused):
                kernel.capture_window(*pair)
        window = kernel.capture_window(*dates()); window.cancel()
        with self.assertRaisesRegex(kernel.PublicationRefused, 'expired'):
            kernel._current_window(window)

    def test_payload_ids_identity_purpose_dates_and_exact_utf8_are_bound(self):
        binding = identity(); operation, raw, pair = observation(binding)
        window = kernel.capture_window(*pair); scope_data = {'enrollment': {'identity': binding}}
        kernel._command('yacht-observation', operation, raw, window, scope_data)
        for kind, op, body in (('yacht-effects', operation, raw), ('yacht-observation', str(uuid.uuid4()), raw),
                               ('yacht-observation', operation, b'\xef\xbb\xbf' + raw),
                               ('yacht-observation', operation, raw + b' '), ('../gateway', operation, raw),
                               ('yacht-observation', operation, b'x' * (65536 + 1))):
            with self.assertRaises(kernel.PublicationRefused):
                kernel._command(kind, op, body, window, scope_data)
        for change in ({'identity': identity()}, {'expiresAt': iso(time.time_ns() // 1000000 + 1000)},
                       {'extra': True}, {'requestMac': 'wrong'}):
            with self.assertRaises(kernel.PublicationRefused):
                kernel._command('yacht-observation', operation, canonical({**json.loads(raw), **change}), window, scope_data)

    def test_all_three_fixed_purposes_have_distinct_native_schema_and_operation_fields(self):
        binding, operation, pair = identity(), str(uuid.uuid4()), dates()
        common = {'identity': binding, 'issuedAt': pair[0], 'expiresAt': pair[1]}
        controls = {'gateway': {**common, 'schema': 'amz.ap.public-beta.gateway-control.v2',
                               'operationId': operation, 'command': 'revoke_slot', 'gate': {}, 'payload': {}},
                    'yacht-effects': {**common, 'schema': 'amz.ap.public-beta.yacht-effects-control.v1',
                                      'deliveryId': operation, 'commit': {}, 'commitMac': '1' * 64, 'deliveryMac': '2' * 64}}
        for kind, value in controls.items():
            window = kernel.capture_window(*pair)
            kernel._command(kind, operation, canonical(value), window, {'enrollment': {'identity': binding}})
            with self.assertRaises(kernel.PublicationRefused):
                kernel._command(kind, str(uuid.uuid4()), canonical(value), window, {'enrollment': {'identity': binding}})


class Fixture:
    """Separately compiled module; never edits the unchanged source or its brand map."""
    def __init__(self, scope_duration=60000):
        self.temp = tempfile.TemporaryDirectory(prefix='amz-publication-source-')
        self.folder = Path(self.temp.name); self.root = self.folder / 'runtime'; self.root.mkdir(mode=0o700)
        source = SOURCE.read_text()
        replacements = {"RUNTIME_ROOT = '/home/container/.amz'": 'RUNTIME_ROOT = ' + repr(str(self.root)),
                        "HOST_ROOT = '/srv/public-beta/wings/data'": 'HOST_ROOT = ' + repr(str(self.folder / 'host')),
                        'OWNER_UID = 65532': 'OWNER_UID = ' + str(os.geteuid()),
                        'OWNER_GID = 65532': 'OWNER_GID = ' + str(os.getegid())}
        for old, new in replacements.items():
            if source.count(old) != 1: raise AssertionError('fixture source anchor changed')
            source = source.replace(old, new)
        self.module_file = self.folder / 'fixture_kernel.py'; self.module_file.write_text(source)
        self.k = load(self.module_file, 'publication_owned_fixture_' + uuid.uuid4().hex)
        self.binding, self.server = identity(), str(uuid.uuid4())
        lock = {'schema': 'amz.ap.public-beta.publication-lock.v1', 'identity': self.binding,
                'serverUuid': self.server, 'nonce': str(uuid.uuid4())}
        self.write(self.k.LOCK, canonical(lock))
        root, lock_info = self.root.stat(), (self.root / self.k.LOCK).stat()
        pair = dates(scope_duration)
        self.enrollment = {'schema': 'amz.ap.public-beta.publication-scope.v1', 'identity': self.binding,
              'serverUuid': self.server, 'containerId': 'a' * 64,
              'rootDevice': str(os.major(root.st_dev)) + ':' + str(os.minor(root.st_dev)), 'rootInode': str(root.st_ino),
              'lockDevice': str(os.major(lock_info.st_dev)) + ':' + str(os.minor(lock_info.st_dev)), 'lockInode': str(lock_info.st_ino),
              'lockSha256': hashlib.sha256(canonical(lock)).hexdigest(), 'runtimeArtifactSha256': 'b' * 64,
              'runtimeProfileSha256': 'c' * 64, 'publisherSourceSha256': hashlib.sha256(source.encode()).hexdigest(),
              'runtimeSourceCommit': 'd' * 40, 'imageId': 'sha256:' + 'e' * 64, 'issuedAt': pair[0], 'expiresAt': pair[1]}
        self.write(self.k.SCOPE, canonical(self.enrollment)); self.pin = hashlib.sha256(canonical(self.enrollment)).hexdigest()
        self.scope = self.k.capture_runtime_scope(self.pin, self.k.capture_window(*dates()))
        self.lock = self.k.PublicationLock(self.scope, self.k.capture_window(*dates()))
        self.publisher = self.k.FixedControlPublisher(self.scope, self.lock, self.k.capture_window(*dates()))
        self.children = []

    def write(self, name, raw):
        fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output: output.write(raw)
        except BaseException:
            raise

    def publish(self, pair=None):
        operation, raw, pair = observation(self.binding, pair)
        return self.publisher.publish('yacht-observation', operation, raw, self.k.capture_window(*pair)), raw

    def child(self, body):
        prelude = '''import importlib.util,json,os,sys,time
from pathlib import Path
file,root,pin=sys.argv[1:]
spec=importlib.util.spec_from_file_location('isolated_kernel_child',file)
k=importlib.util.module_from_spec(spec);spec.loader.exec_module(k)
def iso(ms):
 from datetime import datetime,timezone
 return datetime.fromtimestamp(ms/1000,timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def window():
 now=time.time_ns()//1000000
 return k.capture_window(iso(now),iso(now+4500))
folder=Path(root).parent
scope=k.capture_runtime_scope(pin,window());lock=k.PublicationLock(scope,window())
'''
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', prelude + body,
                                  str(self.module_file), str(self.root), self.pin], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        return child

    def wait_file(self, name):
        end = time.monotonic() + 3
        while not (self.folder / name).exists():
            if time.monotonic() >= end: raise AssertionError('child barrier timeout')
            time.sleep(0.005)

    def finish(self, child):
        stdout, stderr = child.communicate(timeout=5)
        if child.returncode: raise AssertionError('child source fixture failed: ' + stderr.decode())
        return stdout

    def close(self):
        for child in self.children:
            if child.poll() is None: child.kill()
            child.communicate(timeout=5)
        if self.lock in self.k._LOCKS: self.lock.close()
        if self.scope in self.k._SCOPES: self.scope.close()
        self.temp.cleanup()


@unittest.skipUnless(sys.platform == 'linux', 'actual Linux FD/flock source fixture, not simulated on Windows')
class LinuxPublicationTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(); self.addCleanup(self.f.close)

    def test_actual_replacement_is_bounded_verified_and_not_a_native_ack(self):
        f = self.f
        first, old = f.publish(); second, new = f.publish()
        self.assertEqual((f.root / f.k.CONTROLS['yacht-observation']).read_bytes(), new)
        self.assertEqual(second['previousSha256'], hashlib.sha256(old).hexdigest())
        self.assertFalse(second['activation']); self.assertFalse(second['nativeAcknowledged'])
        self.assertFalse(second['qualification']); self.assertTrue(first['sourceOnly'])
        self.assertEqual((f.root / f.k.CONTROLS['yacht-observation']).stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(f.root.glob('*.publication-pending')), [])
        with f.lock.hold(f.k.capture_window(*dates())):
            with f.lock.hold(f.k.capture_window(*dates())):
                self.assertTrue(True)  # One FD; no inner unlock/downgrade.

    def test_private_fixture_scope_cannot_cross_to_unchanged_module(self):
        f = self.f
        with self.assertRaisesRegex(kernel.PublicationRefused, 'scope_brand'):
            kernel.PublicationLock(f.scope, kernel.capture_window(*dates()))
        with self.assertRaisesRegex(f.k.PublicationRefused, 'scope_pin'):
            f.k.capture_runtime_scope('f' * 64, f.k.capture_window(*dates()))

    def test_foreign_lock_replacement_never_mutates_controls_or_foreign_lock(self):
        f = self.f; lock = f.root / f.k.LOCK; raw = lock.read_bytes()
        lock.rename(f.root / 'foreign-old-lock'); f.write(f.k.LOCK, raw)
        with self.assertRaises(f.k.PublicationRefused): f.publish()
        self.assertEqual(lock.read_bytes(), raw)
        self.assertFalse((f.root / f.k.CONTROLS['yacht-observation']).exists())

    def test_root_replacement_refuses_the_original_captured_fd_before_writing(self):
        f = self.f
        f.root.rename(f.folder / 'original-root'); f.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(f.k.PublicationRefused, 'root_changed'): f.publish()
        self.assertEqual(list(f.root.iterdir()), [])
        self.assertFalse((f.folder / 'original-root' / f.k.CONTROLS['yacht-observation']).exists())

    def test_root_replaced_during_actual_scope_read_is_rechecked_after_io(self):
        f = self.f; original = f.k._read; replaced = []
        def swap(fd, directory, name, maximum):
            result = original(fd, directory, name, maximum)
            if name == f.k.SCOPE and not replaced:
                f.root.rename(f.folder / 'original-root'); f.root.mkdir(mode=0o700); replaced.append(True)
            return result
        with patch.object(f.k, '_read', swap):
            with self.assertRaisesRegex(f.k.PublicationRefused, 'root_changed'): f.publish()
        self.assertEqual(len(replaced), 1); self.assertEqual(list(f.root.iterdir()), [])
        self.assertFalse((f.folder / 'original-root' / f.k.CONTROLS['yacht-observation']).exists())

    def test_scope_rewrite_and_cancelled_window_never_create_pending_or_final(self):
        f = self.f
        operation, raw, pair = observation(f.binding)
        window = f.k.capture_window(*pair); window.cancel()
        with self.assertRaisesRegex(f.k.PublicationRefused, 'expired'):
            f.publisher.publish('yacht-observation', operation, raw, window)
        scope_file = f.root / f.k.SCOPE
        scope_file.write_bytes(scope_file.read_bytes().replace(b'"serverId":"source-fixture"', b'"serverId":"changed-source"'))
        with self.assertRaises(f.k.PublicationRefused): f.publish()
        self.assertEqual(set(p.name for p in f.root.iterdir()), {f.k.SCOPE, f.k.LOCK})

    def test_same_operation_cannot_replace_an_accepted_payload_with_different_bytes(self):
        f = self.f; _, raw = f.publish()
        value = json.loads(raw); value['actorUuid'] = str(uuid.uuid4())
        with self.assertRaisesRegex(f.k.PublicationRefused, 'operation_conflict'):
            f.publisher.publish('yacht-observation', value['requestId'], canonical(value),
                                f.k.capture_window(value['issuedAt'], value['expiresAt']))
        self.assertEqual((f.root / f.k.CONTROLS['yacht-observation']).read_bytes(), raw)

    def test_delayed_hold_cannot_unlock_a_reused_foreign_descriptor_after_close(self):
        f = self.f
        state = f.k._LOCKS[f.lock]; old_fd = state['fd']
        captured, release = threading.Event(), threading.Event()
        errors = []; original = f.k._lock_state
        def paused(lock):
            result = original(lock)
            if threading.current_thread().name == 'stale-waiter':
                captured.set()
                if not release.wait(3): raise AssertionError('test release barrier')
            return result
        def wait():
            try:
                with f.lock.hold(f.k.capture_window(*dates())): pass
            except BaseException as error: errors.append(error)
        foreign = probe = None
        try:
            with patch.object(f.k, '_lock_state', paused):
                thread = threading.Thread(target=wait, name='stale-waiter'); thread.start()
                self.assertTrue(captured.wait(3)); f.lock.close()
                foreign_path = f.folder / 'foreign-lock'
                foreign = os.open(foreign_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                self.assertEqual(foreign, old_fd)  # Real kernel reuse, not a fake FD DTO.
                f.k.fcntl.flock(foreign, f.k.fcntl.LOCK_EX | f.k.fcntl.LOCK_NB)
                release.set(); thread.join(3); self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1); self.assertIsInstance(errors[0], f.k.PublicationRefused)
            probe = os.open(foreign_path, os.O_RDWR)
            with self.assertRaises(BlockingIOError):
                f.k.fcntl.flock(probe, f.k.fcntl.LOCK_EX | f.k.fcntl.LOCK_NB)
            os.fstat(foreign)
        finally:
            release.set()
            if probe is not None: os.close(probe)
            if foreign is not None: os.close(foreign)

    def test_scope_close_waits_for_lock_constructor_and_cannot_close_its_root_fds(self):
        f = self.f; f.lock.close()
        captured, release, close_started, close_done = [threading.Event() for _ in range(4)]
        result, errors = [], []; original = f.k._read
        def paused(fd, directory, name, maximum):
            value = original(fd, directory, name, maximum)
            if threading.current_thread().name == 'capturing-lock' and name == f.k.LOCK:
                captured.set()
                if not release.wait(3): raise AssertionError('test constructor barrier')
            return value
        def construct():
            try: result.append(f.k.PublicationLock(f.scope, f.k.capture_window(*dates())))
            except BaseException as error: errors.append(error)
        def close_scope():
            close_started.set()
            try: f.scope.close()
            except BaseException as error: errors.append(error)
            finally: close_done.set()
        try:
            with patch.object(f.k, '_read', paused):
                constructor = threading.Thread(target=construct, name='capturing-lock'); constructor.start()
                self.assertTrue(captured.wait(3))
                closer = threading.Thread(target=close_scope); closer.start(); self.assertTrue(close_started.wait(3))
                self.assertFalse(close_done.wait(.05))
                release.set(); constructor.join(3); closer.join(3)
                self.assertFalse(constructor.is_alive()); self.assertFalse(closer.is_alive())
            self.assertEqual(len(result), 1); f.lock = result[0]
            f.publisher = f.k.FixedControlPublisher(f.scope, f.lock, f.k.capture_window(*dates()))
            self.assertEqual(len(errors), 1); self.assertIsInstance(errors[0], f.k.PublicationRefused)
            receipt, _ = f.publish(); self.assertFalse(receipt['activation'])
        finally:
            release.set()
            if result: f.lock = result[0]

    def test_real_write_fd_close_failure_after_readback_never_returns_success_or_retries_fd(self):
        f = self.f; original = os.close; failed = []
        def close(fd):
            try:
                path = os.readlink('/proc/self/fd/' + str(fd))
                writer = (f.k.fcntl.fcntl(fd, f.k.fcntl.F_GETFL) & os.O_ACCMODE) == os.O_WRONLY
            except OSError:
                path, writer = '', False
            if writer and path.endswith('/' + f.k.CONTROLS['yacht-observation']):
                failed.append(fd); original(fd)
                raise OSError('synthetic close acknowledgement lost after actual close')
            return original(fd)
        with patch.object(os, 'close', close):
            with self.assertRaises(OSError): f.publish()
        self.assertEqual(len(failed), 1)
        self.assertTrue(f.k._SCOPES[f.scope]['held'])
        with self.assertRaisesRegex(f.k.PublicationRefused, 'held'): f.publish()
        self.assertTrue((f.root / f.k.CONTROLS['yacht-observation']).is_file())

    def test_slow_actual_scope_read_cannot_cross_independent_monotonic_expiry(self):
        f = Fixture(scope_duration=2000); self.addCleanup(f.close)
        frozen = f.k._wall(); original = f.k._read
        window = f.k.capture_window(iso(frozen), iso(frozen + 4500))
        delayed = []
        def slow(fd, directory, name, maximum):
            result = original(fd, directory, name, maximum)
            if name == f.k.SCOPE:
                remaining = (f.k._SCOPES[f.scope]['deadline'] - time.monotonic_ns()) / 1000000000
                time.sleep(max(0, remaining) + .02); delayed.append(True)
            return result
        with patch.object(f.k, '_wall', return_value=frozen), patch.object(f.k, '_read', slow):
            with self.assertRaisesRegex(f.k.PublicationRefused, 'scope_expired'):
                f.k._scope_current(f.scope, window)
            f.k._current_window(window)  # Its independent original 4.5-second budget is still live.
        self.assertEqual(len(delayed), 1)

    def test_slow_actual_lock_read_cannot_admit_a_hold_after_scope_deadline(self):
        f = Fixture(scope_duration=2000); self.addCleanup(f.close)
        frozen = f.k._wall(); original = f.k._read
        window = f.k.capture_window(iso(frozen), iso(frozen + 4500)); admitted = []
        def slow(fd, directory, name, maximum):
            result = original(fd, directory, name, maximum)
            if name == f.k.LOCK:
                remaining = (f.k._SCOPES[f.scope]['deadline'] - time.monotonic_ns()) / 1000000000
                time.sleep(max(0, remaining) + .02)
            return result
        with patch.object(f.k, '_wall', return_value=frozen), patch.object(f.k, '_read', slow):
            with self.assertRaisesRegex(f.k.PublicationRefused, 'scope_expired'):
                with f.lock.hold(window): admitted.append(True)
            f.k._current_window(window)
        self.assertEqual(admitted, [])

    def test_initial_scope_capture_uses_pre_io_window_anchor_and_closes_its_fds(self):
        f = Fixture(scope_duration=2000); self.addCleanup(f.close)
        f.lock.close(); f.scope.close()
        frozen = f.k._wall(); original = f.k._read
        window = f.k.capture_window(iso(frozen), iso(frozen + 4500))
        anchor = f.k._WINDOWS[window]
        deadline = anchor['deadline'] + (f.k._instant(f.enrollment['expiresAt']) - anchor['expiry']) * 1000000
        delayed = []
        def slow(fd, directory, name, maximum):
            result = original(fd, directory, name, maximum)
            if name == f.k.SCOPE:
                time.sleep(max(0, (deadline - time.monotonic_ns()) / 1000000000) + .02)
                delayed.append(True)
            return result
        before = len(os.listdir('/proc/self/fd'))
        with patch.object(f.k, '_wall', return_value=frozen), patch.object(f.k, '_read', slow):
            with self.assertRaisesRegex(f.k.PublicationRefused, 'scope_expired'):
                f.k.capture_runtime_scope(f.pin, window)
            f.k._current_window(window)
        self.assertEqual(len(delayed), 1)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_symlink_hardlink_and_permission_refusals_preserve_owned_files(self):
        f = self.f; target = f.root / f.k.CONTROLS['gateway']; outside = f.folder / 'outside'
        outside.write_bytes(b'outside'); os.chmod(outside, 0o600); target.symlink_to(outside)
        with self.assertRaises(f.k.PublicationRefused): f.publish()
        target.unlink(); os.link(outside, target)
        with self.assertRaises(f.k.PublicationRefused): f.publish()
        target.unlink(); f.write(target.name, b'{}'); os.chmod(target, 0o644)
        with self.assertRaises(f.k.PublicationRefused): f.publish()
        self.assertEqual(outside.read_bytes(), b'outside')

    def test_pending_unknown_and_whole_workspace_budget_refuse_before_open(self):
        f = self.f; name = f.k._pending(f.k.CONTROLS['gateway']); f.write(name, b'partial')
        with self.assertRaisesRegex(f.k.PublicationRefused, 'unknown_or_pending'): f.publish()
        self.assertEqual((f.root / name).read_bytes(), b'partial')
        (f.root / name).unlink()
        for name in ('public-seed.archipelago', 'public-seed.apsave', 'public-gateway-journal.json',
                     'public-yacht-effects-journal.json', 'public-yacht-observation-ack.json'):
            f.write(name, b'x' * f.k.CAPS[name])
        with self.assertRaisesRegex(f.k.PublicationRefused, 'budget'): f.publish()
        self.assertFalse((f.root / f.k.CONTROLS['yacht-observation']).exists())

    def test_real_child_flock_blocks_until_original_deadline_without_publication(self):
        f = self.f
        child = f.child('''with lock.hold(window()):
 (folder/'locked').write_text('yes')
 while not (folder/'release').exists(): time.sleep(.002)
lock.close();scope.close()
''')
        f.wait_file('locked')
        with self.assertRaisesRegex(f.k.PublicationRefused, 'expired'): f.publish(dates(100))
        self.assertFalse((f.root / f.k.CONTROLS['yacht-observation']).exists())
        (f.folder / 'release').write_text('yes'); f.finish(child)
        receipt, _ = f.publish(); self.assertFalse(receipt['activation'])

    def test_real_child_crash_after_actual_pending_fsync_is_retained_and_blocks_reopen(self):
        f = self.f; _, original = f.publish()
        child = f.child('''original=os.fsync
def pause(fd):
 original(fd)
 if os.readlink('/proc/self/fd/'+str(fd)).endswith('.publication-pending'):
  (folder/'pending-fsynced').write_text('yes')
  while True: time.sleep(.01)
os.fsync=pause
publisher=k.FixedControlPublisher(scope,lock,window())
binding=json.loads((Path(root)/k.SCOPE).read_text())['identity']
now=time.time_ns()//1000000
value={'schema':'amz.ap.public-beta.yacht-observation-control.v1','requestId':'11111111-1111-1111-1111-111111111111','identity':binding,'actorUuid':'22222222-2222-2222-2222-222222222222','issuedAt':iso(now),'expiresAt':iso(now+4500),'requestMac':'0'*64}
publisher.publish('yacht-observation',value['requestId'],json.dumps(value,sort_keys=True,separators=(',',':')).encode(),k.capture_window(value['issuedAt'],value['expiresAt']))
''')
        f.wait_file('pending-fsynced'); child.kill(); child.communicate(timeout=5)
        pending = f.root / f.k._pending(f.k.CONTROLS['yacht-observation'])
        before = pending.read_bytes()
        with self.assertRaisesRegex(f.k.PublicationRefused, 'unknown_or_pending'): f.publish()
        self.assertEqual(pending.read_bytes(), before)
        self.assertEqual((f.root / f.k.CONTROLS['yacht-observation']).read_bytes(), original)

    def test_real_child_cooperating_reader_observes_only_complete_canonical_files(self):
        f = self.f; f.publish()
        child = f.child('''reads=0
while not (folder/'reader-stop').exists():
 with lock.hold(window()):
  raw,_=k._read_named(k._SCOPES[scope]['directory'],k.CONTROLS['yacht-observation'],k.LIMIT)
  k._decode(raw,k.LIMIT);reads+=1
  if reads==1: (folder/'reader-ready').write_text('yes')
(folder/'reader-count').write_text(str(reads))
lock.close();scope.close()
''')
        f.wait_file('reader-ready')
        for _ in range(12): f.publish()
        (f.folder / 'reader-stop').write_text('yes'); f.finish(child)
        self.assertGreater(int((f.folder / 'reader-count').read_text()), 0)

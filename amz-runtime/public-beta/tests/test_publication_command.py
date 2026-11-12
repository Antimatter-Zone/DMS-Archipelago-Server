"""Source-only command ABI, real owned Linux files/flock; no provider authority."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from test_native_publication import Fixture as KernelFixture, canonical, dates, identity, iso, load, observation

SOURCE = Path(__file__).resolve().parents[2] / 'public-beta-publication/runtime/command.py'
KERNEL = SOURCE.with_name('publication.py')
command = load(SOURCE, 'unchanged_publication_command_source_fixture')


def request(binding, pair=None, *, action='read', channel='status', payload=None, operation=None):
    pair = pair or dates()
    return canonical({'schema': command.REQUEST_SCHEMA, 'requestId': operation or str(uuid.uuid4()),
                      'identity': binding, 'issuedAt': pair[0], 'expiresAt': pair[1],
                      'action': action, 'channel': channel, 'payload': payload}), pair


class PureCommandTests(unittest.TestCase):
    def test_fixed_source_is_captured_before_execution_without_import_substitution(self):
        raw = KERNEL.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), command.KERNEL_SHA256)
        with patch.object(command, 'compile', side_effect=AssertionError('no unadmitted compile'), create=True):
            for bad in (raw + b'\n', memoryview(raw), b'', b'x' * 65537):
                with self.assertRaisesRegex(command.PublicationCommandRefused, 'source_pin'):
                    command.capture_command_sources(bad)
        original = sys.modules.get('publication')
        sources = command.capture_command_sources(raw)
        self.assertIs(sys.modules.get('publication'), original)
        self.assertEqual(command._sources(sources).CONTROLS,
                         {'gateway': 'public-gateway-control.json',
                          'yacht-observation': 'public-yacht-observation-control.json',
                          'yacht-effects': 'public-yacht-effects-control.json'})

    def test_copied_source_command_or_subclass_is_not_authority(self):
        for bad in ({}, object.__new__(command.CapturedCommandSources)):
            with self.assertRaisesRegex(command.PublicationCommandRefused, 'source_brand'):
                command.open_host_command(bad, str(uuid.uuid4()), 'a' * 64, *dates())
        with self.assertRaises(command.PublicationCommandRefused): command.CapturedCommandSources()
        with self.assertRaises(command.PublicationCommandRefused): command.HostPublicationCommand()
        class Sub(command.HostPublicationCommand): pass
        with self.assertRaisesRegex(command.PublicationCommandRefused, 'brand'):
            object.__new__(Sub).execute(b'{}')

    def test_canonical_single_frame_refuses_bom_duplicates_nonfinite_and_unbounded_input(self):
        for raw in (b'\xef\xbb\xbf{}', b'{}\n', b'{}{}', b'{"a":1,"a":1}',
                    b'{"a":NaN}', b'{"a":"\xff"}', b'[]', b'', b'x' * (command.REQUEST_LIMIT + 1)):
            with self.assertRaises(command.PublicationCommandRefused):
                command._decode(raw, command.REQUEST_LIMIT)
        self.assertEqual(command._decode(b'{"x":1}', 7), {'x': 1})

    def test_original_monotonic_ceiling_and_cancel_do_not_follow_stalled_wall_clock(self):
        wall = time.time_ns() // 1000000
        pair = (iso(wall), iso(wall + 4500))
        with patch.object(command.time, 'time_ns', return_value=wall * 1000000), \
             patch.object(command.time, 'monotonic_ns', side_effect=[1000000000, 5500000000]):
            window = command._capture_window(*pair)
            with self.assertRaisesRegex(command.PublicationCommandRefused, 'expired'):
                command._current_window(window)
        window = command._capture_window(*dates())
        command._WINDOWS[window]['cancelled'] = True
        with self.assertRaisesRegex(command.PublicationCommandRefused, 'expired'):
            command._current_window(window)
        with self.assertRaises(command.PublicationCommandRefused): command._capture_window(*dates(5001))

    def test_cli_is_explicit_and_invalid_boot_arguments_never_read_source_or_stdin(self):
        with patch.object(command, '_source_bytes', side_effect=AssertionError('no source IO')), \
             patch.object(command, '_read_stdin', side_effect=AssertionError('no stdin')):
            for argv in ([], ['--once'], ['--root', '/srv/member'],
                         ['--once', '--server-uuid', 'bad', '--scope-sha256', 'a' * 64,
                          '--issued-at', 'bad', '--expires-at', 'bad']):
                self.assertEqual(command.main(argv), 1)
        source = SOURCE.read_text()
        self.assertNotIn('import subprocess', source)
        self.assertNotIn('import socket', source)
        self.assertNotIn('os.environ', source)
        self.assertNotIn('from publication', source)

    def test_fixed_ack_caps_match_actual_fresh_profile_and_reject_mutable_map(self):
        self.assertEqual(dict(command.READS), {
            'gateway-ack': ('public-gateway-ack.json', 65536),
            'yacht-observation-ack': ('public-yacht-observation-ack.json', 524288),
            'yacht-effects-ack': ('public-yacht-effects-ack.json', 65536),
            'status': ('public-runtime-status.json', 16384)})
        with self.assertRaises(TypeError): command.READS['configuration'] = ('public-runtime.json', 16384)
        kernel = command._sources(command.capture_command_sources(KERNEL.read_bytes()))
        for name, maximum in command.READS.values(): self.assertEqual(kernel.CAPS[name], maximum)


class CommandFixture:
    """Counted, isolated fixed-root/UID/pin substitution; cannot mint real brands."""
    def __init__(self):
        self.base = KernelFixture()
        self.base.lock.close(); self.base.scope.close()
        parent = self.base.folder / 'host' / self.base.server
        parent.mkdir(parents=True, mode=0o700)
        self.base.root.rename(parent / '.amz')
        self.base.root = parent / '.amz'
        self.root, self.folder = self.base.root, self.base.folder
        raw = self.base.module_file.read_bytes()
        self.kernel_file = self.folder / 'publication.py'; self.kernel_file.write_bytes(raw)
        source = SOURCE.read_text()
        substitutions = {
            command.KERNEL_SHA256: hashlib.sha256(raw).hexdigest(),
            'os.geteuid() == 65532 and os.getegid() == 65532':
                'os.geteuid() == ' + str(os.geteuid()) + ' and os.getegid() == ' + str(os.getegid()),
        }
        for before, after in substitutions.items():
            if source.count(before) != 1: raise AssertionError('fixed fixture command anchor changed')
            source = source.replace(before, after)
        self.module_file = self.folder / 'fixture_command.py'; self.module_file.write_text(source)
        self.k = load(self.module_file, 'isolated_publication_command_' + uuid.uuid4().hex)
        self.sources = self.k.capture_command_sources(raw)
        self.handles, self.children = [], []

    def open(self, pair=None):
        pair = pair or dates()
        handle = self.k.open_host_command(self.sources, self.base.server, self.base.pin, *pair)
        self.handles.append(handle)
        return handle, pair

    def close(self):
        for child in self.children:
            if child.poll() is None: child.kill()
            child.communicate(timeout=5)
        for handle in self.handles:
            state = self.k._COMMANDS.get(handle)
            if state and not state['closed']:
                try: handle.close()
                except self.k.PublicationCommandRefused: pass
        self.base.close()

    def cli(self, raw, pair, *, timeout=7):
        return subprocess.run([sys.executable, '-I', '-B', str(self.module_file), '--once',
                               '--server-uuid', self.base.server, '--scope-sha256', self.base.pin,
                               '--issued-at', pair[0], '--expires-at', pair[1]],
                              input=raw, capture_output=True, timeout=timeout)


@unittest.skipUnless(sys.platform == 'linux', 'Real Linux owned FD/flock source cases; not host qualification')
class LinuxCommandTests(unittest.TestCase):
    def setUp(self): self.f = CommandFixture()
    def tearDown(self): self.f.close()

    def test_actual_kernel_publishes_only_fixed_control_and_one_shot_cannot_retry(self):
        handle, pair = self.f.open()
        operation, payload, _ = observation(self.f.base.binding, pair)
        raw, _ = request(self.f.base.binding, pair, action='publish', channel='yacht-observation',
                         payload=base64.b64encode(payload).decode(), operation=operation)
        response = handle.execute(raw)
        self.assertEqual((self.f.root / 'public-yacht-observation-control.json').read_bytes(), payload)
        self.assertEqual(response['result']['operationId'], operation)
        self.assertFalse(response['nativeAcknowledged'])
        self.assertFalse(response['activation'])
        state = self.f.k._COMMANDS[handle]
        self.assertTrue(state['publicationAttempted'])
        self.assertFalse(state['uncertain'])
        with self.assertRaisesRegex(self.f.k.PublicationCommandRefused, 'used'): handle.execute(raw)
        self.assertTrue(state['publicationAttempted'])
        self.assertFalse(state['uncertain'])
        self.assertEqual((self.f.root / 'public-yacht-observation-control.json').read_bytes(), payload)
        self.assertFalse(handle.close()['publicationUncertain'])

    def test_actual_reads_return_exact_bounded_bytes_or_absent_without_native_proof(self):
        for channel, (name, _) in self.f.k.READS.items():
            handle, pair = self.f.open()
            raw, _ = request(self.f.base.binding, pair, channel=channel)
            response = handle.execute(raw)
            self.assertEqual(response['result'], {'state': 'absent', 'payload': None, 'payloadSha256': None, 'bytes': 0})
            handle.close()
            payload = canonical({'schema': 'synthetic-source-only-ack', 'channel': channel})
            self.f.base.write(name, payload)
            handle, pair = self.f.open(); raw, _ = request(self.f.base.binding, pair, channel=channel)
            response = handle.execute(raw)
            self.assertEqual(base64.b64decode(response['result']['payload']), payload)
            self.assertEqual(response['result']['payloadSha256'], hashlib.sha256(payload).hexdigest())
            self.assertFalse(response['nativeSaveDurable']); handle.close()

    def test_payload_context_operation_window_and_path_selectors_fail_before_any_write(self):
        for changes in ({'channel': '../public-runtime.json'}, {'channel': 'configuration'},
                        {'identity': identity()}, {'payload': 'e30='}, {'extra': 1},
                        {'expiresAt': dates(1000)[1]}, {'action': 'delete'}):
            handle, pair = self.f.open()
            raw, _ = request(self.f.base.binding, pair)
            value = {**json.loads(raw), **changes}
            with self.assertRaises(Exception): handle.execute(canonical(value))
            self.assertEqual(sorted(p.name for p in self.f.root.iterdir()),
                             ['public-control-publication.lock', 'public-publication-scope.json'])
            handle.close()
        handle, pair = self.f.open()
        operation, payload, _ = observation(self.f.base.binding, pair)
        raw, _ = request(self.f.base.binding, pair, action='publish', channel='yacht-observation',
                         payload=base64.b64encode(payload).decode(), operation=str(uuid.uuid4()))
        with self.assertRaises(Exception): handle.execute(raw)
        self.assertFalse(self.f.k._COMMANDS[handle]['publicationAttempted'])

    def test_pending_and_oversize_ack_symlink_hardlink_or_mode_refuse_without_mutation(self):
        name = 'public-yacht-effects-ack.json'; target = self.f.root / name
        cases = ('pending', 'oversize', 'symlink', 'hardlink', 'mode')
        for kind in cases:
            if kind == 'pending': self.f.base.write('.public-yacht-effects-control.json.publication-pending', b'x')
            elif kind == 'oversize': self.f.base.write(name, b'x' * 65537)
            elif kind == 'symlink': target.symlink_to(self.f.root / self.f.base.k.LOCK)
            elif kind == 'hardlink':
                source = self.f.folder / 'separate-hardlink-source'
                source.write_bytes(b'x'); source.chmod(0o600); os.link(source, target)
            else: self.f.base.write(name, b'x'); target.chmod(0o644)
            handle, pair = self.f.open()
            raw, _ = request(self.f.base.binding, pair, channel='yacht-effects-ack')
            with self.assertRaises(Exception): handle.execute(raw)
            handle.close()
            residue = self.f.root / '.public-yacht-effects-control.json.publication-pending'
            self.assertTrue(residue.exists() if kind == 'pending' else target.exists())
            # Explicit isolated fixture maintenance only; production has no cleanup API.
            (residue if kind == 'pending' else target).unlink()

    def test_lost_readback_after_replace_is_sticky_unknown_and_never_redispatched(self):
        handle, pair = self.f.open()
        state = self.f.k._COMMANDS[handle]; kernel = state['kernel']
        operation, payload, _ = observation(self.f.base.binding, pair)
        raw, _ = request(self.f.base.binding, pair, action='publish', channel='yacht-observation',
                         payload=base64.b64encode(payload).decode(), operation=operation)
        original = kernel._read_named
        def lost(directory, name, maximum):
            if name == 'public-yacht-observation-control.json': raise OSError('synthetic lost readback')
            return original(directory, name, maximum)
        with patch.object(kernel, '_read_named', side_effect=lost):
            with self.assertRaises(OSError): handle.execute(raw)
        self.assertEqual((self.f.root / 'public-yacht-observation-control.json').read_bytes(), payload)
        self.assertTrue(state['publicationAttempted'])
        self.assertTrue(state['uncertain'])
        with self.assertRaisesRegex(self.f.k.PublicationCommandRefused, 'held'): handle.execute(raw)
        self.assertTrue(state['uncertain'])
        closure = handle.close()
        self.assertTrue(closure['publicationUncertain']); self.assertTrue(closure['processExitRequired'])

    def test_delayed_actual_read_and_cancel_cannot_outlive_original_window(self):
        self.f.base.write('public-runtime-status.json', b'{}')
        handle, pair = self.f.open(dates(150))
        state = self.f.k._COMMANDS[handle]; original = state['kernel']._read_named
        raw, _ = request(self.f.base.binding, pair)
        def delayed(*args):
            value = original(*args); time.sleep(.18); return value
        with patch.object(state['kernel'], '_read_named', side_effect=delayed):
            with self.assertRaises(Exception): handle.execute(raw)
        handle.close()
        handle, pair = self.f.open(); raw, _ = request(self.f.base.binding, pair)
        handle.cancel()
        with self.assertRaisesRegex(self.f.k.PublicationCommandRefused, 'expired'): handle.execute(raw)
        handle.close()

    def test_explicit_cli_captures_actual_source_and_requires_one_eof_delimited_frame(self):
        self.f.base.write('public-runtime-status.json', b'{"fixture":true}')
        raw, pair = request(self.f.base.binding)
        result = self.f.cli(raw, pair)
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(result.stdout, canonical(response))
        self.assertEqual(response['requestSha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(base64.b64decode(response['result']['payload']), b'{"fixture":true}')
        self.assertEqual(result.stderr, b'')
        for suffix in (b'\n', b'{}', b'x' * self.f.k.REQUEST_LIMIT):
            raw, pair = request(self.f.base.binding)
            result = self.f.cli(raw + suffix, pair)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')

    def test_another_process_cannot_observe_partial_ack_under_real_shared_kernel_lock(self):
        # Construct both handles before the child holds EX: opening a real
        # publisher also checks the enrolled lock, rather than bypassing it.
        handle, parent_pair = self.f.open()
        raw, _ = request(self.f.base.binding, parent_pair)
        script = '''import importlib.util,json,os,sys,time
from pathlib import Path
file,server,pin,root,pair=sys.argv[1:]
spec=importlib.util.spec_from_file_location('isolated_child_command',file)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
sources=c.capture_command_sources(Path(file).with_name('publication.py').read_bytes())
h=c.open_host_command(sources,server,pin,*json.loads(pair));s=c._COMMANDS[h];k=s['kernel']
with s['lock'].hold(s['nativeWindow']):
 path=Path(root)/'public-runtime-status.json'
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:
  os.write(fd,b'{"complete":');os.fsync(fd)
  (Path(root).parent.parent.parent/'locked').write_bytes(b'1')
  end=time.monotonic()+3
  while not (Path(root).parent.parent.parent/'continue').exists():
   if time.monotonic()>end:raise RuntimeError('source fixture barrier')
   time.sleep(.005)
  os.write(fd,b'true}');os.fsync(fd)
 finally:os.close(fd)
h.close()
'''
        pair = dates()
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', script, str(self.f.module_file),
                                  self.f.base.server, self.f.base.pin, str(self.f.root), json.dumps(pair)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.f.children.append(child)
        end = time.monotonic() + 3
        while not (self.f.folder / 'locked').exists():
            if child.poll() is not None or time.monotonic() > end: self.fail('child source lock not acquired')
            time.sleep(.005)
        result, errors = [], []
        def read():
            try: result.append(handle.execute(raw))
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=read); thread.start(); time.sleep(.04)
        self.assertTrue(thread.is_alive()); self.assertEqual(result, [])
        (self.f.folder / 'continue').write_bytes(b'1')
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        self.assertEqual(base64.b64decode(result[0]['result']['payload']), b'{"complete":true}')

    def test_exact_close_failure_requires_process_exit_without_numeric_fd_retry(self):
        handle, pair = self.f.open()
        state = self.f.k._COMMANDS[handle]; kernel = state['kernel']
        descriptor = kernel._LOCKS[state['lock']]['fd']; original = kernel.os.close
        closed = []
        def close_then_fail(fd):
            if fd == descriptor:
                closed.append(fd); original(fd); raise OSError('source fixture close result lost')
            return original(fd)
        with patch.object(kernel.os, 'close', side_effect=close_then_fail):
            with self.assertRaisesRegex(self.f.k.PublicationCommandRefused, 'close_unknown') as caught:
                handle.close()
        self.assertTrue(caught.exception.process_exit_required)
        self.assertEqual(closed, [descriptor])
        with self.assertRaisesRegex(self.f.k.PublicationCommandRefused, 'closed'): handle.close()
        self.assertEqual(closed, [descriptor])


if __name__ == '__main__': unittest.main()

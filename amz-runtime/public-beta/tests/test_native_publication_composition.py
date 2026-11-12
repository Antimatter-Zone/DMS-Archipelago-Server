"""Actual captured file implementations; no engine, transport or native proof."""
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from test_native_publication import Fixture as KernelFixture, dates, load

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'public-beta-publication/runtime/native_composition.py'
PATHS = {
    'publication': ROOT / 'public-beta-publication/runtime/publication.py',
    'gateway_barrier': ROOT / 'public-beta/runtime/gateway_barrier.py',
    'native_files': ROOT / 'public-beta/runtime/native_files.py',
    'checkpoint_custody': ROOT / 'public-beta/runtime/checkpoint_custody.py',
    'native_checkpoint': ROOT / 'public-beta/runtime/native_checkpoint.py',
    'native_budget': ROOT / 'public-beta-yacht-actions/runtime/native_budget.py',
    'gateway_hooks': ROOT / 'public-beta/runtime/gateway_hooks.py',
    'native_yacht_effects': ROOT / 'public-beta-effects/runtime/native_yacht_effects.py',
    'native_yacht_observations': ROOT / 'public-beta-observations/runtime/native_yacht_observations.py',
}
composition = load(SOURCE, 'unchanged_native_composition_source_fixture')


def bundle():
    return {name: path.read_bytes() for name, path in PATHS.items()}


class PureCompositionTests(unittest.TestCase):
    def test_all_nine_sources_are_pinned_before_any_execution(self):
        actual = bundle()
        self.assertEqual(set(actual), set(composition.SOURCE_PINS))
        self.assertTrue(all(hashlib.sha256(actual[name]).hexdigest() == digest
                            for name, digest in composition.SOURCE_PINS.items()))
        bad = {**actual, 'native_yacht_observations': actual['native_yacht_observations'] + b'\n'}
        with patch.object(composition, 'compile', side_effect=AssertionError('must not compile'), create=True):
            with self.assertRaisesRegex(composition.NativeCompositionRefused, 'source_pin'):
                composition.capture_native_sources(bad)
        for changed in ({}, {**actual, 'arbitrary': b'code'}, {**actual, 'publication': memoryview(actual['publication'])}):
            with self.assertRaises(composition.NativeCompositionRefused): composition.capture_native_sources(changed)

    def test_isolated_actual_imports_share_types_without_mutating_sys_modules(self):
        previous = sys.modules.get('native_files')
        sources = composition.capture_native_sources(bundle()); modules = composition._sources(sources)['modules']
        actual = modules['native_files'].NativeFiles
        self.assertIs(modules['native_checkpoint'].NativeFiles, actual)
        self.assertIs(modules['native_yacht_effects'].NativeFiles, actual)
        self.assertIs(modules['native_yacht_observations'].NativeFiles, actual)
        self.assertIs(sys.modules.get('native_files'), previous)
        self.assertNotIn(modules['publication'].SCOPE, modules['native_budget'].PUBLISH)
        self.assertEqual(dict(modules['native_budget'].CAPS), dict(modules['publication'].CAPS))
        with self.assertRaises(TypeError): modules['native_budget'].CAPS['caller.json'] = 4

    def test_json_subclasses_and_unregistered_instances_are_not_source_or_composition_authority(self):
        for value in ({}, object.__new__(composition.CapturedNativeSources)):
            with self.assertRaisesRegex(composition.NativeCompositionRefused, 'source_brand'):
                composition.open_native_composition(value, 'a' * 64, *dates())
        with self.assertRaises(composition.NativeCompositionRefused): composition.CapturedNativeSources()
        with self.assertRaises(composition.NativeCompositionRefused): composition.NativePublicationComposition()


class NativeFixture:
    def __init__(self):
        self.base = KernelFixture(); self.folder, self.root = self.base.folder, self.base.root
        raw = bundle()
        raw['publication'] = self.base.module_file.read_bytes()
        source = raw['native_files'].decode()
        anchor = 'ROOT = Path("/home/container/.amz")'
        if source.count(anchor) != 1: raise AssertionError('native file root anchor changed')
        raw['native_files'] = source.replace(anchor, 'ROOT = Path(' + repr(str(self.root)) + ')').encode()
        guard = SOURCE.read_text()
        for name in ('publication', 'native_files'):
            old = composition.SOURCE_PINS[name]; new = hashlib.sha256(raw[name]).hexdigest()
            if guard.count(old) != 1: raise AssertionError('guard source pin anchor changed')
            guard = guard.replace(old, new)
        file = self.folder / 'fixture_composition.py'; file.write_text(guard)
        self.module_file, self.raw = file, raw
        self.k = load(file, 'isolated_composition_fixture_' + uuid.uuid4().hex)
        self.sources = self.k.capture_native_sources(raw)
        self.guard = self.k.open_native_composition(self.sources, self.base.pin, *dates())
        self.guard.files.initialize(self.guard.components['gateway_barrier']['initial_state'](self.base.binding))

    def close(self):
        try:
            state = self.k._COMPOSITIONS.get(self.guard)
            if state is not None and not state['closed']:
                try: self.guard.close()
                except self.k.NativeCompositionRefused: pass
        finally:
            self.base.close()

    def child(self, body):
        self.guard.close()
        inputs = self.folder / 'captured-sources'; inputs.mkdir()
        for name, raw in self.raw.items(): (inputs / (name + '.py')).write_bytes(raw)
        script = '''import importlib.util,json,os,sys,time,threading
from pathlib import Path
file,inputs,pin,root=sys.argv[1:]
spec=importlib.util.spec_from_file_location('actual_child_composition',file)
k=importlib.util.module_from_spec(spec);spec.loader.exec_module(k)
sources=k.capture_native_sources({name:(Path(inputs)/(name+'.py')).read_bytes() for name in k.SOURCE_PINS})
def dates(ms=4500):
 from datetime import datetime,timezone
 def iso(n):return datetime.fromtimestamp(n/1000,timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
 now=time.time_ns()//1000000
 return iso(now),iso(now+ms)
g=k.open_native_composition(sources,pin,*dates())
state=k._COMPOSITIONS[g];pub=state['modules']['publication']
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script + body,
                                 str(self.module_file), str(inputs), self.base.pin, str(self.root)],
                                capture_output=True, text=True, timeout=15)
        if result.returncode: raise AssertionError('actual child source fixture: ' + result.stderr)
        return json.loads(result.stdout)


@unittest.skipUnless(sys.platform == 'linux', 'actual captured Linux native file/budget implementations')
class LinuxCompositionTests(unittest.TestCase):
    def setUp(self):
        self.f = NativeFixture(); self.addCleanup(self.f.close)

    def test_real_owner_journal_status_and_binary_save_are_bounded_and_coordinated(self):
        f = self.f; state = f.k._COMPOSITIONS[f.guard]
        self.assertIs(type(f.guard.files), state['modules']['native_files'].NativeFiles)
        self.assertTrue((f.root / 'public-gateway-native.lock').is_file())
        self.assertEqual(f.guard.files.load_journal()['ready'], False)
        f.guard.files.publish_ack({'schema': 'source-file-writer-fixture-only'})
        f.guard.publish_status({'schema': 'source-status-fixture-only'})
        save = f.guard.open_save_files(); self.assertIs(type(save), state['modules']['native_checkpoint'].NativeSaveFiles)
        save.write(b'actual-source-binary-writer-fixture'); self.assertEqual(save.read()[0], b'actual-source-binary-writer-fixture')
        sizes = f.guard.audit()
        self.assertEqual(sizes['public-seed.apsave'], len(b'actual-source-binary-writer-fixture'))
        self.assertFalse(f.guard.describe()['activation']); self.assertFalse(f.guard.describe()['qualification'])
        with self.assertRaises(TypeError): f.guard.components['caller-module'] = object()

    def test_even_direct_captured_save_constructor_is_bound_to_actual_budget_before_return(self):
        f = self.f; save_type = f.guard.components['native_checkpoint']['NativeSaveFiles']
        save = save_type(f.guard.files); save.write(b'old')
        with self.assertRaises(Exception): save.write(b'x' * 524289)
        self.assertEqual((f.root / 'public-seed.apsave').read_bytes(), b'old')
        self.assertEqual(list(f.root.glob('.public-seed.apsave.pending-*')), [])

    def test_unknown_pending_holds_native_before_control_reads_and_keeps_evidence_on_close(self):
        f = self.f
        pending = f.base.k._pending(f.base.k.CONTROLS['gateway']); f.base.write(pending, b'unknown')
        with self.assertRaises(Exception): f.guard.files.read_control()
        self.assertTrue(f.guard.describe()['uncertain'])
        with self.assertRaises(f.k.NativeCompositionRefused): f.guard.close()
        with self.assertRaises(f.k.NativeCompositionRefused): f.guard.close()
        self.assertEqual((f.root / pending).read_bytes(), b'unknown')
        self.assertTrue((f.root / 'public-gateway-native.lock').is_file())

    def test_removing_external_symptom_does_not_reopen_a_held_composition(self):
        f = self.f
        pending = f.base.k._pending(f.base.k.CONTROLS['gateway']); f.base.write(pending, b'unknown')
        with self.assertRaises(Exception): f.guard.files.read_control()
        (f.root / pending).unlink()  # Fixture-only manual repair cannot revive the old owner.
        admitted = []
        with self.assertRaises(f.k.NativeCompositionRefused):
            with f.guard.transaction(): admitted.append(True)
        with self.assertRaises(f.k.NativeCompositionRefused): f.guard.audit()
        with self.assertRaises(f.k.NativeCompositionRefused): f.guard.publish_status({'schema': 'must-not-publish'})
        self.assertEqual(admitted, []); self.assertFalse((f.root / 'public-runtime-status.json').exists())

    def test_inaccessible_native_read_close_error_requires_process_exit_without_reclosing_reused_fd(self):
        f = self.f; original = os.close; foreign = []; foreign_path = f.folder / 'foreign-after-native-close'
        foreign_path.write_bytes(b'foreign')
        def close(fd):
            try: path = os.readlink('/proc/self/fd/' + str(fd))
            except OSError: path = ''
            if path.endswith('/public-gateway-journal.json'):
                original(fd)
                replacement = os.open(foreign_path, os.O_RDONLY)
                self.assertEqual(replacement, fd); foreign.append(replacement)
                raise OSError('fixture native close acknowledgement lost')
            return original(fd)
        try:
            with patch.object(os, 'close', close):
                with self.assertRaises(OSError): f.guard.files.load_journal()
            self.assertEqual(len(foreign), 1)
            self.assertTrue(f.guard.describe()['processExitRequired'])
            with self.assertRaises(f.k.NativeCompositionRefused): f.guard.close()
            self.assertEqual(os.read(foreign[0], 7), b'foreign')
            self.assertTrue((f.root / 'public-gateway-native.lock').is_file())
        finally:
            for fd in foreign: original(fd)

    def test_nested_actual_native_transactions_keep_one_window_and_one_kernel_hold(self):
        f = self.f; state = f.k._COMPOSITIONS[f.guard]
        with f.guard.transaction():
            original = state['mutex'].window
            f.guard.audit(); f.guard.publish_status({'schema': 'nested-source-fixture'})
            with f.guard.transaction():
                self.assertIs(state['mutex'].window, original)
                self.assertEqual(f.guard.files.load_journal()['ready'], False)
            self.assertIs(state['mutex'].window, original)

    def test_effects_like_engine_phase_keeps_native_rlock_without_holding_publication_flock(self):
        f = self.f; state = f.k._COMPOSITIONS[f.guard]
        self.assertIs(f.guard.files._mutex, state['rawNativeMutex'])
        with f.guard.files._mutex:
            f.guard.files.commit_journal(f.guard.files.load_journal())
            child = f.base.child('''import uuid
publisher=k.FixedControlPublisher(scope,lock,window())
binding=json.loads((Path(root)/k.SCOPE).read_text())['identity'];now=time.time_ns()//1000000
value={'schema':'amz.ap.public-beta.gateway-control.v2','operationId':str(uuid.uuid4()),'command':'revoke_slot','identity':binding,'gate':{},'payload':{},'issuedAt':iso(now),'expiresAt':iso(now+4500)}
publisher.publish('gateway',value['operationId'],json.dumps(value,sort_keys=True,separators=(',',':')).encode(),k.capture_window(value['issuedAt'],value['expiresAt']))
lock.close();scope.close()
''')
            f.base.finish(child)  # Must finish while the genuine native RLock remains held.
        self.assertFalse(f.guard.describe()['uncertain'])

    def test_actual_native_save_pending_is_not_visible_to_cross_process_publisher_audit(self):
        f = self.f; save = f.guard.open_save_files(); original = os.fsync
        staged, release = threading.Event(), threading.Event(); errors = []
        def pause(fd):
            original(fd)
            if os.readlink('/proc/self/fd/' + str(fd)).split('/')[-1].startswith('.public-seed.apsave.pending-'):
                staged.set()
                if not release.wait(3): raise AssertionError('save source barrier timeout')
        def write():
            try: save.write(b'actual bounded native-save source bytes')
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=write)
        try:
            with patch.object(os, 'fsync', pause):
                thread.start(); self.assertTrue(staged.wait(3))
                child = f.base.child('''(folder/'audit-attempting').write_text('yes')
with lock.hold(window()):
 k._audit(k._SCOPES[scope]);(folder/'audit-completed').write_text('yes')
lock.close();scope.close()
''')
                f.base.wait_file('audit-attempting')
                self.assertFalse((f.folder / 'audit-completed').exists())
                release.set(); thread.join(3); self.assertFalse(thread.is_alive())
                f.base.finish(child)
            self.assertEqual(errors, []); self.assertTrue((f.folder / 'audit-completed').is_file())
            self.assertFalse(f.guard.describe()['uncertain'])
        finally:
            release.set(); thread.join(3)

    def test_cross_process_publisher_cannot_expose_partial_controls_to_actual_read_audit_and_save(self):
        f = self.f
        child = f.base.child('''import uuid
publisher=k.FixedControlPublisher(scope,lock,window())
binding=json.loads((Path(root)/k.SCOPE).read_text())['identity']
(folder/'publisher-ready').write_text('yes')
while not (folder/'publisher-start').exists(): time.sleep(.002)
for n in range(16):
 now=time.time_ns()//1000000
 value={'schema':'amz.ap.public-beta.gateway-control.v2','operationId':str(uuid.uuid4()),'command':'revoke_slot','identity':binding,'gate':{},'payload':{'fixture':n},'issuedAt':iso(now),'expiresAt':iso(now+4500)}
 publisher.publish('gateway',value['operationId'],json.dumps(value,sort_keys=True,separators=(',',':')).encode(),k.capture_window(value['issuedAt'],value['expiresAt']))
(folder/'publisher-done').write_text('yes')
lock.close();scope.close()
''')
        f.base.wait_file('publisher-ready'); (f.folder / 'publisher-start').write_text('yes')
        save = f.guard.open_save_files()
        for n in range(16):
            control = f.guard.files.read_control()
            if control is not None: self.assertEqual(control['identity'], f.base.binding)
            f.guard.audit(); save.write(('source-save-' + str(n)).encode())
        f.base.finish(child)
        self.assertTrue((f.folder / 'publisher-done').is_file())
        self.assertFalse(f.guard.describe()['uncertain'])

    def test_expired_scope_closes_positively_owned_handles_without_unlinking_native_evidence(self):
        f = self.f; state = f.k._COMPOSITIONS[f.guard]; pub = state['modules']['publication']
        descriptors = [f.guard.files._lock, f.guard.files._directory, state['budget'].fd]
        pub._SCOPES[state['scope']]['deadline'] = time.monotonic_ns() - 1  # Negative-only shortening.
        with self.assertRaises(f.k.NativeCompositionRefused): f.guard.close()
        self.assertTrue((f.root / 'public-gateway-native.lock').is_file())
        for fd in descriptors:
            with self.assertRaises(OSError): os.fstat(fd)
        self.assertTrue(f.guard.describe()['uncertain'])

    def test_original_opening_window_cannot_be_renewed_after_bootstrap(self):
        f = self.f; f.guard.close()
        modules = f.k._sources(f.sources)['modules']; original = modules['native_budget'].NativeBudget.install
        def delayed(budget, owner):
            result = original(budget, owner); time.sleep(.15); return result
        with patch.object(modules['native_budget'].NativeBudget, 'install', delayed):
            with self.assertRaises(f.k.NativeCompositionRefused):
                f.k.open_native_composition(f.sources, f.base.pin, *dates(100))
        self.assertTrue((f.root / 'public-gateway-native.lock').is_file())

    def test_normal_close_settles_actual_native_and_budget_handles_but_is_not_resource_release(self):
        f = self.f; state = f.k._COMPOSITIONS[f.guard]
        descriptors = [f.guard.files._lock, f.guard.files._directory, state['budget'].fd]
        result = f.guard.close()
        self.assertFalse(result['resourceReleaseAuthorized']); self.assertFalse(result['activation'])
        self.assertFalse((f.root / 'public-gateway-native.lock').exists())
        for fd in descriptors:
            with self.assertRaises(OSError): os.fstat(fd)
        self.assertEqual(f.guard.close()['activation'], False)

    def test_queued_real_native_user_is_fenced_after_close_timed_out_and_requires_process_exit(self):
        result = self.f.child('''held=threading.Event();release=threading.Event();queued=threading.Event()
errors=[];reads=[]
raw=state['rawNativeMutex']
class ObserveRealMutex:
 def acquire(self,blocking=False):
  if threading.current_thread().name=='queued':queued.set()
  return raw.acquire(blocking=blocking)
 def release(self):return raw.release()
state['mutex'].native=ObserveRealMutex()
original_audit=state['rawAudit']
def audit():
 if threading.current_thread().name=='queued':reads.append(True)
 return original_audit()
state['rawAudit']=audit
def holder():
 try:
  with g.transaction():held.set();release.wait(5)
 except BaseException as e:errors.append(str(e))
def waiter():
 try:g.audit()
 except BaseException as e:errors.append(str(e))
a=threading.Thread(target=holder);a.start();assert held.wait(3)
b=threading.Thread(target=waiter,name='queued');b.start();assert queued.wait(3)
original_window=k._coordination_window
def short(s):
 if threading.current_thread() is threading.main_thread():return pub.capture_window(*dates(100))
 return original_window(s)
k._coordination_window=short
try:g.close();raise AssertionError('close unexpectedly settled')
except k.NativeCompositionRefused as e:assert e.process_exit_required
release.set();a.join(3);b.join(3);assert not a.is_alive() and not b.is_alive()
assert reads==[] and len(errors)==2
print(json.dumps({'reads':len(reads),'requiresExit':g.describe()['processExitRequired'],'activation':g.describe()['activation']}))
''')
        self.assertEqual(result, {'reads': 0, 'requiresExit': True, 'activation': False})

    def test_actual_partial_native_constructor_close_error_never_retries_foreign_reused_fd(self):
        result = self.f.child('''g.close()
modules=k._sources(sources)['modules'];native=modules['native_files'].NativeFiles
original_write=native._write_all;original_close=os.close;foreign=[]
foreign_path=Path(root).parent/'constructor-foreign';foreign_path.write_bytes(b'foreign')
def fail_write(fd,raw):
 original_write(fd,raw);raise OSError('fixture constructor write failed')
def close(fd):
 try:path=os.readlink('/proc/self/fd/'+str(fd))
 except OSError:path=''
 if path.endswith('/public-gateway-native.lock'):
  original_close(fd);replacement=os.open(foreign_path,os.O_RDONLY);assert replacement==fd;foreign.append(fd)
  raise OSError('fixture constructor close acknowledgement lost')
 return original_close(fd)
native._write_all=staticmethod(fail_write);os.close=close
try:
 try:k.open_native_composition(sources,pin,*dates());raise AssertionError('constructor unexpectedly passed')
 except k.NativeCompositionRefused as e:assert e.process_exit_required
 assert len(foreign)==1 and os.read(foreign[0],7)==b'foreign'
 print(json.dumps({'foreignPreserved':True,'requiresExit':True,'activation':False}))
finally:
 os.close=original_close
 for fd in foreign:original_close(fd)
''')
        self.assertEqual(result, {'foreignPreserved': True, 'requiresExit': True, 'activation': False})

    def test_actual_partial_budget_constructor_close_error_requires_exit_without_fd_retry(self):
        result = self.f.child('''g.close()
modules=k._sources(sources)['modules'];budget_type=modules['native_budget'].NativeBudget
original=budget_type.close;foreign=[]
foreign_path=Path(root).parent/'budget-foreign';foreign_path.write_bytes(b'foreign')
(Path(root)/'unknown-source-fixture').write_bytes(b'unknown')
def fail_close(self):
 fd=self.fd;original(self)
 replacement=os.open(foreign_path,os.O_RDONLY);assert replacement==fd;foreign.append(replacement)
 raise RuntimeError('fixture budget close acknowledgement unknown')
budget_type.close=fail_close
try:
 try:k.open_native_composition(sources,pin,*dates());raise AssertionError('constructor unexpectedly passed')
 except k.NativeCompositionRefused as e:assert e.process_exit_required
 assert len(foreign)==1 and os.read(foreign[0],7)==b'foreign'
 print(json.dumps({'foreignPreserved':True,'requiresExit':True,'activation':False}))
finally:
 for fd in foreign:os.close(fd)
''')
        self.assertEqual(result, {'foreignPreserved': True, 'requiresExit': True, 'activation': False})

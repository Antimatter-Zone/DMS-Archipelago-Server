"""Separate restore source guards/composition. No engine import or listener."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_loader import configuration
from test_checkpoint_custody import NOW
from test_native_restore import restore_fixture

ROOT = Path(__file__).resolve().parents[2] / 'public-beta-restore'
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result
builder = module('restore_builder_fixture', ROOT / 'build.py')
loader = module('restore_loader_fixture', ROOT / 'runtime/loader.py')


def artifact():
    _, _, _, dependencies, inputs, transfer, admitted, provenance = builder.reviewed_source()
    value = builder.artifact_document('a' * 40, dependencies, inputs, transfer, admitted, provenance)
    return value, inputs, admitted


def config():
    value = configuration()
    value.update(schema='amz.ap.public-beta.native-restore-configuration.v1', profileId='public-native-restricted-restore-v1',
                 journalMode='migrate', requiredCheckpointSha256='c' * 64, requiredMigrationSha256='d' * 64, oldStopReceiptSha256='e' * 64)
    return value


class RestoreGuards(unittest.TestCase):
    def test_pinned_foundations_and_new_inventory_are_separate_from_fresh_profile(self):
        value, inputs, _ = artifact()
        self.assertEqual(len(inputs), 13)
        self.assertEqual(value['sourceFoundation']['freshSourceCommit'], '79e2b0d293d9d6f1f12ee05d6bfe8cb13fd6392e')
        self.assertEqual(value['sourceFoundation']['restoreSourceCommit'], '88cc5aa87f023d734d8e516fcc23f722c252a9a0')
        self.assertEqual(value['engine']['worldPackSha256'], loader.WORLD_PACK_SHA)
        self.assertEqual(builder.digest(inputs['fresh-runtime-profile.json']), loader.WORLD_PACK_SHA)
        self.assertEqual(builder.digest(inputs['runtime-profile.json']), loader.PROFILE_SHA)
        self.assertNotEqual(loader.PROFILE_SHA, loader.WORLD_PACK_SHA)
        self.assertFalse(any(enabled for key, enabled in value['qualification'].items() if key != 'sourceOnly'))

    def test_actual_python_and_node_validators_require_the_independent_new_artifact_pin(self):
        value, _, _ = artifact(); raw = json.dumps(value).encode()
        self.assertEqual(loader.validate_artifact(raw, loader.sha(raw)), value)
        script = "import{validateArtifact}from " + json.dumps((ROOT/'runtime/launcher.mjs').as_uri()) + ";import{validateArtifact as fresh}from " + json.dumps((ROOT.parent/'public-beta/runtime/launcher.mjs').as_uri()) + ";import{readFileSync}from'node:fs';const v=JSON.parse(readFileSync(0,'utf8'));validateArtifact(Buffer.from(v.raw),v.sha);let refused=false;try{fresh(Buffer.from(v.raw),v.sha);}catch{refused=true;}if(!refused)throw Error('fresh-profile-accepted-restore');console.log('verified-source-only');"
        result = subprocess.run(['node', '--input-type=module', '-e', script], input=json.dumps({'raw':raw.decode(),'sha':loader.sha(raw)}).encode(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertEqual(result.stdout.strip(), b'verified-source-only')
        with self.assertRaises(loader.Refused): loader.validate_artifact(raw, 'f' * 64)
        for change in (lambda v:v.update(schema='amz.ap.public-beta.server-runtime.v1'), lambda v:v.update(profileId='public-disposable-beta-v1'),
                       lambda v:v['qualification'].update(restore=True), lambda v:v['ownedFiles'][0].update(path='../other.py'),
                       lambda v:v['sourceFoundation'].update(freshSourceCommit='b' * 40)):
            changed=copy.deepcopy(value);change(changed);encoded=json.dumps(changed).encode()
            with self.assertRaises(loader.Refused):loader.validate_artifact(encoded,loader.sha(encoded))

    def test_fresh_configuration_never_falls_back_to_restore_or_initializes_a_missing_journal(self):
        value = config(); self.assertEqual(loader.validate_configuration(value), value)
        with self.assertRaises(loader.Refused): loader.validate_configuration(configuration())
        for change in ({'journalMode':'initialize'}, {'requiredMigrationSha256':None}, {'requiredCheckpointSha256':None}, {'oldStopReceiptSha256':'f'}):
            with self.assertRaises(loader.Refused): loader.validate_configuration({**value, **change})
        source = (ROOT / 'runtime/loader.py').read_text()
        self.assertNotIn('files.initialize(', source)
        self.assertLess(source.index('adopted = custody_module.migrate('), source.index('import MultiServer'))
        self.assertIn("'amz.ap.public-beta.native-restore-status.v1'", source)
        self.assertIn("'held_ready'", source)

    def test_failed_guard_never_loads_owned_modules_or_engine(self):
        with patch.object(loader,'verify_inputs',side_effect=loader.Refused('synthetic_guard_failure')), patch.object(loader,'load_verified_module') as imported:
            with self.assertRaises(loader.Refused):loader.main()
            imported.assert_not_called()
        self.assertNotIn('MultiServer', sys.modules)

    def test_artifact_and_toolchain_metadata_use_captured_bytes_not_later_paths(self):
        _, _, _, dependencies, inputs, transfer, admitted, provenance = builder.reviewed_source()
        with patch.object(builder,'regular',side_effect=AssertionError('unexpected reread')):
            value=builder.artifact_document('a'*40,dependencies,inputs,transfer,admitted,provenance)
        self.assertEqual(value['toolchain']['dockerfileSha256'],builder.digest(admitted[builder.key(ROOT/'Dockerfile')]))
        changed=dict(admitted);changed[builder.key(builder.FRESH/'build.py')]=b"raise RuntimeError('must not execute')"
        with self.assertRaisesRegex(ValueError,'fresh_builder_changed'):
            builder.artifact_document('a'*40,dependencies,inputs,transfer,changed,provenance)

    def test_uncommitted_new_source_cannot_prepare_or_fetch_under_an_old_git_commit(self):
        public, base, _, _, _, _, admitted, _ = builder.reviewed_source()
        with patch.object(base,'fetch',side_effect=AssertionError('network must not be reached')) as fetch:
            # On a future clean commit, deliberately captured substituted bytes
            # must still fail Git proof rather than relabel them with that HEAD.
            changed=dict(admitted);changed[builder.key(ROOT/'runtime/loader.py')]=b'# uncommitted source\n'
            with self.assertRaises((ValueError,subprocess.CalledProcessError)):public.clean_commit(changed)
            fetch.assert_not_called()


class RestoreBinding(unittest.TestCase):
    def test_restore_precedes_new_barrier_and_never_replaces_native_context_class(self):
        x=restore_fixture(); restored=x.run()
        try:
            from gateway_barrier import NativeBarrier
            import gateway_hooks
            events=[]
            async def original(*_):pass
            class Context:
                host,port='0.0.0.0',38281
                connect_names,games,played_games={'Alice':(0,1)},{1:'Yacht Dice'},{'Archipelago','Yacht Dice'}
                non_hintable_names={};endpoints=[];auto_saver_thread=None
            native=SimpleNamespace(Context=Context,process_client_cmd=original,on_client_joined=original,on_client_disconnected=original,restricted_loads=lambda _: {})
            def restored_value(*_args,**_kwargs):events.append('native_restored_held');return restored
            def barrier(*args):events.append('new_barrier');return NativeBarrier(*args,clock=lambda:NOW)
            snapshots=SimpleNamespace(NativeSnapshots=lambda owner,context:events.append('serialized_writer') or SimpleNamespace(save_now=lambda:True))
            configuration_value=config();configuration_value.update(identity=x.manifest['newIdentity'],password='synthetic_rotated_master_'+'y'*40)
            state=loader.bind_native(native,configuration_value,{'engineCommit':loader.ENGINE_COMMIT,'worldPackSha256':loader.ENGINE_SHA,'defaultBlacklist':[],'overrides':{}},
                x.owner,SimpleNamespace(NativeBarrier=barrier),gateway_hooks,snapshots,SimpleNamespace(restore_native=restored_value),
                SimpleNamespace(CustodyFiles=lambda owner:x.f[3]),{'native-restore-profile.v1.json':b'synthetic'},b'synthetic seed',lambda:NOW)
            self.assertIs(native.Context,Context);context=Context();context._load_world_data();context.init_save()
            self.assertEqual(events,['serialized_writer','native_restored_held','new_barrier'])
            self.assertIs(state['context'],context);self.assertIs(state['hooks']._context,context)
            self.assertFalse(state['barrier'].state['ready']);self.assertEqual(state['barrier'].state['gates'],restored.state['gates'])
            state['barrier'].mark_ready()
            self.assertEqual(state['barrier'].state['generation'],restored.state['generation'])
            self.assertEqual(state['barrier'].state['lastDisconnectAt'],restored.state['lastDisconnectAt'])
            self.assertEqual(state['barrier'].state['initialReadyAt'],restored.state['initialReadyAt'])
            with self.assertRaises(loader.Refused):context.init_save()
        finally:restored.close()


if __name__=='__main__':unittest.main()

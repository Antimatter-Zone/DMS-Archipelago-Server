"""Pure source/data checks. No engine import, cache/context/image or listener."""
import copy
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2] / 'public-beta-yacht-actions'


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


policy = load('yacht_action_packet_source_fixture', ROOT / 'runtime/yacht_packet_policy.py')
loader = load('yacht_action_loader_source_fixture', ROOT / 'runtime/loader.py')
builder = load('yacht_action_builder_source_fixture', ROOT / 'build.py')
budget_module = load('yacht_action_budget_source_fixture', ROOT / 'runtime/native_budget.py')
base = load('yacht_action_foundation_source_fixture', ROOT.parent / 'public-beta/runtime/loader.py')


def connect():
    return {'cmd': 'Connect', 'name': 'Yacht_One', 'game': 'Yacht Dice', 'password': 'a' * 85,
            'uuid': str(uuid.uuid4()), 'version': {'class': 'Version', 'major': 0, 'minor': 6, 'build': 8},
            'tags': ['AP'], 'items_handling': 7, 'slot_data': True}


def configuration():
    ident = {k: str(uuid.uuid4()) for k in ('environmentId', 'dataEpoch', 'roomId', 'attemptId', 'runtimeLaunchId')}
    ident.update(appVariant='public-beta', policyId='public-disposable-beta-v1', allocationRevision=1, serverId='synthetic', seedRevision=1, credentialEpoch=1)
    ident['externalId'] = 'ap-beta-' + ident['roomId'] + '-r1'
    run = {k: ident[k] for k in ('appVariant', 'policyId', 'environmentId', 'dataEpoch', 'roomId', 'attemptId', 'seedRevision')}
    run.update(configurationRevision=1, seedArtifactSha256='a' * 64, seedName='Synthetic source check')
    return {'schema': 'amz.ap.public-beta.yacht-native-configuration.v1', 'profileId': loader.PROFILE, 'identity': ident,
            'runtimeArtifactSha256': 'b' * 64, 'executionProfileSha256': loader.PROFILE_SHA, 'worldPackSha256': base.PROFILE_SHA,
            'engineCommit': base.ENGINE_COMMIT, 'engineInventorySha256': base.ENGINE_SHA, 'seedArtifactSha256': 'a' * 64,
            'password': 'master_source_fixture_only_12345678901234567890', 'port': 7105, 'journalMode': 'initialize', 'requiredCheckpointSha256': None,
            'run': run, 'roster': [{'actorUuid': str(uuid.uuid4()), 'slotAlias': 'Yacht_One', 'team': 0, 'slot': 1}], 'browserBuildSha256': 'c' * 64}


def keyfile(config):
    return {'schema': 'amz.ap.public-beta.yacht-runtime-keys.v1', 'identity': copy.deepcopy(config['identity']),
            'runtimeArtifactSha256': config['runtimeArtifactSha256'], 'runSha256': base.sha(base.canonical(config['run'])),
            'observationKey': bytes(range(32)).hex(), 'effectsKey': bytes(range(32, 64)).hex()}


class YachtActionRuntimeSourceTests(unittest.TestCase):
    def test_all_four_wire_commands_have_exact_bounded_positive_shapes(self):
        packets = [connect(), {'cmd': 'ConnectUpdate', 'tags': ['AP'], 'items_handling': 7}, {'cmd': 'Sync'},
                   {'cmd': 'GetDataPackage', 'games': ['Archipelago', 'Yacht Dice']}]
        self.assertEqual(policy.validate_frame(json.dumps(packets)), packets)
        self.assertEqual(policy.COMMANDS, {'Connect', 'ConnectUpdate', 'Sync', 'GetDataPackage'})

    def test_any_forbidden_packet_rejects_whole_batch_before_any_dispatch(self):
        for command in ('LocationChecks', 'StatusUpdate', 'Say', 'Set', 'Bounce', 'LocationScouts', 'Get', 'SetNotify', 'UpdateHint', 'Unknown'):
            for batch in ([connect(), {'cmd': command}], [{'cmd': 'Sync'}, {'cmd': command}], [{'cmd': command}, {'cmd': 'GetDataPackage', 'games': ['Yacht Dice']}]):
                dispatched = []
                with self.assertRaises(policy.PacketRefused):
                    for value in policy.validate_frame(json.dumps(batch)): dispatched.append(value)
                self.assertEqual(dispatched, [])

    def test_native_version_conversion_is_preserved_without_coercion_or_unknown_classes(self):
        for change in ({'major': False}, {'minor': '6'}, {'class': 'NetworkItem'}, {'major': 1}, {'extra': 1}):
            value = connect(); value['version'].update(change)
            with self.assertRaises(policy.PacketRefused): policy.validate_frame(json.dumps([value]))
        self.assertEqual(policy.validate_frame(json.dumps([connect()]))[0]['version']['class'], 'Version')

    def test_whole_frame_preflight_precedes_decoder_and_only_exact_version_conversion_survives(self):
        # Deliberately synthetic parser, not an installed/native authority seam.
        Version = collections.namedtuple('Version', ('major', 'minor', 'build'))
        calls = []
        def decode(raw):
            calls.append(True); values = json.loads(raw)
            for value in values:
                if value['cmd'] == 'Connect': value['version'] = Version(0, 6, 8)
            return values
        raw = json.dumps([connect(), {'cmd': 'Sync'}])
        result = policy._decode_frame(raw, decode, Version)
        self.assertIs(type(result[0]['version']), Version); self.assertEqual(len(calls), 1)
        calls.clear()
        with self.assertRaises(policy.PacketRefused): policy._decode_frame(json.dumps([connect(), {'cmd': 'LocationChecks'}]), decode, Version)
        self.assertEqual(calls, [])
        for transform in (lambda v: [*v, {'cmd': 'Sync'}], lambda v: [dict(v[0], cmd='LocationChecks'), v[1]],
                          lambda v: [dict(v[0], version=(0, 6, 8)), v[1]], lambda v: [dict(v[0], game='Other'), v[1]]):
            with self.assertRaises(policy.PacketRefused): policy._decode_frame(raw, lambda text: transform(decode(text)), Version)

    def test_slot_switch_tracker_partial_item_stream_and_extra_fields_refuse(self):
        for change in ({'game': 'Archipelago'}, {'tags': ['Tracker']}, {'tags': ['AP', 'DeathLink']}, {'items_handling': 3},
                       {'items_handling': True}, {'slot_data': False}, {'name': '../other'}, {'score': 1000}):
            value = connect(); value.update(change)
            with self.assertRaises(policy.PacketRefused): policy.validate_frame(json.dumps([value]))
        for value in ({'cmd': 'ConnectUpdate'}, {'cmd': 'ConnectUpdate', 'tags': ['TextOnly']}, {'cmd': 'Sync', 'checks': []},
                      {'cmd': 'GetDataPackage', 'games': ['foreign']}, {'cmd': 'GetDataPackage', 'games': ['Yacht Dice', 'Yacht Dice']}):
            with self.assertRaises(policy.PacketRefused): policy.validate_frame(json.dumps([value]))

    def test_json_escaped_surrogates_refuse_whole_mixed_batch_before_native_decoder(self):
        for value in (chr(0xd800), chr(0xdfff), 'prefix' + chr(0xd800)):
            for field in ('uuid', 'password'):
                changed = connect(); changed[field] = value
                for frame in ([changed], [{'cmd': 'Sync'}, changed], [connect(), changed]):
                    raw = json.dumps(frame)
                    self.assertTrue(raw.isascii())
                    with self.assertRaises(policy.PacketRefused): policy.validate_frame(raw)
                    called = []
                    def native_decode(_):
                        called.append(True); self.fail('native decode ran before complete scalar validation')
                    with self.assertRaises(policy.PacketRefused): policy._decode_frame(raw, native_decode, tuple)
                    self.assertEqual(called, [])
        # Preserve scalar-string compatibility; valid escaped pairs decode to
        # one Unicode scalar, while this profile still requires ASCII aliases.
        valid = connect(); valid['uuid'] = 'scalar-' + chr(0x1f3b2)
        self.assertEqual(policy.validate_frame(json.dumps([valid]))[0]['uuid'], valid['uuid'])

    def test_frame_raw_types_duplicate_keys_utf8_bounds_and_count_refuse(self):
        for raw in (b'[]', '{}', '[]', '[{"cmd":"Sync","cmd":"Sync"}]', '[{"cmd":"Sync","n":NaN}]',
                    json.dumps([{'cmd': 'Sync'}] * 33), json.dumps([{'cmd': 'Say', 'text': '漢' * 90000}], ensure_ascii=False)):
            with self.assertRaises(policy.PacketRefused): policy.validate_frame(raw)
        with self.assertRaises(policy.PacketRefused): policy.install(object(), object(), b'unpinned', b'unpinned', lambda v: v)

    def test_new_boot_contract_is_distinct_and_restore_has_no_fallback(self):
        config = configuration(); self.assertEqual(loader.validate_configuration(base, config), config)
        for change in ({'schema': 'amz.ap.public-beta.native-configuration.v1'}, {'profileId': 'public-disposable-beta-v1'},
                       {'executionProfileSha256': base.PROFILE_SHA}, {'journalMode': 'migrate'}, {'requiredCheckpointSha256': 'd' * 64},
                       {'untrustedPath': '/tmp/selected.py'}):
            with self.assertRaises(Exception): loader.validate_configuration(base, dict(config, **change))

    def test_fixed_private_keys_bind_actual_run_launch_and_artifact_and_are_independent(self):
        config = configuration(); value = keyfile(config)
        self.assertEqual(loader.validate_keys(base, value, config), (bytes(range(32)), bytes(range(32, 64))))
        for change in ({'effectsKey': value['observationKey']}, {'observationKey': '00' * 32}, {'runSha256': 'd' * 64},
                       {'identity': {**config['identity'], 'runtimeLaunchId': str(uuid.uuid4())}}, {'runtimeArtifactSha256': 'e' * 64},
                       {'observationKey': hashlib.sha256(config['password'].encode()).hexdigest()}, {'extra': 'unknown'}):
            with self.assertRaises(Exception): loader.validate_keys(base, dict(value, **change), config)
        import hmac
        derived = hmac.digest(config['password'].encode(), b'amz.ap.public-beta.native-connect-key.v1\n' + base.canonical(config['identity']), 'sha256')
        with self.assertRaises(Exception): loader.validate_keys(base, dict(value, effectsKey=derived.hex()), config)
        for master in (bytes(range(32)).hex(), __import__('base64').urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')):
            with self.assertRaises(Exception): loader.validate_keys(base, value, dict(config, password=master))

    def test_captured_build_closure_enrols_real_modules_and_excludes_keys_and_cert_fixtures(self):
        source = builder.reviewed_source(); inputs = source[4]
        self.assertEqual(set(inputs), set(loader.FILES)); self.assertEqual(len(inputs), 19)
        self.assertEqual(builder.digest(inputs['fresh_loader.py']), loader.FRESH_LOADER_SHA)
        self.assertEqual(builder.digest(inputs['runtime-profile.json']), loader.PROFILE_SHA)
        self.assertEqual(builder.digest(inputs['native_yacht_effects.py']), 'a6630c05b97c4971251a66c8108da732dc301587101b44782b75566b2631cdf2')
        self.assertEqual(builder.digest(inputs['native_yacht_observations.py']), 'a6dbe041e2ac40fc78eeffc8f33ffff00366ff3a30e72a0b14a65a288f8a00d2')
        artifact = builder.artifact_document('1' * 40, source)
        self.assertEqual(artifact['schema'], 'amz.ap.public-beta.yacht-action-runtime.v1')
        self.assertEqual(artifact['executionProfileSha256'], loader.PROFILE_SHA)
        self.assertTrue(artifact['qualification']['sourceOnly'])
        self.assertFalse(any(v for k, v in artifact['qualification'].items() if k != 'sourceOnly'))
        self.assertNotIn('imageDigest', artifact); self.assertNotIn('runtimeArtifactSha256', artifact)
        self.assertTrue(all('keys' not in r['path'] and 'server-key' not in r['path'] for r in artifact['ownedFiles']))

    def test_normal_lifecycle_enrols_frame_policy_controls_and_serialized_shutdown(self):
        text = (ROOT / 'runtime/loader.py').read_text()
        for required in ('policy.install(', 'effects.initialize_effects(', 'effects.YachtEffectsControl(', 'observations.YachtObservationControl(',
                         'await pump.poll_once()', 'effects_control.poll_once()', 'observation_control.poll_once()', 'state[\'snapshots\'].periodic()',
                         'await base.drain_native(', 'observation_control.close()', 'effects_control.close()'):
            self.assertIn(required, text)
        self.assertNotIn('checkpoint.RuntimeControl(', text)
        self.assertIn('budget.bind_save(snapshots.files)', text); self.assertNotIn('base.FixedStatus()', text)
        self.assertIn('budget.publish_status(', text); self.assertIn('budget.reserve_lock()', text)
        self.assertIn("files._entry('public-runtime-control.json') is None", text)
        self.assertIn("== {'public-runtime.json', 'public-seed.archipelago', 'public-yacht-keys.json'}", text)

    def test_real_node_launcher_accepts_exact_python_artifact_and_rejects_cross_profile_inventory(self):
        raw = (json.dumps(builder.artifact_document('1' * 40, builder.reviewed_source()), indent=2) + '\n').encode()
        node = 'C:/Program Files/nodejs/node.exe' if os.name == 'nt' else 'node'
        script = 'import {validateArtifact} from ' + json.dumps((ROOT / 'runtime/launcher.mjs').as_uri()) + ';' + r'''
import {createHash} from 'node:crypto';
let chunks=[];for await(const part of process.stdin)chunks.push(part);const raw=Buffer.concat(chunks),sha=b=>createHash('sha256').update(b).digest('hex');
const artifact=validateArtifact(raw,sha(raw));if(artifact.ownedFiles.length!==19)throw Error('closure');
for(const change of [v=>v.profileId='public-disposable-beta-v1',v=>v.ownedFiles.pop(),v=>v.executionProfileSha256='0'.repeat(64)]){
 const v=JSON.parse(raw);change(v);const b=Buffer.from(JSON.stringify(v));let refused=false;try{validateArtifact(b,sha(b));}catch{refused=true;}if(!refused)throw Error('cross-profile');
}
process.stdout.write(JSON.stringify({artifactSchema:artifact.schema,ownedFiles:19,engineImported:false}));
'''
        result = subprocess.run([node, '--input-type=module', '-e', script], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, 'fixed Node artifact fixture refused')
        self.assertEqual(json.loads(result.stdout), {'artifactSchema': 'amz.ap.public-beta.yacht-action-runtime.v1', 'ownedFiles': 19, 'engineImported': False})
        self.assertEqual(result.stderr, b'')

    def test_recipes_never_download_prepare_or_import_engine_by_default_and_old_sources_stay_pinned(self):
        source = builder.reviewed_source(); provenance = source[7]
        self.assertEqual(len(provenance['files']), 26)
        self.assertEqual(provenance['freshSourceCommit'], '79e2b0d293d9d6f1f12ee05d6bfe8cb13fd6392e')
        self.assertNotIn('MultiServer', sys.modules)
        self.assertNotIn('NetUtils', sys.modules)
        text = (ROOT / 'build.py').read_text(); self.assertNotIn('base.fetch(', text)
        docker = (ROOT / 'Dockerfile').read_text()
        self.assertIn('RUN --network=none', docker); self.assertIn('--no-index', docker); self.assertIn('--require-hashes --no-deps', docker)
        launcher = (ROOT / 'runtime/launcher.mjs').read_text(); self.assertIn("spawn('/usr/local/bin/python'", launcher)
        self.assertNotIn('pipe(process.stdout)', launcher); self.assertNotIn('pipe(process.stderr)', launcher)


class NativeBudgetTests(unittest.TestCase):
    def test_combined_budget_counts_all_files_and_entire_replacement_before_releasing_old_target(self):
        sizes = {'public-seed.archipelago': 524288, 'public-seed.apsave': 524288,
                 'public-gateway-journal.json': 524288, 'public-yacht-effects-journal.json': 524288}
        # Current files fit, but current+new replacement does not; subtracting
        # the old target before pending publication would incorrectly pass.
        self.assertLess(sum(sizes.values()) + budget_module.METADATA + budget_module.EXTERNAL_RESERVE, budget_module.AGGREGATE)
        with self.assertRaises(budget_module.BudgetRefused): budget_module.plan(sizes, budget_module.SAVE, 524288)
        self.assertLess(sum(sizes.values()) + budget_module.METADATA + budget_module.EXTERNAL_RESERVE, budget_module.AGGREGATE)

    def test_ack_growth_reserves_final_save_headroom_and_external_current_plus_pending_maxima(self):
        sizes = {'public-seed.archipelago': 524288, 'public-seed.apsave': 524288,
                 'public-gateway-journal.json': 524288, 'public-yacht-effects-journal.json': 100000}
        with self.assertRaises(budget_module.BudgetRefused): budget_module.plan(sizes, 'public-yacht-observation-ack.json', 400000)
        reserved = budget_module.plan({'public-seed.archipelago': 524288}, 'public-gateway-ack.json', 1000)
        self.assertGreaterEqual(reserved, 524288 + budget_module.CAPS[budget_module.SAVE] + budget_module.METADATA + 3 * 2 * 65536)
        for name, count in (('public-seed.apsave', 524289), ('public-runtime-status.json', 16385), ('foreign', 1)):
            with self.assertRaises(budget_module.BudgetRefused): budget_module.plan({}, name, count)

    def test_actual_owned_files_audit_rejects_oversized_foreign_pending_and_linked_inputs(self):
        with tempfile.TemporaryDirectory(prefix='amz-yacht-budget-') as folder:
            root = Path(folder); root.chmod(0o700)
            seed = root / 'public-seed.archipelago'; seed.write_bytes(b'x' * 100); seed.chmod(0o600)
            b = budget_module.NativeBudget(root)
            try:
                self.assertEqual(b.audit(), {'public-seed.archipelago': 100})
                seed.write_bytes(b'x' * 524289)
                with self.assertRaises(budget_module.BudgetRefused): b.audit()
                seed.write_bytes(b'original')
                foreign = root / '.public-gateway-journal.json.pending-unowned'; foreign.write_bytes(b'preserved'); foreign.chmod(0o600)
                with self.assertRaises(budget_module.BudgetRefused): b.audit()
                self.assertEqual(foreign.read_bytes(), b'preserved'); foreign.unlink()  # Exact test-owned fixture only.
                alias = root / 'public-runtime.json'; os.link(seed, alias)
                with self.assertRaises(budget_module.BudgetRefused): b.audit()
            finally: b.close()

    @unittest.skipUnless(sys.platform == 'linux', 'actual NativeFiles writer/FD owner requires Linux')
    def test_actual_json_publication_refuses_combined_overflow_before_temp_open_and_holds_owner(self):
        self.native_case('aggregate')

    @unittest.skipUnless(sys.platform == 'linux', 'actual NativeFiles writer/FD owner requires Linux')
    def test_actual_binary_save_publication_refuses_oversize_before_temp_open_and_holds_owner(self):
        self.native_case('save')

    @unittest.skipUnless(sys.platform == 'linux', 'actual NativeFiles writer/FD owner requires Linux')
    def test_actual_status_publication_uses_budgeted_owner_and_refuses_before_temp_open(self):
        self.native_case('status')

    @unittest.skipUnless(sys.platform == 'linux', 'actual NativeFiles writer/FD owner requires Linux')
    def test_actual_foreign_pending_state_holds_owner_and_preserves_evidence(self):
        self.native_case('pending')

    @unittest.skipUnless(sys.platform == 'linux', 'actual NativeFiles writer/FD owner requires Linux')
    def test_actual_positive_json_binary_status_publish_and_reserved_lock_share_one_fd_root(self):
        self.native_case('positive')
        with tempfile.TemporaryDirectory(prefix='amz-yacht-budget-identity-') as folder:
            root = Path(folder); root.chmod(0o700)
            opened, real_open, real_stat = [], os.open, os.fstat
            def open_owned(*args, **kwargs):
                fd = real_open(*args, **kwargs); opened.append(fd); return fd
            def changed_identity(fd):
                result = real_stat(fd)
                values = list(result); values[1] += 1
                return os.stat_result(values)
            with patch.object(budget_module.os, 'open', side_effect=open_owned), patch.object(budget_module.os, 'fstat', side_effect=changed_identity):
                with self.assertRaises(budget_module.BudgetRefused): budget_module.NativeBudget(root)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError): real_stat(opened[0])

    def native_case(self, kind):
        with tempfile.TemporaryDirectory(prefix='amz-yacht-budget-native-') as folder:
            root = Path(folder); root.chmod(0o700)
            modules = {}
            for name in ('native_files', 'gateway_barrier', 'checkpoint_custody', 'native_checkpoint'):
                with patch.dict(sys.modules, modules): modules[name] = load(name, ROOT.parent / ('public-beta/runtime/' + name + '.py'))
            modules['native_files'].ROOT = root
            with patch.dict(sys.modules, modules):
                budget = budget_module.NativeBudget(root); budget.reserve_lock(); owner = modules['native_files'].NativeFiles(); budget.install(owner)
                try:
                    if kind == 'positive':
                        owner.initialize({'sourceOnly': True})
                        save = modules['native_checkpoint'].NativeSaveFiles(owner); budget.bind_save(save); save.write(b'synthetic bounded native payload')
                        budget.publish_status({'sourceOnly': True}, base.canonical)
                        self.assertTrue((root / budget_module.SAVE).exists()); self.assertTrue((root / budget_module.STATUS).exists())
                        self.assertLess(sum(budget.audit().values()), budget_module.AGGREGATE)
                        self.assertLessEqual((root / budget_module.LOCK).stat().st_size, budget_module.CAPS[budget_module.LOCK])
                        self.assertFalse(owner._uncertain); return
                    if kind == 'aggregate':
                        for name in ('public-seed.archipelago', 'public-seed.apsave', 'public-gateway-journal.json', 'public-yacht-effects-journal.json'):
                            file = root / name; file.write_bytes(b'x' * 524288); file.chmod(0o600)
                        run = lambda: owner._replace('public-yacht-observation-ack.json', b'{}', 1048576, None)
                    elif kind == 'save':
                        save = modules['native_checkpoint'].NativeSaveFiles(owner); budget.bind_save(save)
                        run = lambda: save.write(b'x' * 524289)
                    elif kind == 'status': run = lambda: budget.publish_status({'text': 'x' * 16384}, base.canonical)
                    else:
                        pending = root / '.public-runtime-status.json.pending-unowned'; pending.write_bytes(b'preserve'); pending.chmod(0o600)
                        run = lambda: budget.publish_status({'sourceOnly': True}, base.canonical)
                    before = {p.name: p.read_bytes() for p in root.iterdir()}
                    with self.assertRaises(budget_module.BudgetRefused): run()
                    self.assertTrue(owner._uncertain); self.assertIsNone(owner._durable)
                    self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                finally:
                    try: owner.close()
                    except modules['native_files'].NativeFilesError: pass
                    budget.close()


if __name__ == '__main__': unittest.main()

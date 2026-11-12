"""Source contract checks only; these cannot qualify a native Context."""
import copy
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('native_observation_acceptance_source', HERE / 'qualify_native_context.py')
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def manifest():
    return {'schema': acceptance.SCHEMA, 'candidateSourceCommit': acceptance.CANDIDATE_COMMIT,
            'foundationImageId': acceptance.IMAGE_ID, 'browserBuildSha256': 'b' * 64,
            'run': {'seedArtifactSha256': 'a' * 64}, 'roster': [{}, {}], 'identity': {}}


class SourceContracts(unittest.TestCase):
    def setUp(self):
        saved = dict(acceptance.DIAGNOSTIC_SOURCES)
        self.addCleanup(lambda: (acceptance.DIAGNOSTIC_SOURCES.clear(), acceptance.DIAGNOSTIC_SOURCES.update(saved)))

    def test_import_is_inert_and_exact_manifest_has_no_path_code_credential_or_fallback_selector(self):
        value = manifest(); captured = acceptance.validate_manifest(value)
        value['run']['seedArtifactSha256'] = 'c' * 64
        self.assertEqual(captured['run']['seedArtifactSha256'], 'a' * 64)
        for change in ({'module': '/tmp/arbitrary.py'}, {'password': 'fixture'}, {'fallback': True},
                       {'foundationImageId': 'sha256:' + 'd' * 64}, {'candidateSourceCommit': 'e' * 40},
                       {'imageQualified': True}, {'cpRosterAuthority': True}):
            with self.assertRaises(acceptance.Refused): acceptance.validate_manifest({**manifest(), **change})
        self.assertEqual(acceptance.PRODUCT_QUALIFICATION, {'cpRosterAuthority': False, 'currentWebsiteAuthorization': False,
            'browserGameplay': False, 'imageQualified': False, 'productionAdmitted': False})
        self.assertNotIn('MultiServer', sys.modules)

    def test_pins_match_the_exact_source_candidate_and_foundation_entrypoint(self):
        base = HERE.parents[1]
        runtime = HERE.parent / 'runtime'
        for name, expected in acceptance.CANDIDATE_PINS.items():
            file = runtime / name if name != 'native_yacht_effects.py' else base / 'public-beta-effects/runtime/native_yacht_effects.py'
            self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(), expected)
        self.assertEqual(hashlib.sha256((base / 'public-beta/runtime/loader.py').read_bytes()).hexdigest(), acceptance.LOADER_SHA)

    def test_duplicate_and_nonfinite_input_fail_without_engine_import(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"number":NaN}', b'{"number":Infinity}'):
            with self.assertRaises(acceptance.Refused): acceptance.strict_json(raw)
        self.assertEqual(acceptance.strict_json(b'{"number":1}'), {'number': 1})

    def test_description_mode_has_only_a_strict_fixed_four_field_metadata_input(self):
        value = {'schema': 'amz.ap.public-beta.yacht-observation-seed-description-input.v1',
                 'candidateSourceCommit': acceptance.CANDIDATE_COMMIT, 'foundationImageId': acceptance.IMAGE_ID,
                 'seedSha256': 'a' * 64}
        self.assertEqual(acceptance.validate_description_manifest(value), value)
        for change in ({'seedPath': '/tmp/other'}, {'password': 'fixture'}, {'seedSha256': 'not-a-hash'}, {'foundationImageId': 'sha256:' + 'd' * 64}):
            with self.assertRaises(acceptance.Refused): acceptance.validate_description_manifest({**value, **change})

    def test_negative_case_requires_the_expected_exception_and_code(self):
        class NativeRefusal(RuntimeError): pass
        def refused(): raise NativeRefusal('expected-native-refusal')
        self.assertTrue(acceptance.expect_refused(refused, NativeRefusal, 'expected-native-refusal'))
        with self.assertRaises(acceptance.Refused): acceptance.expect_refused(lambda: None, NativeRefusal, 'expected')
        with self.assertRaises(acceptance.Refused): acceptance.expect_refused(refused, NativeRefusal, 'wrong-code')
        with self.assertRaises(NativeRefusal): acceptance.expect_refused(refused, ValueError, 'expected-native-refusal')

    def test_missing_exact_environment_is_a_refusal_not_a_fixture_success(self):
        # This source lane's uid1001/Windows host is deliberately not the
        # admitted image's uid65532 private actual-context operation.
        if sys.platform == 'linux' and hasattr(acceptance.os, 'getuid') and acceptance.os.getuid() == 65532:
            self.skipTest('reserved for protected actual-image execution')
        with self.assertRaisesRegex(acceptance.Refused, 'isolated_exact_native_image_required'):
            acceptance.capture_inputs()

    def test_failure_diagnostic_contains_only_captured_code_metadata_not_exception_text(self):
        filename = '/private-synthetic/source.py'
        source = b'def observed():\n    raise ValueError("DO-NOT-EXPORT-private-message")\n'
        acceptance.register_diagnostic_source(filename, source, 'candidate/fixture.py')
        namespace = {}
        exec(compile(source, filename, 'exec'), namespace)
        try: namespace['observed']()
        except ValueError as error: diagnostic = acceptance.safe_exception_diagnostic(error)
        self.assertEqual(diagnostic, {'exceptionType': 'ValueError', 'frames': [
            {'file': 'candidate/fixture.py', 'function': 'observed', 'line': 2}]})
        self.assertNotIn('DO-NOT-EXPORT', json.dumps(diagnostic))
        self.assertNotIn('/private-synthetic', json.dumps(diagnostic))

    def test_diagnostic_never_formats_or_reads_exception_args_and_omits_unregistered_frames(self):
        class PrivateException(Exception):
            def __str__(self): raise AssertionError('exception text accessed')
            def __repr__(self): raise AssertionError('exception representation accessed')
            def __getattribute__(self, name):
                if name == 'args': raise AssertionError('exception args accessed')
                return super().__getattribute__(name)
        source = b'def private():\n    raise PrivateException("secret")\n'
        namespace = {'PrivateException': PrivateException}
        exec(compile(source, '/unregistered/private.py', 'exec'), namespace)
        try: namespace['private']()
        except PrivateException as error: diagnostic = acceptance.safe_exception_diagnostic(error)
        self.assertEqual(diagnostic, {'exceptionType': 'UnclassifiedException', 'frames': []})

    def test_diagnostic_frames_are_bounded_and_functions_require_captured_source(self):
        filename = '/private-synthetic/recursive.py'
        source = b'def descend(n):\n    if n: return descend(n-1)\n    raise TypeError("secret")\n'
        acceptance.register_diagnostic_source(filename, source, 'foundation/fixture.py')
        namespace = {}
        exec(compile(source, filename, 'exec'), namespace)
        try: namespace['descend'](40)
        except TypeError as error: diagnostic = acceptance.safe_exception_diagnostic(error)
        self.assertEqual(len(diagnostic['frames']), 16)
        self.assertTrue(all(row == {'file': 'foundation/fixture.py', 'function': 'descend', 'line': 2}
                            for row in diagnostic['frames'][:-1]))
        self.assertEqual(diagnostic['frames'][-1]['line'], 3)
        # A filename match cannot admit a function absent from captured code.
        exec(compile(b'def unrelated():\n    raise TypeError("secret")\n', filename, 'exec'), namespace)
        try: namespace['unrelated']()
        except TypeError as error: self.assertEqual(acceptance.safe_exception_diagnostic(error)['frames'], [])

    def test_diagnostic_source_is_closed_bounded_and_cannot_be_replaced(self):
        source = b'def observed():\n    return None\n'
        for label in ('/absolute.py', 'engine/../private.py', 'engine//private.py', 'engine/./private.py', 'other/private.py'):
            with self.assertRaises(acceptance.Refused): acceptance.register_diagnostic_source('/fixture', source, label)
        for raw in (b'', b'x' * 1048577, 'not-bytes'):
            with self.assertRaises(acceptance.Refused): acceptance.register_diagnostic_source('/fixture', raw, 'engine/fixture.py')
        acceptance.register_diagnostic_source('/fixture', source, 'engine/fixture.py')
        acceptance.register_diagnostic_source('/fixture', source, 'engine/fixture.py')
        with self.assertRaises(acceptance.Refused):
            acceptance.register_diagnostic_source('/fixture', source + b'\n', 'engine/fixture.py')

    def test_actual_context_substages_remain_separate_and_browser_json_stays_strict(self):
        tree = ast.parse(Path(SPEC.origin).read_bytes())
        exercise, = (node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'exercise')
        stages = [node.value.value for node in ast.walk(exercise) if isinstance(node, ast.Assign) and
                  any(isinstance(target, ast.Name) and target.id == 'STAGE' for target in node.targets) and
                  isinstance(node.value, ast.Constant)]
        ordered = ['native_context_construct', 'native_context_load', 'native_context_init_save',
                   'native_context_empty_checks', 'native_barrier_initial_ready', 'native_observation_abi',
                   'native_observation_construct', 'native_observation_initial_snapshots']
        self.assertEqual([stage for stage in stages if stage in ordered], ordered)
        self.assertNotIn('genuine_native_seed_load', stages)
        self.assertEqual(acceptance.strict_json(b'{"allowed_categories":["Category Ones"]}'),
                         {'allowed_categories': ['Category Ones']})


if __name__ == '__main__': unittest.main()

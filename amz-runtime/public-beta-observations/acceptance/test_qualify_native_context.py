"""Source contract checks only; these cannot qualify a native Context."""
import copy
import hashlib
import importlib.util
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


if __name__ == '__main__': unittest.main()

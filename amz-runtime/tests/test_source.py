"""Source-only boundary tests. Never import an engine or invoke Docker."""
import hashlib
import ast
import importlib.util
import io
import json
from pathlib import Path
import stat
from collections import defaultdict
from types import SimpleNamespace
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("headless_build", ROOT / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class SourceTests(unittest.TestCase):
    def test_reviewed_source_bindings(self):
        manifest, provenance, overlay, dependencies = build.reviewed_source()
        self.assertEqual(len(manifest["files"]), 3539)
        self.assertEqual(len(provenance["excludedForkChanges"]), 6)
        self.assertEqual(provenance["serverBaselineCommit"], "0a601afbf575a4660077304a18ecb521ff1886c4")
        self.assertEqual([row["path"] for row in overlay], ["ap_runtime.py", "launcher.mjs"])
        self.assertEqual(len(dependencies["dependencies"]), 8)
        self.assertFalse(dependencies["redistributionApproved"])
        self.assertNotIn("WebHost.py", [row["path"] for row in overlay])

    def test_pinned_hint_declarations_and_equivalent_projection(self):
        metadata = build.verify_hints(ROOT.parent)
        self.assertEqual(len(metadata["allowedGames"]), 82)
        source = ast.parse((ROOT / "runtime/ap_runtime.py").read_text())
        function = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == "apply_world_hints")
        namespace = {"EXPECTED_ENGINE": build.ENGINE_COMMIT, "EXPECTED_PACK": build.WORLD_PACK_SHA256}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "trusted-metadata-adapter", "exec"), namespace)
        context = SimpleNamespace(played_games=set(metadata["allowedGames"]), non_hintable_names=defaultdict(frozenset))
        namespace["apply_world_hints"](context, metadata)
        self.assertEqual(context.non_hintable_names["A Link to the Past"], frozenset({"Triforce"}))
        self.assertEqual(context.non_hintable_names["Castlevania - Circle of the Moon"], frozenset({"Battle Arena: End reward"}))
        self.assertTrue(all(context.non_hintable_names[game] == frozenset() for game in metadata["allowedGames"] if game not in metadata["overrides"]))
        for game in ("Game Dev Tycoon", "Surviving Mars: Relaunched", "The Farmer Was Replaced", "Unreviewed custom world"):
            with self.subTest(game=game), self.assertRaisesRegex(ValueError, "unsupported"):
                namespace["apply_world_hints"](SimpleNamespace(played_games={game}, non_hintable_names={}), metadata)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            namespace["apply_world_hints"](context, {**metadata, "worldPackSha256": "f" * 64})

    def test_dynamic_and_inherited_hint_overrides_are_rejected(self):
        for source in ("class CustomWorld:\n    def change(self): self.hint_blacklist = {'hidden'}\n", "setattr(World, 'hint_blacklist', {'hidden'})\n", "class CustomWorld(ALTTPWorld): pass\n"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                engine = Path(directory)
                (engine / "worlds").mkdir()
                # First test the explicit dynamic boundary before source pin validation.
                for row in json.loads((ROOT / "world-hints.v1.json").read_text())["sourceFiles"]:
                    target = engine / row["path"]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(build.source_bytes(ROOT.parent / row["path"]))
                (engine / "worlds/custom.py").write_text(source)
                with self.assertRaisesRegex(ValueError, "override"):
                    build.verify_hints(engine)

    def test_only_normalized_relative_paths(self):
        for name in ("", ".", "../x", "/x", "a/../x", "a//x", "./x", "C:/x", "a\\b", "NUL", "x/COM1.txt", "a\x00b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build.safe_path(name)
        self.assertEqual(str(build.safe_path("worlds/paint/__init__.py")), "worlds/paint/__init__.py")

    def archive(self, name="source.py", value=b"hello\r\n", mode=stat.S_IFREG):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            entry = zipfile.ZipInfo("Archipelago-" + build.ENGINE_COMMIT + "/" + name)
            entry.external_attr = (mode | 0o644) << 16
            archive.writestr(entry, value)
        return output.getvalue()

    def test_inventory_extracts_only_pinned_regular_hashes(self):
        row = {"path": "source.py", "algorithm": "sha256-lf", "sha256": hashlib.sha256(b"hello\n").hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            build.extract_inventory(self.archive(), {"files": [row]}, destination)
            self.assertEqual((destination / "source.py").read_bytes(), b"hello\n")
            with self.assertRaises(ValueError):
                build.extract_inventory(self.archive(), {"files": [row]}, destination)

    def test_inventory_rejects_links_traversal_missing_and_changed_inputs(self):
        for name, value, mode, algorithm in (("source.py", b"changed", stat.S_IFREG, "sha256"), ("source.py", b"hello", stat.S_IFLNK, "sha256"), ("../escape", b"hello", stat.S_IFREG, "sha256"), ("source.py", b"hello", stat.S_IFREG, "md5")):
            with self.subTest(name=name, mode=mode, algorithm=algorithm), tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                build.extract_inventory(self.archive(name, value, mode), {"files": [{"path": name, "algorithm": algorithm, "sha256": hashlib.sha256(b"hello").hexdigest()}]}, Path(directory))
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            build.extract_inventory(self.archive(), {"files": [{"path": "missing", "algorithm": "sha256", "sha256": "0" * 64}]}, Path(directory))

    def test_no_mutable_runtime_dependencies_or_shell(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn(build.PYTHON_IMAGE, dockerfile)
        self.assertIn(build.NODE_IMAGE, dockerfile)
        self.assertNotIn("libatomic.so", dockerfile)
        self.assertIn("process.version !== 'v24.20.0'", dockerfile)
        self.assertIn("RUN --network=none", dockerfile)
        self.assertIn("--no-index", dockerfile)
        self.assertIn("--require-hashes --no-deps", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        launcher = (ROOT / "runtime/launcher.mjs").read_text()
        self.assertIn("shell:false", launcher)
        self.assertIn("stdio:['ignore','pipe','pipe']", launcher)
        self.assertNotIn("fetch(", launcher)


if __name__ == "__main__":
    unittest.main()

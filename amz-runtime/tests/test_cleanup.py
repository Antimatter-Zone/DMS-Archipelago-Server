"""No Docker execution: exercise unknown/foreign/removal/publication boundaries."""
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

SOURCE = Path(__file__).resolve().parent / "native-acceptance.py"


class CleanupTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("native_cleanup_fixture", SOURCE)
        self.harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.harness)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.harness.ROOT = self.root
        (self.root / ".build").mkdir()
        self.run = str(uuid.uuid4())
        self.private = self.root / ".private" / ("native-" + self.run)
        self.private.mkdir(parents=True)
        self.intent = self.private / "intent.json"
        self.identifier = "1" * 64
        self.record = {"owner": self.harness.OWNER, "runId": self.run, "name": "amz-ap-native-" + self.run,
            "image": "sha256:" + "a" * 64, "attempts": [{"containerId": self.identifier, "state": "removed"}],
            "removals": [{"containerId": self.identifier, "ack": "docker-rm-exit-0"}]}
        self.intent.write_text(json.dumps(self.record))

    def tearDown(self):
        self.temporary.cleanup()

    def result(self, stdout=b"", returncode=0):
        return subprocess.CompletedProcess([], returncode, stdout, b"")

    def test_terminal_removal_and_healthy_exact_inventory_prove_absence_without_error_text(self):
        calls = []
        def command(args, **_):
            calls.append(args)
            self.assertEqual(args[0], "ps")
            return self.result()
        self.harness.command = command
        result = self.harness.cleanup(self.intent)
        self.assertTrue(result["ownedContainerAbsent"] and result["privateFixtureRemoved"])
        self.assertFalse(self.private.exists())
        self.assertTrue(any("id=" + self.identifier in args for args in calls))
        self.assertTrue(any("name=^/" + re.escape(self.record["name"]) + "$" in args for args in calls))

    def test_existing_owned_container_requires_exact_id_removal_ack_before_private_deletion(self):
        self.record["attempts"][0]["state"] = "created"
        self.record["removals"] = []
        self.intent.write_text(json.dumps(self.record))
        calls = []
        removed = False
        def command(args, **_):
            nonlocal removed
            calls.append(args)
            if args[0] == "ps": return self.result(b"" if removed else (self.record["name"] + "\n").encode())
            if args[0] == "inspect": return self.result(json.dumps([{"Id": self.identifier, "Image": self.record["image"], "Config": {"Labels": {"amz.owner": self.harness.OWNER, "amz.run": self.run}}}]).encode())
            self.assertEqual(args, ["rm", "-f", self.identifier])
            removed = True
            return self.result((self.identifier + "\n").encode())
        self.harness.command = command
        result = self.harness.cleanup(self.intent)
        self.assertEqual(result["terminalRemovalAcknowledgments"], 1)
        self.assertFalse(self.private.exists())
        self.assertTrue(removed)

    def test_daemon_failure_or_unacknowledged_create_keeps_private_intent(self):
        def unavailable(*_, **__): raise RuntimeError("fixture daemon unavailable")
        self.harness.command = unavailable
        with self.assertRaises(RuntimeError): self.harness.cleanup(self.intent)
        self.assertTrue(self.intent.exists())
        self.harness.command = lambda *_args, **_kwargs: self.result()
        self.record["attempts"][0] = {"containerId": None, "state": "creating"}
        self.record["removals"] = []
        self.intent.write_text(json.dumps(self.record))
        with self.assertRaisesRegex(ValueError, "dispatch_unresolved"): self.harness.cleanup(self.intent)
        self.assertTrue(self.intent.exists())

    def test_foreign_matching_name_and_inspection_permission_error_are_preserved(self):
        calls = []
        def command(args, **_):
            calls.append(args)
            if args[0] == "ps": return self.result((self.record["name"] + "\n").encode())
            return self.result(json.dumps([{"Id": self.identifier, "Image": self.record["image"], "Config": {"Labels": {"amz.owner": "foreign", "amz.run": self.run}}}]).encode())
        self.harness.command = command
        with self.assertRaisesRegex(ValueError, "foreign"): self.harness.cleanup(self.intent)
        self.assertTrue(self.intent.exists())
        self.assertFalse(any(args[0] == "rm" for args in calls))
        def denied(args, **_):
            if args[0] == "ps": return self.result((self.record["name"] + "\n").encode())
            raise RuntimeError("fixture permission denied")
        self.harness.command = denied
        with self.assertRaises(RuntimeError): self.harness.cleanup(self.intent)
        self.assertTrue(self.intent.exists())

    def test_pass_receipt_cannot_precede_cleanup_or_omit_terminal_acknowledgements(self):
        commit = "b" * 40
        receipt = {"sourceCommit": commit, "passed": True}
        proof = {"ownedContainerAbsent": True, "privateFixtureRemoved": True, "createdContainerIds": ["1" * 64, "2" * 64, "3" * 64], "terminalRemovalAcknowledgments": 3}
        with self.assertRaisesRegex(ValueError, "cleanup_incomplete"):
            self.harness.publish_passed_receipt(commit, receipt, proof, self.private)
        self.assertEqual(list((self.root / ".build").iterdir()), [])
        self.intent.unlink(); self.private.rmdir()
        with self.assertRaisesRegex(ValueError, "cleanup_incomplete"):
            self.harness.publish_passed_receipt(commit, receipt, {**proof, "terminalRemovalAcknowledgments": 2}, self.private)
        output = self.harness.publish_passed_receipt(commit, receipt, proof, self.private)
        self.assertEqual(json.loads(output.read_text())["cleanup"], proof)


if __name__ == "__main__":
    unittest.main()

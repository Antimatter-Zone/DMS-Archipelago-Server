"""Explicit local Docker acceptance; isolated synthetic protocol fixture, no game qualification."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
OWNER = "amz.ap.server-native-source.v1"
spec = importlib.util.spec_from_file_location("headless_build", ROOT / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def command(arguments, timeout=30, required=True):
    result = subprocess.run(["docker", *arguments], capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError("bounded_docker_command_failed")
    return result


def bounded_diagnostics(value):
    raw = value[-262144:]
    diagnostics = []
    stopped = None
    stages = {"configuration", "engine_verification", "native_import", "checkpoint_load", "native_runtime"}
    types = {"ValueError", "ModuleNotFoundError", "ImportError", "OSError", "PermissionError", "RuntimeError", "TypeError", "KeyError", "AssertionError", "AttributeError"}
    codes = types | {"private_file_invalid", "private_root_invalid", "runtime_configuration_invalid", "runtime_overlay_changed", "seed_integrity", "manifest_pin_mismatch", "engine_pin_mismatch", "source_path_invalid", "engine_source_changed", "checkpoint_integrity", "explicit_checkpoint_required", "initial_checkpoint_failed", "nonroot_container_required", "headless_world_pack_unsupported", "headless_hint_integrity"}
    for line in raw.decode(errors="replace").splitlines():
        match = re.fullmatch(r"AP runtime stopped: ([a-z_]{1,64}):([A-Za-z_][A-Za-z0-9_]{0,63})", line)
        if match and match[1] in stages and match[2] in codes:
            stopped = {"stage": match[1], "code": match[2]}
        try:
            row = json.loads(line)
            if row.get("schema") == "amz.ap.runtime-diagnostic.v1" and len(diagnostics) < 16 and row.get("stage") in stages and row.get("exceptionType") in types and isinstance(row.get("module"), str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", row["module"]) and isinstance(row.get("function"), str) and re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]{0,127}|<module>)", row["function"]) and type(row.get("line")) is int and 0 < row["line"] < 1000000:
                diagnostics.append({key: row[key] for key in ("stage", "exceptionType", "module", "function", "line")})
        except (ValueError, AttributeError, TypeError):
            pass
    return stopped, diagnostics, hashlib.sha256(raw).hexdigest()


def cleanup(intent):
    if intent.is_symlink() or not intent.is_file() or intent.stat().st_size > 8192:
        raise ValueError("native_cleanup_intent_invalid")
    record = json.loads(intent.read_text())
    if record.get("owner") != OWNER or not re.fullmatch(r"[a-f0-9-]{36}", record.get("runId", "")) or record.get("name") != "amz-ap-native-" + record["runId"]:
        raise ValueError("native_cleanup_identity_invalid")
    directory = intent.parent.resolve()
    if directory.parent != (ROOT / ".private").resolve() or directory.name != "native-" + record["runId"] or intent.parent.is_symlink():
        raise ValueError("native_cleanup_directory_invalid")
    if not isinstance(record.get("attempts"), list) or not isinstance(record.get("removals"), list):
        raise ValueError("native_cleanup_dispatch_unresolved")
    # A successful exact-name inventory is the absence proof. Never infer it
    # from Docker's localized/case-sensitive error text or an API failure.
    listed = command(["ps", "--all", "--no-trunc", "--filter", "name=^/" + re.escape(record["name"]) + "$", "--format", "{{.Names}}"])
    if listed.stdout.strip():
        container = json.loads(command(["inspect", record["name"]]).stdout)[0]
        if container["Config"]["Labels"].get("amz.owner") != OWNER or container["Config"]["Labels"].get("amz.run") != record["runId"] or container["Image"] != record["image"]:
            raise ValueError("foreign_native_container_protected")
        identifier = container["Id"]
        if not record["attempts"]:
            raise ValueError("native_cleanup_dispatch_unresolved")
        current = record["attempts"][-1]
        if current.get("containerId") not in (None, identifier):
            raise ValueError("native_cleanup_identity_changed")
        current["containerId"] = identifier
        removal_ack(record, identifier, command(["rm", "-f", identifier]))
        intent.write_text(json.dumps(record))
    names = command(["ps", "--all", "--no-trunc", "--filter", "name=^/" + re.escape(record["name"]) + "$", "--format", "{{.Names}}"])
    if names.stdout.strip():
        raise ValueError("native_cleanup_reconciliation_unavailable")
    for attempt in record["attempts"]:
        identifier = attempt.get("containerId")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier) or attempt.get("state") != "removed" or not any(row.get("containerId") == identifier and row.get("ack") == "docker-rm-exit-0" for row in record["removals"]):
            raise ValueError("native_cleanup_dispatch_unresolved")
        if command(["ps", "--all", "--no-trunc", "--filter", "id=" + identifier, "--format", "{{.ID}}"]).stdout.strip():
            raise ValueError("native_cleanup_reconciliation_unavailable")
    shutil.rmtree(directory)
    return {"ownedContainerAbsent": True, "createdContainerIds": [attempt["containerId"] for attempt in record["attempts"]], "terminalRemovalAcknowledgments": len(record["removals"]), "privateFixtureRemoved": not directory.exists()}


def removal_ack(record, identifier, result):
    if result.returncode != 0 or result.stdout.decode().strip() != identifier:
        raise ValueError("native_removal_acknowledgement_invalid")
    for attempt in record["attempts"]:
        if attempt.get("containerId") == identifier:
            attempt["state"] = "removed"
    record["removals"].append({"containerId": identifier, "ack": "docker-rm-exit-0"})


def publish_passed_receipt(commit, receipt, cleanup_receipt, private_directory):
    ids = cleanup_receipt.get("createdContainerIds", [])
    if private_directory.exists() or private_directory.is_symlink() or cleanup_receipt.get("ownedContainerAbsent") is not True or cleanup_receipt.get("privateFixtureRemoved") is not True or cleanup_receipt.get("terminalRemovalAcknowledgments") != 3 or len(ids) != 3 or len(set(ids)) != 3 or not all(isinstance(identifier, str) and re.fullmatch(r"[a-f0-9]{64}", identifier) for identifier in ids):
        raise ValueError("native_cleanup_incomplete")
    if receipt.get("passed") is not True or receipt.get("sourceCommit") != commit:
        raise ValueError("native_acceptance_incomplete")
    receipt["cleanup"] = cleanup_receipt
    output = ROOT / ".build" / ("native-acceptance-" + commit + ".json")
    with output.open("x") as file:
        file.write(json.dumps(receipt, indent=2) + "\n")
    return output


def accept(image, artifact_file):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("immutable_local_image_required")
    build.reviewed_source()
    artifact_bytes = artifact_file.read_bytes()
    artifact = json.loads(artifact_bytes)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT.parent, text=True).strip()
    if artifact["schema"] != "amz.ap.server-runtime.v1" or artifact["sourceCommit"] != commit or artifact["engine"]["worldPackSha256"] != build.WORLD_PACK_SHA256:
        raise ValueError("native_artifact_source_mismatch")
    inspected = json.loads(command(["image", "inspect", image]).stdout)[0]
    if inspected["Id"] != image or inspected["Architecture"] != "amd64" or inspected["Os"] != "linux":
        raise ValueError("native_image_platform_invalid")
    run_id = str(uuid.uuid4())
    name = "amz-ap-native-" + run_id
    private = ROOT / ".private" / ("native-" + run_id)
    private.mkdir(parents=True)
    storage = private / "storage"
    storage.mkdir()
    intent = private / "intent.json"
    intent_record = {"owner": OWNER, "runId": run_id, "name": name, "image": image, "sourceCommit": commit, "attempts": [], "removals": []}
    intent.write_text(json.dumps(intent_record))
    password = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    config = {"schema": 1, "attemptId": str(uuid.uuid4()), "seedRevision": 1, "credentialEpoch": 1, "runtimeLaunchId": str(uuid.uuid4()),
        "password": password, "port": 38281, "engineCommit": build.ENGINE_COMMIT, "worldPackSha256": build.WORLD_PACK_SHA256,
        "runtimeOverlaySha256": artifact["overlay"]["sha256"], "requiredCheckpointSha256": None, "allowFreshSave": True}
    config_file = storage / "current.json"
    config_file.write_text(json.dumps(config))
    observed = []
    receipt = None

    def status(predicate):
        for _ in range(100):
            try:
                value = json.loads((storage / "runtime-status.json").read_text())
                if value.get("runtimeLaunchId") == config["runtimeLaunchId"] and predicate(value):
                    return value
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            inspection = command(["inspect", "--format", "{{.State.Running}}", name], required=False)
            if inspection.stdout.strip() == b"false":
                raise RuntimeError("native_runtime_exited_before_observation")
            time.sleep(.25)
        raise RuntimeError("native_observation_timeout")

    def start():
        config_file.write_text(json.dumps(config))
        attempt = {"runtimeLaunchId": config["runtimeLaunchId"], "containerId": None, "state": "creating"}
        intent_record["attempts"].append(attempt)
        intent.write_text(json.dumps(intent_record))
        created = command(["create", "--name", name, "--label", "amz.owner=" + OWNER, "--label", "amz.run=" + run_id,
            "--read-only", "--network", "none", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--pids-limit", "128", "--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--stop-timeout", "15",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,uid=65532,gid=65532",
            "--mount", f"type=bind,src={storage.resolve()},dst=/home/container/.amz",
            "--mount", f"type=bind,src={(ROOT / 'tests').resolve()},dst=/qa,readonly",
            "--entrypoint", "/usr/local/bin/python", image, "-I", "-B", "/qa/runtime-fixture.py"])
        identifier = created.stdout.decode().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", identifier): raise ValueError("native_create_identity_invalid")
        attempt["containerId"] = identifier; attempt["state"] = "created"
        intent.write_text(json.dumps(intent_record))
        command(["start", name])

    def stop():
        container = json.loads(command(["inspect", name]).stdout)[0]
        identifier = intent_record["attempts"][-1]["containerId"]
        if container["Id"] != identifier or container["Image"] != image or container["Config"]["Labels"].get("amz.owner") != OWNER or container["Config"]["Labels"].get("amz.run") != run_id:
            raise ValueError("foreign_native_container_protected")
        command(["stop", "--time", "15", identifier])
        output = command(["logs", identifier])
        logs = output.stdout + output.stderr
        for secret in (password, config["password"]):
            if secret.encode() in logs:
                raise AssertionError("native_secret_log_leak")
        observed.append({"logsRedacted": True})
        removal_ack(intent_record, identifier, command(["rm", identifier]))
        intent.write_text(json.dumps(intent_record))

    def client(mode, expected):
        (storage / "probe-mode").write_text(mode)
        release = storage / "probe-release"
        release.unlink(missing_ok=True)
        process = subprocess.Popen(["docker", "exec", name, "python", "-I", "-B", "/qa/native-client.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # Client's own receive/hold deadlines and outer container lifetime are bounded.
            result = json.loads(process.stdout.readline())
            assert result == expected
            if result["authenticated"]:
                measured = status(lambda value: value["connectedGameClients"] == 1 and value["slots"][0]["checkedLocations"] == 1)
                observed.append({"connectedGameClients": measured["connectedGameClients"], "checkedLocations": measured["slots"][0]["checkedLocations"]})
            release.touch()
            process.communicate(timeout=15)
            assert process.returncode == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    try:
        start()
        initial = status(lambda value: value["state"] == "running")
        config.update(json.loads(config_file.read_text()))
        seed_sha = config["seedArtifactSha256"]
        client("current", {"authenticated": True, "refused": False})
        stop()
        checkpoint = (storage / "seed.apsave").read_bytes()
        checkpoint_sha = hashlib.sha256(checkpoint).hexdigest()
        (storage / "old-password").write_text(password)
        config.update({"password": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="), "credentialEpoch": 2,
            "runtimeLaunchId": str(uuid.uuid4()), "requiredCheckpointSha256": checkpoint_sha, "allowFreshSave": False})
        start()
        restored = status(lambda value: value["restoredCheckpointSha256"] == checkpoint_sha and value["slots"][0]["checkedLocations"] == 1)
        assert restored["seedArtifactSha256"] == seed_sha
        client("old", {"authenticated": False, "refused": True})
        client("current", {"authenticated": True, "refused": False})
        running = json.loads(command(["inspect", name]).stdout)[0]
        limits = running["HostConfig"]
        assert limits["Memory"] == 512 * 1024 ** 2 and limits["MemorySwap"] == limits["Memory"]
        assert limits["NanoCpus"] == 1000000000 and limits["PidsLimit"] == 128
        assert limits["ReadonlyRootfs"] and limits["NetworkMode"] == "none" and not limits["PortBindings"]
        assert limits["CapDrop"] == ["ALL"] and "no-new-privileges=true" in limits["SecurityOpt"]
        stop()
        # Real negative native load: a modified save cannot start a new listener or
        # reuse stale telemetry as proof of the new launch.
        current_checkpoint = (storage / "seed.apsave").read_bytes()
        config.update({"requiredCheckpointSha256": hashlib.sha256(current_checkpoint).hexdigest(), "runtimeLaunchId": str(uuid.uuid4())})
        (storage / "seed.apsave").write_bytes(current_checkpoint + b"tamper")
        start()
        for _ in range(100):
            failed = json.loads(command(["inspect", name]).stdout)[0]
            if not failed["State"]["Running"]:
                break
            time.sleep(.2)
        assert not failed["State"]["Running"] and failed["State"]["ExitCode"] != 0
        failure_logs = command(["logs", name])
        assert b"checkpoint_integrity" in failure_logs.stdout + failure_logs.stderr
        assert json.loads((storage / "runtime-status.json").read_text())["runtimeLaunchId"] != config["runtimeLaunchId"]
        stop()
        receipt = {"schema": "amz.ap.server-native-source-acceptance.v1", "sourceCommit": commit, "imageId": image,
            "runtimeArtifactSha256": hashlib.sha256(artifact_bytes).hexdigest(), "engineCommit": build.ENGINE_COMMIT,
            "worldPackSha256": build.WORLD_PACK_SHA256, "headlessMetadataSha256": build.WORLD_HINTS_SHA256,
            "seedSha256": seed_sha, "restoredCheckpointSha256": checkpoint_sha, "credentialEpoch": 2,
            "oldPasswordRejected": True, "newPasswordAccepted": True, "checksRetained": True,
            "tamperedCheckpointRejected": True,
            "network": "none", "hostPorts": [], "memoryLimitMiB": 512, "cpus": 1, "observations": observed,
            "qualification": "synthetic standard AP protocol and native checkpoint only; no game/browser/DMS qualification", "passed": True}
    except BaseException as error:
        # Preserve only fixed structured diagnostics; never retain credentials,
        # arbitrary tracebacks, the seed/save, or raw native output after failure.
        logs = command(["logs", name], required=False)
        stopped, diagnostics, output_sha = bounded_diagnostics(logs.stdout + logs.stderr)
        failed = {"schema": "amz.ap.server-native-source-failure.v1", "sourceCommit": commit, "imageId": image,
            "runtimeArtifactSha256": hashlib.sha256(artifact_bytes).hexdigest(), "errorType": type(error).__name__,
            "stopped": stopped, "diagnostics": diagnostics, "boundedOutputSha256": output_sha,
            "passed": False, "qualifiedGames": []}
        output = ROOT / ".build" / ("native-failure-" + commit + ".json")
        output.write_text(json.dumps(failed, indent=2) + "\n")
        print(json.dumps({"passed": False, "receipt": str(output), "stopped": stopped, "diagnostics": diagnostics, "qualifiedGames": []}))
        raise
    finally:
        try:
            cleanup_receipt = cleanup(intent)
        except BaseException as cleanup_error:
            failure = {"schema": "amz.ap.server-native-source-failure.v1", "sourceCommit": commit, "imageId": image,
                "runtimeArtifactSha256": hashlib.sha256(artifact_bytes).hexdigest(), "phase": "cleanup", "errorType": type(cleanup_error).__name__,
                "nativeAssertionsPassed": receipt is not None, "passed": False, "qualifiedGames": []}
            (ROOT / ".build" / ("native-failure-" + commit + ".json")).write_text(json.dumps(failure, indent=2) + "\n")
            raise
    # A pass becomes reviewable only after terminal removal and private-input
    # cleanup. Finally-block errors can never leave a published pass receipt.
    output = publish_passed_receipt(commit, receipt, cleanup_receipt, private)
    print(json.dumps({"passed": True, "receipt": str(output), "sourceCommit": commit, "qualifiedGames": []}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image")
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--cleanup", type=Path)
    args = parser.parse_args()
    if args.cleanup:
        cleanup(args.cleanup)
    elif args.image and args.artifact:
        accept(args.image, args.artifact)
    else:
        parser.error("Select immutable --image and --artifact, or exact owned --cleanup intent.")

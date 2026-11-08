"""Prepare a bounded immutable headless context; never import engine code."""
import argparse
import ast
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parent
ENGINE_COMMIT = "54803be064fc7e80c4628777ed0b46a9390f255f"
ENGINE_ARCHIVE_SHA256 = "3b9c408cd43b09ab27691d5a0b8d18686cd113ebdd06fdd9606c229010648ef8"
WORLD_PACK_SHA256 = "ea87c2f934bb559c64deeb76cf61253fdbb0d12b975de02929e18d97d508f54f"
WORLD_HINTS_SHA256 = "68e714887bfe7a867a74bc9a73d759f2b4c2e67a2e67dd0a784fa43b75dd01cc"
PYTHON_IMAGE = "python:3.12-slim-bookworm@sha256:623674a14ef93d052bb9b0de4dbf5f28eb578a35263838941cc8aa43213c1487"
NODE_IMAGE = "node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e"
RUNTIME_FILES = ("ap_runtime.py", "launcher.mjs")


def verify_hints(engine):
    """Only the pinned default and two exact overrides. No world code executes."""
    value = json.loads((ROOT / "world-hints.v1.json").read_text())
    expected = {name: ast.dump(ast.parse(expression, mode="eval").body) for name, expression in {
        "worlds/AutoWorld.py": "frozenset()",
        "worlds/alttp/__init__.py": "{'Triforce'}",
        "worlds/cvcotm/__init__.py": "frozenset({lname.ba24})",
    }.items()}
    seen = {}
    for file in (engine / "worlds").rglob("*.py"):
        source = source_bytes(file)
        if b"hint_blacklist" not in source:
            continue
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Attribute) and node.attr == "hint_blacklist" or isinstance(node, ast.Call) and any(isinstance(argument, ast.Constant) and argument.value == "hint_blacklist" for argument in node.args):
                raise ValueError("headless_hint_dynamic_override")
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id == "hint_blacklist" for target in targets):
                    name = file.relative_to(engine).as_posix()
                    if name in seen:
                        raise ValueError("headless_hint_declaration_changed")
                    seen[name] = ast.dump(node.value)
    if seen != expected or value["defaultBlacklist"] != [] or value["overrides"] != {
        "A Link to the Past": ["Triforce"], "Castlevania - Circle of the Moon": ["Battle Arena: End reward"]
    }:
        raise ValueError("headless_hint_declaration_changed")
    # No inherited override may silently acquire the empty base default.
    for file in (engine / "worlds").rglob("*.py"):
        source = source_bytes(file)
        if b"ALTTPWorld" not in source and b"CVCotMWorld" not in source:
            continue
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ClassDef) and any(isinstance(base, (ast.Name, ast.Attribute)) and getattr(base, "id", getattr(base, "attr", "")) in ("ALTTPWorld", "CVCotMWorld") for base in node.bases):
                raise ValueError("headless_hint_inherited_override")
    for row in value["sourceFiles"]:
        if row["algorithm"] != "sha256-lf" or digest(source_bytes(engine / row["path"])) != row["sha256"]:
            raise ValueError("headless_hint_source_changed")
    return value


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def source_bytes(file):
    return file.read_bytes().replace(b"\r\n", b"\n")


def safe_path(name):
    value = PurePosixPath(name)
    if not name or name == "." or value.is_absolute() or str(value) != name or "\\" in name or ":" in name or any(
        segment in ("", ".", "..") or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", segment)
        for segment in value.parts
    ) or any(ord(character) < 32 for character in name):
        raise ValueError("source_path_invalid")
    return value


def extract_inventory(archive, manifest, destination):
    """Select only pinned regular entries. Preserve all inventoried notices."""
    prefix = "Archipelago-" + ENGINE_COMMIT + "/"
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        entries = source.infolist()
        if len(entries) > 8192 or len({entry.filename for entry in entries}) != len(entries):
            raise ValueError("source_archive_invalid")
        indexed = {entry.filename: entry for entry in entries}
        total = 0
        for row in manifest["files"]:
            relative = safe_path(row["path"])
            entry = indexed.get(prefix + row["path"])
            if not entry or entry.is_dir() or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG) or entry.file_size > 64 * 1024 ** 2:
                raise ValueError("source_entry_invalid")
            total += entry.file_size
            if total > 256 * 1024 ** 2:
                raise ValueError("source_inventory_limit")
            original = source.read(entry)
            value = original
            if row["algorithm"] == "sha256-lf":
                value = value.replace(b"\r\n", b"\n")
            elif row["algorithm"] != "sha256":
                raise ValueError("source_algorithm_invalid")
            if digest(value) != row["sha256"]:
                raise ValueError("engine_source_changed")
            target = destination.joinpath(*relative.parts)
            if target.exists() or not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("source_path_invalid")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                # Verification normalizes once; keep the exact upstream bytes.
                # CRCRLF sequences are not idempotent under repeated replace().
                output.write(original)


def reviewed_source():
    raw = (ROOT / "engine-manifest.json").read_bytes()
    if digest(raw) != WORLD_PACK_SHA256:
        raise ValueError("engine_manifest_changed")
    manifest = json.loads(raw)
    if manifest["engineCommit"] != ENGINE_COMMIT or len(manifest["files"]) != 3539:
        raise ValueError("engine_pin_changed")
    if digest(source_bytes(ROOT / "world-hints.v1.json")) != WORLD_HINTS_SHA256:
        raise ValueError("headless_hint_metadata_changed")
    provenance = json.loads((ROOT / "source-provenance.v1.json").read_text())
    overlay = [{"path": name, "sha256": digest(source_bytes(ROOT / "runtime" / name))} for name in RUNTIME_FILES]
    if provenance["orderedPatches"][-1]["files"] != overlay:
        raise ValueError("runtime_source_changed")
    dependencies = json.loads((ROOT / "dependencies.v1.json").read_text())
    if dependencies["platform"] != "linux/amd64" or dependencies["python"] != "3.12":
        raise ValueError("dependency_platform_changed")
    for dependency in dependencies["dependencies"]:
        if not dependency["url"].startswith("https://files.pythonhosted.org/packages/") or not dependency["url"].endswith(".whl") or not re.fullmatch("[a-f0-9]{64}", dependency["sha256"]):
            raise ValueError("dependency_pin_invalid")
    expected_lock = "".join(f"{item['name']}=={item['version']} --hash=sha256:{item['sha256']}\n" for item in dependencies["dependencies"])
    if source_bytes(ROOT / "requirements.lock") != expected_lock.encode():
        raise ValueError("dependency_lock_changed")
    return manifest, provenance, overlay, dependencies


def fetch(url, expected_sha256, maximum, cache):
    file = cache / expected_sha256
    if file.exists():
        if file.is_symlink() or not file.is_file() or file.stat().st_size > maximum:
            raise ValueError("source_cache_invalid")
        value = file.read_bytes()
    else:
        value = bytearray()
        with urllib.request.urlopen(url, timeout=60) as response:
            while part := response.read(1024 * 1024):
                value.extend(part)
                if len(value) > maximum:
                    raise ValueError("source_download_limit")
        value = bytes(value)
        if digest(value) != expected_sha256:
            raise ValueError("source_download_changed")
        with file.open("xb") as output:
            output.write(value)
    if digest(value) != expected_sha256:
        raise ValueError("source_cache_changed")
    return value


def prepare():
    manifest, provenance, overlay, dependencies = reviewed_source()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPOSITORY, text=True).strip()
    if not re.fullmatch("[a-f0-9]{40}", commit) or subprocess.check_output(["git", "status", "--porcelain"], cwd=REPOSITORY, text=True).strip():
        raise ValueError("clean_committed_source_required")
    output = ROOT / ".build"
    output.mkdir(exist_ok=True)
    if output.is_symlink():
        raise ValueError("build_directory_invalid")
    cache = output / "cache"
    cache.mkdir(exist_ok=True)
    if cache.is_symlink():
        raise ValueError("build_directory_invalid")
    context = output / ("context-" + commit)
    context.mkdir()
    engine = context / "engine"
    engine.mkdir()
    archive = fetch("https://github.com/ArchipelagoMW/Archipelago/archive/" + ENGINE_COMMIT + ".zip", ENGINE_ARCHIVE_SHA256, 32 * 1024 ** 2, cache)
    extract_inventory(archive, manifest, engine)
    verify_hints(engine)
    runtime = context / "runtime"
    runtime.mkdir()
    for name in RUNTIME_FILES:
        (runtime / name).write_bytes(source_bytes(ROOT / "runtime" / name))
    (runtime / "engine-manifest.json").write_bytes((ROOT / "engine-manifest.json").read_bytes())
    (runtime / "world-hints.v1.json").write_bytes(source_bytes(ROOT / "world-hints.v1.json"))
    wheels = context / "wheels"
    wheels.mkdir()
    notices = []
    for dependency in dependencies["dependencies"]:
        value = fetch(dependency["url"], dependency["sha256"], 16 * 1024 ** 2, cache)
        (wheels / dependency["url"].rsplit("/", 1)[-1]).write_bytes(value)
        with zipfile.ZipFile(io.BytesIO(value)) as wheel:
            for entry in wheel.infolist():
                if re.search(r"(?:^|/)(?:LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*)$", entry.filename, re.I):
                    if entry.file_size > 1024 ** 2:
                        raise ValueError("dependency_notice_invalid")
                    notices.append({"dependency": dependency["name"], "path": entry.filename, "sha256": digest(wheel.read(entry))})
    for name in ("requirements.lock", "Dockerfile", "source-provenance.v1.json", "dependencies.v1.json"):
        (context / name).write_bytes(source_bytes(ROOT / name))
    artifact = {"schema": "amz.ap.server-runtime.v1", "version": 1, "repository": "Antimatter-Zone/DMS-Archipelago-Server", "sourceCommit": commit,
        "engine": {"version": "0.6.8", "commit": ENGINE_COMMIT, "archiveSha256": ENGINE_ARCHIVE_SHA256, "worldPackSha256": WORLD_PACK_SHA256},
        "overlay": {"sha256": digest(canonical({"schema": "amz.ap.runtime-overlay.v1", "files": overlay})), "files": overlay},
        "toolchain": {"pythonImage": PYTHON_IMAGE, "nodeImage": NODE_IMAGE, "dockerfileSha256": digest(source_bytes(ROOT / "Dockerfile")), "builderSha256": digest(source_bytes(ROOT / "build.py")), "requirementsSha256": digest(source_bytes(ROOT / "requirements.lock")), "dependenciesSha256": digest(source_bytes(ROOT / "dependencies.v1.json"))},
        "headlessMetadata": {"schema": "amz.ap.headless-world-hints.v1", "sha256": digest(source_bytes(ROOT / "world-hints.v1.json"))},
        "provenance": provenance, "dependencyNotices": notices}
    raw = json.dumps(artifact, indent=2).encode() + b"\n"
    (context / "server-runtime.v1.json").write_bytes(raw)
    (context / "server-runtime.v1.json.sha256").write_text(digest(raw) + "\n")
    print(json.dumps({"context": str(context), "artifact": str(context / "server-runtime.v1.json"), "sha256": digest(raw), "sourceCommit": commit, "published": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true", help="Download hash-verified inputs into a new bounded build context.")
    arguments = parser.parse_args()
    if arguments.prepare:
        prepare()
    else:
        reviewed_source()
        print("Headless source pins verified; no engine import, download or image build.")

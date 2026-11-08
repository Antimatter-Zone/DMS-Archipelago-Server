"""Container-only synthetic AP protocol fixture; never a generated/qualified game."""
import hashlib
import json
import os
from pathlib import Path
import pickle
import signal
import sys
import zlib

ROOT = Path("/home/container/.amz")
sys.path.insert(0, "/engine")
from NetUtils import NetworkSlot, SlotType

config = json.loads((ROOT / "current.json").read_text())
seed_file = ROOT / "seed.archipelago"
if not seed_file.exists():
    package = {"item_name_to_id": {"Synthetic item": 1001}, "location_name_to_id": {"Synthetic location": 1000}, "item_name_groups": {}, "location_name_groups": {}, "checksum": "synthetic-source-only"}
    data = {"version": (0, 6, 8), "minimum_versions": {"server": (0, 6, 8), "clients": {1: (0, 5, 0)}},
        "slot_info": {1: NetworkSlot("Player1", "APQuest", SlotType.player)}, "connect_names": {"Player1": (0, 1)},
        "locations": {1: {1000: (1001, 1, 0)}}, "slot_data": {1: {}}, "er_hint_data": {},
        "precollected_items": {1: []}, "precollected_hints": {1: set()}, "seed_name": "amz-synthetic-native-source-fixture",
        "server_options": {}, "datapackage": {"APQuest": package, "Archipelago": {**package, "item_name_to_id": {}, "location_name_to_id": {}}}, "spheres": []}
    seed = bytes([3]) + zlib.compress(pickle.dumps(data))
    seed_file.write_bytes(seed)
    config["seedArtifactSha256"] = hashlib.sha256(seed).hexdigest()
    (ROOT / "current.json").write_text(json.dumps(config))
else:
    assert hashlib.sha256(seed_file.read_bytes()).hexdigest() == config["seedArtifactSha256"]
# Inherited across exec: a crashed host harness cannot leave this runtime alive indefinitely.
signal.alarm(180)
os.execve("/usr/local/bin/node", ["node", "/opt/amz-ap/launcher.mjs"], {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "SKIP_REQUIREMENTS_UPDATE": "1"})

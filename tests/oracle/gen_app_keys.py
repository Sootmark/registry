"""Writes plaso-app-keys.tsv: what plaso's ccleaner, diagnosed_applications,
explorer_programscache, microsoft_outlook_mru, msie_zone and
windows_boot_execute plugins read from plaso's and Andrew Rathbun's test
hives (psort JSON lines), one line per event, sorted:
file, plugin, key (without its HKEY_… root), time in microseconds, values.

Run: python3 -I gen_app_keys.py plaso.jsonl rathbun.jsonl > plaso-app-keys.tsv
"""

import json
import sys

ROOTS = ("HKEY_CURRENT_USER\\", "HKEY_LOCAL_MACHINE\\Software\\", "HKEY_LOCAL_MACHINE\\System\\")


def key(path):
    for root in ROOTS:
        if path.startswith(root):
            return path[len(root):]
    return path


lines = []
for name in sys.argv[1:]:
    for line in open(name, encoding="utf-8"):
        e = json.loads(line)
        file = e["pathspec"]["location"].replace("/data/in/", "")
        t = e["data_type"]
        cells = None
        if t == "windows:registry:ccleaner:configuration":
            cells = ["ccleaner-config", "|".join(e["configuration"])]
        elif t == "windows:registry:ccleaner:update":
            cells = ["ccleaner-update"]
        elif t == "windows:registry:diagnosed_applications":
            cells = ["diagnosed-" + e["timestamp_desc"].replace(" ", "-").lower(), e["process_name"]]
        elif t == "windows:registry:explorer:programcache":
            cells = ["programscache", e["value_name"], e.get("known_folder_identifier") or "", e.get("entries") or ""]
        elif t == "windows:registry:outlook_search_mru":
            cells = ["outlook", e.get("entries") or ""]
        elif t == "windows:registry:msie_zone_settings":
            cells = ["zone", "|".join(f"{n}={v}" for n, v in e["settings"])]
        elif t == "windows:registry:boot_execute":
            cells = ["boot-execute", e["value"]]
        if cells is not None:
            lines.append("\t".join([file, cells[0], key(e["key_path"]), str(e["timestamp"])] + cells[1:]))
for line in sorted(lines):
    print(line)

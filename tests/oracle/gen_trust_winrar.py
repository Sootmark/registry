"""Writes trust-winrar.tsv, one line per item, sorted:

- `trust`: every Office trust record python-registry reads (file, key
  without its root, value name, the FILETIME in the data's first 8 bytes,
  1 when its last four bytes are FF FF FF 7F (macros enabled), the key's
  last written FILETIME);
- `winrar`: what plaso's winrar_mru plugin reads (file, key, the key's last
  written time in microseconds, plaso's `entries`).

Run from tests/fixtures, with python-registry installed:
python3 -I ../oracle/gen_trust_winrar.py winrar.jsonl HIVE... > ../oracle/trust-winrar.tsv
where winrar.jsonl holds plaso's `windows:registry:winrar:history` events
(psort json_line) of the same hives, read from a directory laid out as
tests/fixtures.
"""

import json
import struct
import sys

from Registry import Registry

TRUST = "Security\\Trusted Documents\\TrustRecords"
MACROS = b"\xff\xff\xff\x7f"


def walk(key, path):
    yield key, path
    for sub in key.subkeys():
        yield from walk(sub, path + "\\" + sub.name() if path else sub.name())


lines = []
plaso, hives = sys.argv[1], sys.argv[2:]
for line in open(plaso, encoding="utf-8"):
    e = json.loads(line)
    file = e["pathspec"]["location"].removeprefix("/data/in/")
    path = e["key_path"].removeprefix("HKEY_CURRENT_USER\\")
    lines.append("\t".join([file, "winrar", path, str(e["timestamp"]), e["entries"]]))
for hive in hives:
    root = Registry.Registry(hive).root()
    for key, path in walk(root, ""):
        if not path.endswith(TRUST):
            continue
        written = key._nkrecord.unpack_qword(0x4)
        for value in key.values():
            data = value.raw_data()
            (trusted,) = struct.unpack_from("<Q", data)
            macros = int(len(data) >= 12 and data[-4:] == MACROS)
            cells = [hive, "trust", path, value.name(), str(trusted), str(macros), str(written)]
            lines.append("\t".join(cells))
for line in sorted(lines):
    print(line)

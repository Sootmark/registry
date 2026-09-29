# Oracle dump (python-registry): one JSON line per key, depth first, subkeys
# in the hive's order: path, last written (FILETIME), values with name,
# type number and raw data (hex).
import json, sys
from Registry import Registry

def filetime(key):
    return key._nkrecord.timestamp()  # raw FILETIME? fall back below

def walk(key, path, out):
    values = []
    for v in key.values():
        try:
            rec = v._vkrecord
            size = rec.unpack_dword(0x4)
            kind = rec.unpack_dword(0xc)
            if size & 0x80000000:
                # Inline: the declared length of the offset field's bytes.
                raw = rec.unpack_dword(0x8).to_bytes(4, "little")[: min(size & 0x7fffffff, 4)]
            else:
                raw = v.raw_data()
            values.append({"name": v.name(), "type": kind, "data": raw.hex()})
        except Exception as e:
            values.append({"name": v.name(), "error": type(e).__name__})
    ts = key._nkrecord.unpack_qword(0x4)
    out.write(json.dumps({"path": path, "written": ts, "values": values}) + "\n")
    for sub in key.subkeys():
        walk(sub, path + "\\" + sub.name(), out)

reg = Registry.Registry(sys.argv[1])
walk(reg.root(), "", sys.stdout)

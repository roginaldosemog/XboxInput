"""Map XAM export entries and candidate callback signatures OFFLINE.

Input must be a decompressed, memory-layout PE extracted from the given XEX.
No addresses emitted here are approved for calling or patching on hardware.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from audit_16537 import inspect_xex, u32

XAM_ORDINALS = (400, 401, 402, 447, 463, 685, 746, 1183)
BIND_SIGNATURE = bytes.fromhex("7C8B23787CA42B7854CA063F")


def analyze(xex, image):
    metadata = inspect_xex(xex)
    base = int(metadata["preferred_image_base"], 16)
    security = u32(xex, 16)
    table_va = u32(xex, security + 0x160)
    offset = table_va - base
    if offset < 0 or offset + 44 > len(image):
        raise ValueError("XAM export table outside image")
    words = struct.unpack_from(">11I", image, offset)
    if words[:3] != (0x48000000, 0x00485645, 0x48000000):
        raise ValueError("Invalid XEX export-table magic")
    count, first = words[9:11]
    if not 0 < count <= 8192 or offset + 44 + count * 4 > len(image):
        raise ValueError("Invalid XAM export table count")
    if image[:2] != b"MZ":
        raise ValueError("Expected PE image")
    nt = struct.unpack_from("<I", image, 60)[0]
    if image[nt:nt + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    if struct.unpack_from("<I", image, nt + 24 + 28)[0] != base:
        raise ValueError("PE and XEX image-base mismatch")
    number = struct.unpack_from("<H", image, nt + 6)[0]
    opt_size = struct.unpack_from("<H", image, nt + 20)[0]
    section_table = nt + 24 + opt_size
    executable_sections = []
    for index in range(number):
        pos = section_table + 40 * index
        name = image[pos:pos + 8].rstrip(b"\0").decode("ascii", errors="replace")
        size, rva = struct.unpack_from("<II", image, pos + 8)
        flags = struct.unpack_from("<I", image, pos + 36)[0]
        if rva + size > len(image):
            raise ValueError("Section outside memory-layout PE")
        if flags & 0x20000000:
            executable_sections.append((name, rva, size))
    def in_code(address):
        return any(base + rva <= address < base + rva + size
                   for _, rva, size in executable_sections)
    exports = []
    for ordinal in XAM_ORDINALS:
        if not first <= ordinal < first + count:
            exports.append({"ordinal": ordinal, "present": False})
            continue
        relative = u32(image, offset + 44 + 4 * (ordinal - first))
        address = (words[8] << 16) + relative if relative else 0
        exports.append({"ordinal": ordinal, "present": bool(relative),
                        "address": "0x{:08X}".format(address),
                        "in_executable_section": in_code(address)})
    hits = []
    for name, rva, size in executable_sections:
        start = rva
        while True:
            match = image.find(BIND_SIGNATURE, start, rva + size)
            if match < 0:
                break
            if match % 4 == 0:
                hits.append({"address": "0x{:08X}".format(base + match), "section": name})
            start = match + 1
    return {
        "status": "OFFLINE_CANDIDATES_NOT_RUNTIME_VALIDATED",
        "version": metadata.get("execution_version"),
        "image_sha256": hashlib.sha256(image).hexdigest().upper(),
        "base": "0x{:08X}".format(base),
        "export_table_magic": ["0x{:08X}".format(word) for word in words[:3]],
        "export_count": count, "export_ordinal_base": first,
        "required_export_candidates": exports,
        "bind_device_signature_matches": hits,
        "warning": "A unique 12-byte signature is a candidate, not ABI or semantic proof.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xex", type=Path)
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.xex.read_bytes(), args.image.read_bytes()), indent=2))


if __name__ == "__main__":
    main()

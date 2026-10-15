"""Offline port inventory. Reads source/XEX metadata; never connects to a console.

This is NOT an XEX decoder, a compatibility verifier, or a plugin builder.
No ROM, CPU key, keyvault, credentials, or machine-specific path belongs here.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


def u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("Truncated XEX field")
    return struct.unpack_from(">I", data, offset)[0]


def version_string(value):
    return "{}.{}.{}.{}".format(
        value >> 28, (value >> 24) & 15, (value >> 8) & 65535, value & 255
    )


def inspect_xex(data):
    if len(data) < 24 or data[:4] != b"XEX2":
        raise ValueError("Not an XEX2 image")
    count = u32(data, 20)
    if count > (len(data) - 24) // 8:
        raise ValueError("Truncated optional-header table")
    result = {
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "pe_data_offset": u32(data, 8),
        "note": "Header metadata only; execution version does not prove running kernel.",
    }
    for index in range(count):
        key = u32(data, 24 + index * 8)
        value = u32(data, 28 + index * 8)
        if key == 0x00040006:  # XEX execution info, six DWORDs
            if value + 24 > len(data):
                raise ValueError("Truncated execution-info header")
            result["execution_version"] = version_string(u32(data, value + 4))
            result["execution_base_version"] = version_string(u32(data, value + 8))
        elif key == 0x000003FF:  # File format info: size, encryption, compression
            size = u32(data, value)
            if size < 8 or value + size > len(data):
                raise ValueError("Invalid file-format-info header")
            encryption, compression = struct.unpack_from(">HH", data, value + 4)
            result["encryption_type"] = encryption
            result["compression_type"] = compression
        elif key == 0x00010201:  # Immediate image base
            result["preferred_image_base"] = "0x{:08X}".format(value)
    return result


def strip_comments(text):
    # Preserve line numbers. Preserve quoted strings, including // inside them.
    pattern = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    def replace(match):
        value = match.group(0)
        if value.startswith(("//", "/*")):
            return "\n" * value.count("\n")
        return value
    return re.sub(pattern, replace, text)


def inventory(text):
    clean = strip_comments(text)
    addresses = []
    exports = []
    for line_number, line in enumerate(clean.splitlines(), 1):
        for address in re.findall(r"\b0x8[0-9a-fA-F]{7}\b", line):
            addresses.append({"line": line_number, "value": address.upper(),
                              "source": line.strip()})
        match = re.search(
            r"XexGetProcedureAddress\((kernelHandle|xamHandle),\s*(\d+),\s*(.*?)\);", line)
        if match:
            exports.append({"line": line_number, "module": match[1],
                            "ordinal": int(match[2]), "destination": match[3]})
    return {
        "target_kernel": 16537,
        "status": "BLOCKED_NOT_PORTED",
        "warning": "Lexical candidates, NOT a preprocessed list of live addresses; includes masks.",
        "original_version_guard_present": bool(re.search(
            r"XboxKrnlVersion->Build != 17559 && XboxKrnlVersion->Build != 17489", clean)),
        "address_candidates": addresses,
        "export_lookups": exports,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1] / "source")
    parser.add_argument("--xam", type=Path, help="Optional local, read-only XAM snapshot")
    args = parser.parse_args()
    result = inventory((args.source_root / "main.cpp").read_text(encoding="utf-8"))
    if args.xam:
        result["xam_metadata"] = inspect_xex(args.xam.read_bytes())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

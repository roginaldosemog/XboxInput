"""Extract an UNENCRYPTED XEX2 copy for offline analysis; never patch the input.

Normal compression follows emoose/idaxex formats/xex.cpp; block SHA-1 values
are verified before calling the separately built libmspack analysis DLL.
This does not validate the Microsoft signature or runtime compatibility.
"""
import argparse
import ctypes
import hashlib
import json
import struct
from pathlib import Path

from audit_16537 import inspect_xex, u32


def deblock(data, offset, size, digest):
    chunks = []
    blocks = 0
    while size:
        if size < 26 or offset + size > len(data):
            raise ValueError("Invalid compressed block bounds")
        block = data[offset:offset + size]
        if hashlib.sha1(block).digest() != digest:
            raise ValueError("Compressed block SHA-1 mismatch")
        next_size = u32(block, 0)
        next_digest = block[4:24]
        cursor = 24
        while True:
            if cursor + 2 > len(block):
                raise ValueError("Missing compressed chunk terminator")
            count = struct.unpack_from(">H", block, cursor)[0]
            cursor += 2
            if not count:
                break
            if count > 0x9800 or cursor + count > len(block):
                raise ValueError("Invalid compressed chunk bounds")
            chunks.append(block[cursor:cursor + count])
            cursor += count
        offset += size
        size, digest = next_size, next_digest
        blocks += 1
    return b"".join(chunks), blocks


def extract(data, dll_path=None):
    metadata = inspect_xex(data)
    if metadata.get("encryption_type", 0) != 0:
        raise ValueError("Encrypted XEX not supported: no keys are requested or read")
    headers = {u32(data, 24 + i * 8): u32(data, 28 + i * 8)
               for i in range(u32(data, 20))}
    security = u32(data, 16)
    image_size = u32(data, security + 4)
    if not 0 < image_size <= 64 * 1024 * 1024:
        raise ValueError("Unreasonable image size")
    offset = metadata["pe_data_offset"]
    fmt = headers.get(0x3FF)
    compression = metadata.get("compression_type", 0)
    blocks = 0
    if compression == 2:
        if fmt is None or u32(data, fmt) < 36:
            raise ValueError("Truncated normal-compression header")
        window = u32(data, fmt + 8)
        if window < 32768 or window > 2097152 or window & (window - 1):
            raise ValueError("Invalid LZX window size")
        source, blocks = deblock(data, offset, u32(data, fmt + 12), data[fmt + 16:fmt + 36])
        if not dll_path:
            raise ValueError("Normal compression requires --lzx-dll")
        dll = ctypes.CDLL(str(Path(dll_path).resolve()))
        decode = dll.xboxinput_lzx_decode
        decode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                           ctypes.c_size_t, ctypes.c_int]
        decode.restype = ctypes.c_int
        src = ctypes.create_string_buffer(source)
        dst = ctypes.create_string_buffer(image_size)
        code = decode(src, len(source), dst, image_size, window.bit_length() - 1)
        if code:
            raise ValueError("libmspack returned {}".format(code))
        image = dst.raw
    elif compression == 1:
        if fmt is None:
            raise ValueError("Missing basic-compression header")
        fmt_size = u32(data, fmt)
        if fmt_size < 8 or (fmt_size - 8) % 8:
            raise ValueError("Invalid basic-compression header")
        image = bytearray()
        for pos in range(fmt + 8, fmt + fmt_size, 8):
            raw, zeros = u32(data, pos), u32(data, pos + 4)
            if offset + raw > len(data) or len(image) + raw + zeros > image_size:
                raise ValueError("Basic block exceeds image/input bounds")
            image.extend(data[offset:offset + raw])
            image.extend(bytes(zeros))
            offset += raw
        image = bytes(image)
    elif compression == 0:
        image = data[offset:offset + image_size]
    else:
        raise ValueError("Unsupported compression")
    if len(image) != image_size or image[:2] != b"MZ":
        raise ValueError("Invalid extracted PE image")
    metadata["compressed_blocks_verified"] = blocks
    metadata["extracted_bytes"] = len(image)
    metadata["extracted_sha256"] = hashlib.sha256(image).hexdigest().upper()
    # XEX2 security image info, as emoose/idaxex formats/xex.hpp / xex.cpp.
    metadata["export_table_va"] = "0x{:08X}".format(u32(data, security + 0x160))
    return image, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--lzx-dll", type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve() or args.output.exists():
        parser.error("Output must be a NEW file, distinct from the input")
    image, metadata = extract(args.input.read_bytes(), args.lzx_dll)
    with args.output.open("xb") as output:
        output.write(image)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()

import hashlib
import struct
import unittest

from extract_xex import deblock, extract


def basic_image(encrypted=0):
    data = bytearray(256)
    data[:4] = b"XEX2"
    struct.pack_into(">IIII", data, 8, 128, 0, 64, 1)
    struct.pack_into(">II", data, 24, 0x3FF, 40)
    struct.pack_into(">IHHII", data, 40, 16, encrypted, 1, 2, 126)
    struct.pack_into(">I", data, 68, 128)
    data[128:130] = b"MZ"
    # Security export-table field is outside this minimal synthetic header.
    data.extend(bytes(256))
    return bytes(data)


class ExtractTests(unittest.TestCase):
    def test_deblock_valid(self):
        block = bytes(24) + b"\x00\x03abc\x00\x00"
        stream, count = deblock(block, 0, len(block), hashlib.sha1(block).digest())
        self.assertEqual((stream, count), (b"abc", 1))

    def test_deblock_hash_failure(self):
        block = bytes(24) + b"\x00\x00"
        with self.assertRaisesRegex(ValueError, "SHA-1"):
            deblock(block, 0, len(block), bytes(20))

    def test_deblock_bounds_failure(self):
        block = bytes(24) + b"\x00\x04ab"
        with self.assertRaisesRegex(ValueError, "bounds"):
            deblock(block, 0, len(block), hashlib.sha1(block).digest())

    def test_basic_extract(self):
        image, metadata = extract(basic_image())
        self.assertEqual(image, b"MZ" + bytes(126))
        self.assertEqual(metadata["compressed_blocks_verified"], 0)

    def test_reject_encrypted_without_reading_keys(self):
        with self.assertRaisesRegex(ValueError, "Encrypted"):
            extract(basic_image(encrypted=1))

    def test_basic_overflow(self):
        data = bytearray(basic_image())
        struct.pack_into(">I", data, 52, 129)
        with self.assertRaisesRegex(ValueError, "bounds"):
            extract(bytes(data))


if __name__ == "__main__":
    unittest.main()

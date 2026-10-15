import struct
import unittest

from map_xam import BIND_SIGNATURE, analyze


def fixture():
    base = 0x815F0000
    xex = bytearray(512)
    xex[:4] = b"XEX2"
    struct.pack_into(">II", xex, 16, 64, 1)
    struct.pack_into(">II", xex, 24, 0x10201, base)
    struct.pack_into(">I", xex, 64 + 0x160, base + 0x1000)
    image = bytearray(0x4000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 60, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x86, 1)
    struct.pack_into("<H", image, 0x94, 224)
    struct.pack_into("<I", image, 0x80 + 24 + 28, base)
    pos = 0x80 + 24 + 224
    image[pos:pos + 8] = b".text\0\0\0"
    struct.pack_into("<II", image, pos + 8, 0x800, 0x400)
    struct.pack_into("<I", image, pos + 36, 0x60000020)
    struct.pack_into(">11I", image, 0x1000, 0x48000000, 0x00485645, 0x48000000,
                     0, 0, 0, 0, 0, base >> 16, 1183, 1)
    struct.pack_into(">I", image, 0x1000 + 44 + 399 * 4, 0x500)
    image[0x500:0x500 + len(BIND_SIGNATURE)] = BIND_SIGNATURE
    return xex, image


class MapTests(unittest.TestCase):
    def test_export_resolution_and_signature(self):
        result = analyze(*fixture())
        self.assertEqual(result["required_export_candidates"][0]["address"], "0x815F0500")
        self.assertTrue(result["required_export_candidates"][0]["in_executable_section"])
        self.assertEqual(result["bind_device_signature_matches"],
                         [{"address": "0x815F0500", "section": ".text"}])

    def test_duplicate_pattern_is_not_silently_selected(self):
        xex, image = fixture()
        image[0x600:0x600 + len(BIND_SIGNATURE)] = BIND_SIGNATURE
        self.assertEqual(len(analyze(xex, image)["bind_device_signature_matches"]), 2)

    def test_rejects_wrong_export_magic(self):
        xex, image = fixture()
        image[0x1000] = 0
        with self.assertRaisesRegex(ValueError, "magic"):
            analyze(xex, image)

    def test_rejects_base_mismatch(self):
        xex, image = fixture()
        struct.pack_into("<I", image, 0x80 + 24 + 28, 0x82000000)
        with self.assertRaisesRegex(ValueError, "base"):
            analyze(xex, image)

    def test_export_outside_code_not_approved(self):
        xex, image = fixture()
        struct.pack_into(">I", image, 0x1000 + 44 + 399 * 4, 0x2000)
        self.assertFalse(analyze(xex, image)["required_export_candidates"][0]["in_executable_section"])


if __name__ == "__main__":
    unittest.main()

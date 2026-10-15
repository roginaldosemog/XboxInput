import struct
import unittest

from audit_16537 import inspect_xex, inventory, version_string


class AuditTests(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(version_string((2 << 28) | (16537 << 8)), "2.0.16537.0")
        self.assertEqual(version_string((2 << 28) | (17559 << 8)), "2.0.17559.0")

    def test_xex_metadata(self):
        data = bytearray(128)
        data[:4] = b"XEX2"
        struct.pack_into(">I", data, 20, 3)
        struct.pack_into(">II", data, 24, 0x40006, 64)
        struct.pack_into(">II", data, 32, 0x3FF, 96)
        struct.pack_into(">II", data, 40, 0x10201, 0x81600000)
        struct.pack_into(">II", data, 68, 0x20409900, 0x20409900)
        struct.pack_into(">IHH", data, 96, 8, 1, 2)
        result = inspect_xex(data)
        self.assertEqual(result["execution_version"], "2.0.16537.0")
        self.assertEqual(result["preferred_image_base"], "0x81600000")
        self.assertEqual(result["compression_type"], 2)
        self.assertEqual(result["encryption_type"], 1)
        self.assertEqual(len(result["sha256"]), 64)

    def test_rejects_invalid_headers(self):
        for data in (b"", b"XEX2", b"MZ" + bytes(64)):
            with self.assertRaises(ValueError):
                inspect_xex(data)

    def test_rejects_truncated_table(self):
        data = bytearray(b"XEX2" + bytes(20))
        struct.pack_into(">I", data, 20, 100)
        with self.assertRaises(ValueError):
            inspect_xex(data)

    def test_rejects_truncated_execution_info(self):
        data = bytearray(b"XEX2" + bytes(28))
        struct.pack_into(">I", data, 20, 1)
        struct.pack_into(">II", data, 24, 0x40006, 30)
        with self.assertRaises(ValueError):
            inspect_xex(data)

    def test_inventory_ignores_comments_and_keeps_lines(self):
        result = inventory("// 0x80000001\n/* 0x80000002\n */\n"
                           "p = (void*)0x800D8500;\n"
                           "XexGetProcedureAddress(kernelHandle, 759, &p);\n")
        self.assertEqual(len(result["address_candidates"]), 1)
        self.assertEqual(result["address_candidates"][0]["line"], 4)
        self.assertEqual(result["export_lookups"][0]["ordinal"], 759)
        self.assertFalse(result["original_version_guard_present"])
        self.assertEqual(result["status"], "BLOCKED_NOT_PORTED")


if __name__ == "__main__":
    unittest.main()

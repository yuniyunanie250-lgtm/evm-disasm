import unittest

from evm_disasm import OPCODES, disassemble, format_lines, jumpdests, parse_hex


class ParseHex(unittest.TestCase):
    def test_accepts_prefix_and_bare(self):
        self.assertEqual(parse_hex("0x6001"), b"\x60\x01")
        self.assertEqual(parse_hex("6001"), b"\x60\x01")

    def test_rejects_odd_length(self):
        with self.assertRaises(ValueError):
            parse_hex("0xabc")

    def test_rejects_non_hex(self):
        with self.assertRaises(ValueError):
            parse_hex("0xzz")


class Disassemble(unittest.TestCase):
    def test_push_operand_is_consumed(self):
        # PUSH1 0x5b -- the operand looks like JUMPDEST but is data
        steps = list(disassemble(parse_hex("0x605b")))
        self.assertEqual(steps, [(0, "PUSH1", "5b")])
        self.assertEqual(jumpdests(parse_hex("0x605b")), [])

    def test_real_jumpdest_is_found(self):
        steps = list(disassemble(parse_hex("0x5b6001")))
        self.assertEqual(steps[0], (0, "JUMPDEST", None))
        self.assertEqual(jumpdests(parse_hex("0x5b6001")), [0])

    def test_push32_consumes_thirty_two_bytes(self):
        code = parse_hex("0x7f" + "11" * 32 + "00")
        steps = list(disassemble(code))
        self.assertEqual(steps[0][1], "PUSH32")
        self.assertEqual(len(steps[0][2]), 64)
        self.assertEqual(steps[1][1], "STOP")

    def test_push0_has_no_operand(self):
        steps = list(disassemble(parse_hex("0x5f")))
        self.assertEqual(steps, [(0, "PUSH0", None)])

    def test_unknown_opcode_is_reported_not_skipped(self):
        steps = list(disassemble(parse_hex("0x0c")))
        self.assertEqual(steps, [(0, "UNKNOWN_0x0c", None)])

    def test_truncated_push_operand_does_not_crash(self):
        steps = list(disassemble(parse_hex("0x61ff")))
        self.assertEqual(steps[0][1], "PUSH2")
        self.assertEqual(steps[0][2], "ff")


class Table(unittest.TestCase):
    def test_opcode_ranges_are_populated(self):
        self.assertEqual(OPCODES[0x60][0], "PUSH1")
        self.assertEqual(OPCODES[0x7F][0], "PUSH32")
        self.assertEqual(OPCODES[0x80][0], "DUP1")
        self.assertEqual(OPCODES[0x8F][0], "DUP16")
        self.assertEqual(OPCODES[0x90][0], "SWAP1")
        self.assertEqual(OPCODES[0x9F][0], "SWAP16")

    def test_format_lines_aligns(self):
        lines = format_lines(parse_hex("0x6001"))
        self.assertEqual(len(lines), 1)
        self.assertIn("PUSH1", lines[0])
        self.assertTrue(lines[0].startswith("0x0000"))


if __name__ == "__main__":
    unittest.main()

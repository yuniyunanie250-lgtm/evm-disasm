"""A disassembler for EVM bytecode.

Walks a hex blob and prints one line per instruction: offset, opcode, name, and
the operand for PUSH instructions. Unlike a naive byte walk, PUSH immediates are
consumed rather than decoded, which is the difference between a correct
disassembly and one full of phantom opcodes.

    $ python3 -m evm_disasm 0x6080604052348015600f57600080fd5b50
    0x0000  PUSH1   0x80
    0x0002  PUSH1   0x40
    0x0004  MSTORE
    ...

No dependencies. No RPC needed.
"""

OPCODES = {
    0x00: ("STOP", 0), 0x01: ("ADD", 0), 0x02: ("MUL", 0), 0x03: ("SUB", 0),
    0x04: ("DIV", 0), 0x05: ("SDIV", 0), 0x06: ("MOD", 0), 0x07: ("SMOD", 0),
    0x08: ("ADDMOD", 0), 0x09: ("MULMOD", 0), 0x0A: ("EXP", 0),
    0x0B: ("SIGNEXTEND", 0), 0x10: ("LT", 0), 0x11: ("GT", 0), 0x12: ("SLT", 0),
    0x13: ("SGT", 0), 0x14: ("EQ", 0), 0x15: ("ISZERO", 0), 0x16: ("AND", 0),
    0x17: ("OR", 0), 0x18: ("XOR", 0), 0x19: ("NOT", 0), 0x1A: ("BYTE", 0),
    0x1B: ("SHL", 0), 0x1C: ("SHR", 0), 0x1D: ("SAR", 0),
    0x20: ("KECCAK256", 0), 0x30: ("ADDRESS", 0), 0x31: ("BALANCE", 0),
    0x32: ("ORIGIN", 0), 0x33: ("CALLER", 0), 0x34: ("CALLVALUE", 0),
    0x35: ("CALLDATALOAD", 0), 0x36: ("CALLDATASIZE", 0), 0x37: ("CALLDATACOPY", 0),
    0x38: ("CODESIZE", 0), 0x39: ("CODECOPY", 0), 0x3A: ("GASPRICE", 0),
    0x3B: ("EXTCODESIZE", 0), 0x3C: ("EXTCODECOPY", 0), 0x3D: ("RETURNDATASIZE", 0),
    0x3E: ("RETURNDATACOPY", 0), 0x3F: ("EXTCODEHASH", 0),
    0x40: ("BLOCKHASH", 0), 0x41: ("COINBASE", 0), 0x42: ("TIMESTAMP", 0),
    0x43: ("NUMBER", 0), 0x44: ("PREVRANDAO", 0), 0x45: ("GASLIMIT", 0),
    0x46: ("CHAINID", 0), 0x47: ("SELFBALANCE", 0), 0x48: ("BASEFEE", 0),
    0x50: ("POP", 0), 0x51: ("MLOAD", 0), 0x52: ("MSTORE", 0), 0x53: ("MSTORE8", 0),
    0x54: ("SLOAD", 0), 0x55: ("SSTORE", 0), 0x56: ("JUMP", 0), 0x57: ("JUMPI", 0),
    0x58: ("PC", 0), 0x59: ("MSIZE", 0), 0x5A: ("GAS", 0), 0x5B: ("JUMPDEST", 0),
    0x5C: ("TLOAD", 0), 0x5D: ("TSTORE", 0), 0x5E: ("MCOPY", 0),
    0x5F: ("PUSH0", 0),
    0xA0: ("LOG0", 0), 0xA1: ("LOG1", 0), 0xA2: ("LOG2", 0), 0xA3: ("LOG3", 0),
    0xA4: ("LOG4", 0),
    0xF0: ("CREATE", 0), 0xF1: ("CALL", 0), 0xF2: ("CALLCODE", 0),
    0xF3: ("RETURN", 0), 0xF4: ("DELEGATECALL", 0), 0xF5: ("CREATE2", 0),
    0xFA: ("STATICCALL", 0), 0xFD: ("REVERT", 0), 0xFE: ("INVALID", 0),
    0xFF: ("SELFDESTRUCT", 0),
}

for _i in range(1, 33):
    OPCODES[0x5F + _i] = ("PUSH%d" % _i, _i)
for _i in range(1, 17):
    OPCODES[0x7F + _i] = ("DUP%d" % _i, 0)
    OPCODES[0x8F + _i] = ("SWAP%d" % _i, 0)


def parse_hex(text):
    """Hex string (with or without 0x) to bytes."""
    s = text[2:] if text[:2].lower() == "0x" else text
    s = s.strip()
    if len(s) % 2:
        raise ValueError("odd number of hex digits: %d" % len(s))
    if not all(c in "0123456789abcdefABCDEF" for c in s):
        raise ValueError("non-hex character in %r" % text)
    return bytes.fromhex(s)


def disassemble(code):
    """Yield (offset, mnemonic, operand_hex_or_None) tuples."""
    i = 0
    while i < len(code):
        op = code[i]
        entry = OPCODES.get(op)
        if entry is None:
            yield (i, "UNKNOWN_0x%02x" % op, None)
            i += 1
            continue
        name, imm_len = entry
        operand = None
        if imm_len:
            operand = code[i + 1:i + 1 + imm_len].hex()
        yield (i, name, operand)
        i += 1 + imm_len


def jumpdests(code):
    """Offsets that are real JUMPDESTs, ignoring 0x5b bytes inside operands."""
    return [off for off, name, _ in disassemble(code) if name == "JUMPDEST"]


def format_lines(code):
    return [
        "0x%04x  %-12s %s" % (off, name, operand if operand else "")
        for off, name, operand in disassemble(code)
    ]


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    code = parse_hex(argv[0])
    for line in format_lines(code):
        print(line)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))

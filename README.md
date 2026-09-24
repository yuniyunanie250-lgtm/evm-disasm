# evm-disasm

A dependency-free disassembler for EVM bytecode. Hex in, one line per
instruction out.

Reading raw runtime bytecode by eye is how you miss a jump target. This walks the
blob properly: **PUSH operands are consumed as data**, so a `0x5b` byte sitting
inside a `PUSH1` operand is not reported as a `JUMPDEST`.

## Usage

```bash
python3 -m evm_disasm 0x6080604052348015600f57600080fd5b
```

```
0x0000  PUSH1        80
0x0002  PUSH1        40
0x0004  MSTORE
0x0005  CALLVALUE
0x0006  DUP1
0x0007  ISZERO
0x0008  PUSH1        0f
0x000a  JUMPI
...
```

As a library:

```python
from evm_disasm import disassemble, jumpdests
list(disassemble(bytes.fromhex("605b")))   # [(0, 'PUSH1', '5b')]
jumpdests(bytes.fromhex("5b6001"))         # [0]
```

## The correctness detail

`jumpdests()` is the function that matters. Any tool that scans for the byte
`0x5b` finds jump destinations that do not exist, because `0x5b` is also a valid
`PUSH` operand byte. Skipping operands is the whole trick, and there is a test
pinning it.

## What it does not do

- **No control-flow graph.** It gives you instructions and real `JUMPDEST`
  offsets; building basic blocks is a layer above.
- **No data-section analysis.** PUSH operands that are addresses or selectors are
  shown as hex, not decoded.
- **No source mapping.** That requires the compiler's metadata, not the bytecode.

## Development

```bash
python3 -m unittest discover -s test
```

## License

MIT

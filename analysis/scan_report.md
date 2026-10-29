# Function discovery — SporeApp.exe

* linear sweep: 5,496,576 instructions in .text (16,559,914 bytes)
* seeds: 81,731 (entry + call targets + prologues + code pointers)
* functions recovered: 18,654
* instructions inside functions: 2,066,220
* call targets: 35,941; branch targets: 277,362
* indirect `jmp` sites in sweep: 3,171
* functions with indirect jmp: 438
* functions with jump-table-shaped indirect jmp: 231
* largest functions: 0xb8fe00 (20,010 insn), 0x1d7b95 (20,008 insn), 0xc7c6d0 (20,006 insn), 0x37e510 (12,909 insn), 0xbba300 (12,806 insn)

## Mnemonic histogram (top 60)

| mnemonic | count |
|---|---|
| mov | 1,444,236 |
| int3 | 733,403 |
| push | 593,433 |
| call | 327,517 |
| movss | 293,994 |
| add | 199,499 |
| pop | 190,181 |
| je | 172,775 |
| lea | 171,826 |
| cmp | 167,597 |
| test | 129,415 |
| ret | 116,091 |
| jmp | 72,115 |
| sub | 71,243 |
| xor | 66,624 |
| jne | 66,233 |
| fld | 65,007 |
| fstp | 54,731 |
| mulss | 49,662 |
| movaps | 35,224 |
| addss | 27,795 |
| movzx | 27,046 |
| fmul | 26,848 |
| and | 23,005 |
| subss | 20,053 |
| inc | 19,916 |
| or | 16,124 |
| sar | 16,036 |
| jbe | 15,264 |
| xorps | 15,178 |
| shl | 13,747 |
| imul | 13,010 |
| shr | 12,887 |
| jle | 12,147 |
| jae | 11,722 |
| faddp | 11,435 |
| comiss | 10,963 |
| jl | 9,341 |
| jb | 9,141 |
| fadd | 7,933 |
| ja | 7,584 |
| dec | 6,789 |
| fxch | 6,285 |
| jge | 6,239 |
| fsub | 5,982 |
| rep movsd | 5,549 |
| mulps | 4,941 |
| fst | 4,790 |
| neg | 4,323 |
| shufps | 3,757 |
| sbb | 3,721 |
| fsqrt | 3,551 |
| divss | 3,377 |
| fmulp | 3,162 |
| cvtsi2ss | 3,103 |
| ucomiss | 3,045 |
| lahf | 2,950 |
| jg | 2,906 |
| movsx | 2,892 |
| addps | 2,695 |

## Rare / risky mnemonics

* in: 385
* out: 320
* hlt: 62
* lcall: 57
* ljmp: 39
* insb: 36
* outsb: 57
* xlatb: 95
* enter: 105
* aaa: 54
* aas: 25
* daa: 37
* das: 29

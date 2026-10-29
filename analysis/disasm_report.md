# Disassembly census — SporeApp.exe

* .text: 16,559,914 bytes at 0x1000
* linear sweep: 5,496,576 instructions, 457 undecodable bytes
* seeds: 99,382
* functions: 50,530
* decoded instructions: 4,007,285
* bytes claimed: 13,203,898 (79.7% of .text)
* functions that hit a decode limit: 14,285
* basic blocks: 657,177

## Unclaimed bytes by kind

| kind | bytes |
|---|---|
| unexplained | 2,979,390 |
| mostly int3 | 275,544 |
| int3 pad | 88,407 |
| zero fill | 12,649 |
| ascii data | 26 |

## Largest unexplained gaps (11601)

* 0x00fb9030..0x00fbc990 (14,688 B) `b909a57101e80690e2ff6870ba3c01e8`
* 0x00fbcef4..0x00fbffff (12,555 B) `ccccccccccccccccccccccccb959505e`
* 0x00f09ac5..0x00f0c560 (10,907 B) `ccccccccccccccccccccccf30f10058c`
* 0x00fb6c81..0x00fb8e50 (8,655 B) `ccccccccccccccccccccccccccccccf3`
* 0x0053e551..0x0053ffff (6,830 B) `cccccccccccccccccccccccccccccc8b`
* 0x0038e572..0x0038ff09 (6,551 B) `d8cddc8c24d0010000d9442470dec2d9`
* 0x00654893..0x00656160 (6,349 B) `cccccccccccccccccccccccccca1ec55`
* 0x0018e6d0..0x0018fede (6,158 B) `81ecc4000000535556576a006a006a00`
* 0x00f07761..0x00f08d20 (5,567 B) `ccccccccccccccccccccccccccccccf3`
* 0x0050b1e4..0x0050c790 (5,548 B) `cccccccccccccccccccccccc8b4c2408`
* 0x00e11a97..0x00e12fc0 (5,417 B) `000000e9217c59ff8b4df081c1ec0000`
* 0x00f6babc..0x00f6cf30 (5,236 B) `ccccccccf30f1005142e5a01f30f1105`
* 0x0071e486..0x0071f8a0 (5,146 B) `cccccccccccccccccccc6a006a006a00`
* 0x0011b03e..0x0011c417 (5,081 B) `8b8534feffffc7803c03000001000000`
* 0x00fcab0c..0x00fcbe2f (4,899 B) `ccccccccb988066e01e9f68124ffcccc`
* 0x0056570c..0x00566a0f (4,867 B) `8b168b420468d8e9ecff8bceffd08b7d`
* 0x00cbd883..0x00cbeb76 (4,851 B) `d94750d84e10d94614d84f54d94618d8`
* 0x00fc30b1..0x00fc4340 (4,751 B) `cccccccccccccccccccccccccccccca1`
* 0x00348c82..0x00349ec4 (4,674 B) `cccccccccccccccccccccccccccc81c1`
* 0x00cbba0e..0x00cbcc40 (4,658 B) `8bff8b442410d940048d4640d946108d`
* 0x00f7d987..0x00f7eb40 (4,537 B) `cccccccccccccccccc6a006a006a006a`
* 0x00e0d922..0x00e0ea90 (4,462 B) `ffffe937432dff8d8d60faffffe9ac45`
* 0x00f76803..0x00f778f0 (4,333 B) `cccccccccccccccccccccccccc6a006a`
* 0x00f78a81..0x00f79b60 (4,319 B) `cccccccccccccccccccccccccccccc6a`
* 0x009c1cf5..0x009c2dd0 (4,315 B) `cccccccccccccccccccccc81ec880000`

## Mnemonic histogram (top 40)

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

# PE report: `SporeApp.exe.unpacked.exe`

* size: 24,895,528 bytes
* sha256: `086f299216f6a70d2c23be0fb04b4b7c570d3bbd94ca0b26bcad53681b3e9fe7`
* machine: 0x014c, PE32, subsystem 2, imagebase 0x400000
* timestamp: 1727737552
* entry RVA: 0x00de11e1 -> VA 0x011e11e1

## Sections

| name | VA | vsize | raw size | chars |
|---|---|---|---|---|
| .text | 0x00001000 | 16,559,914 | 16,560,128 | 0x60000020 |
| .rdata | 0x00fcc000 | 1,308,126 | 1,308,160 | 0x40000040 |
| .data | 0x0110c000 | 2,172,772 | 805,888 | 0xc0000040 |
| .tls | 0x0131f000 | 13 | 512 | 0xc0000040 |
| CONST | 0x01320000 | 31 | 512 | 0xc0000040 |
| .rsrc | 0x01321000 | 5,270,208 | 5,270,528 | 0x40000040 |
| .reloc | 0x01828000 | 938,078 | 938,496 | 0x42000040 |

## Data directories

* import: RVA 0x01108d3c size 420
* resource: RVA 0x01321000 size 5,270,208
* security: RVA 0x017e54d0 size 10,280
* basereloc: RVA 0x01828000 size 797,700
* debug: RVA 0x00feb100 size 28
* tls: RVA 0x010f9090 size 24
* iat: RVA 0x00fcc000 size 2,060

## Imports

* 495 functions from 20 DLLs

| DLL | count |
|---|---|
| MSVCR90.dll | 159 |
| KERNEL32.dll | 148 |
| USER32.dll | 89 |
| WSOCK32.dll | 23 |
| ADVAPI32.dll | 12 |
| IMM32.dll | 12 |
| d3dx9_27.dll | 9 |
| dbghelp.dll | 7 |
| GDI32.dll | 6 |
| ole32.dll | 6 |
| VERSION.dll | 5 |
| WINMM.dll | 3 |
| steam_api.dll | 3 |
| SHELL32.dll | 3 |
| WS2_32.dll | 3 |
| USP10.dll | 2 |
| DSOUND.dll | 2 |
| PSAPI.DLL | 1 |
| DINPUT8.dll | 1 |
| d3d9.dll | 1 |

## Code shape (.text)

* .text vsize: 16,559,914 bytes
* movups_store: 165,660
* movups: 128,547
* movss: 128,355
* ret_c3: 99,967
* int3_pad_runs: 83,114
* ret_c2: 74,383
* mulps: 54,607
* movaps: 30,839
* addps: 30,497
* xorps: 15,248
* prologue_55_8b_ec: 12,984
* movaps_store: 4,401
* divps: 3,529
* rdtsc: 673
* movdqa: 165
* cpuid: 40
* fxsave_ldmxcsr: 16
* pxor: 11
* xorpd: 2
* prologue_55_89_e5: 0

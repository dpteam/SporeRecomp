# Instruction census — SporeApp.exe

* .text: 16,559,914 bytes at VA 0x401000 (image base 0x400000)
* instructions: 5,496,576 (457 undecodable bytes)
* instructions assigned to a function: 4,763,173 (86.66%)
* orphan (unreachable but decodable) instructions: 11,229
* functions: 136,851 (4,804 orphan groups)
* basic blocks: 236,957
* call targets: 35,829
* branch targets: 276,933
* branch targets not on an instruction boundary: 900

## Function size histogram (instructions)

| insns | functions |
|---|---|
| 1 | 5,247 |
| 2-4 | 26,994 |
| 5-16 | 50,013 |
| 17-64 | 37,505 |
| 65-256 | 14,471 |
| 257-1k | 2,459 |
| >1k | 162 |

## Largest functions

* 0x00786570: 12,271 insns, 1 blocks
* 0x00441910: 5,316 insns, 233 blocks
* 0x011c04c0: 4,129 insns, 2 blocks
* 0x009f45a0: 4,069 insns, 65 blocks
* 0x0058e815: 3,760 insns, 119 blocks
* 0x00b60ec0: 3,615 insns, 270 blocks
* 0x0118cfd0: 3,357 insns, 1 blocks
* 0x011d4a30: 3,212 insns, 1 blocks
* 0x00ab32a0: 3,063 insns, 102 blocks
* 0x008a95b0: 2,969 insns, 22 blocks
* 0x00770390: 2,924 insns, 15 blocks
* 0x0118a7f0: 2,915 insns, 2 blocks
* 0x004d5080: 2,822 insns, 108 blocks
* 0x011d2360: 2,785 insns, 1 blocks
* 0x00d3d820: 2,597 insns, 6 blocks

## Mnemonic histogram (top 80)

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
| fld1 | 2,679 |
| rol | 2,454 |
| jp | 2,447 |
| nop | 2,388 |
| fcompi | 2,297 |
| fild | 2,295 |
| fldz | 2,181 |
| setne | 2,088 |
| cdq | 2,086 |
| fnstsw | 2,007 |
| sete | 1,903 |
| jnp | 1,845 |
| xchg | 1,796 |
| div | 1,749 |
| lock xadd | 1,648 |
| fabs | 1,525 |
| adc | 1,507 |
| fcomp | 1,465 |
| fsubp | 1,302 |
| subps | 1,253 |

## All mnemonics (338)

`aaa`, `aad`, `aam`, `aas`, `adc`, `add`, `addps`, `addss`, `and`, `andnps`, `andps`, `arpl`, `bnd jmp`, `bound`, `bsr`, `bswap`, `call`, `cbw`, `cdq`, `clc`, `cld`, `cli`, `clts`, `cmc`, `cmova`, `cmovae`, `cmovb`, `cmovbe`, `cmove`, `cmovg`, `cmovge`, `cmovl`, `cmovle`, `cmovne`, `cmp`, `cmpeqps`, `cmpleps`, `cmpltps`, `cmpneqps`, `cmpsb`, `cmpsd`, `comiss`, `cpuid`, `cvtpi2ps`, `cvtps2pi`, `cvtsi2ss`, `cvtss2si`, `cvttps2dq`, `cvttps2pi`, `cvttsd2si`, `cvttss2si`, `cwde`, `daa`, `das`, `dec`, `div`, `divps`, `divss`, `emms`, `enter`, `f2xm1`, `fabs`, `fadd`, `faddp`, `fchs`, `fcmovb`, `fcmovbe`, `fcmove`, `fcmovu`, `fcom`, `fcomi`, `fcomp`, `fcompi`, `fcompp`, `fcos`, `fdecstp`, `fdiv`, `fdivp`, `fdivr`, `fdivrp`, `femms`, `ffreep`, `fiadd`, `ficom`, `ficomp`, `fidiv`, `fidivr`, `fild`, `fimul`, `fist`, `fistp`, `fisttp`, `fisub`, `fisubr`, `fld`, `fld1`, `fldcw`, `fldenv`, `fldl2e`, `fldlg2`, `fldln2`, `fldz`, `fmul`, `fmulp`, `fnsave`, `fnstcw`, `fnstenv`, `fnstsw`, `fpatan`, `fprem`, `fptan`, `frndint`, `frstor`, `fscale`, `fsin`, `fsqrt`, `fst`, `fstp`, `fstpnce`, `fsub`, `fsubp`, `fsubr`, `fsubrp`, `fucomp`, `fucompi`, `fucompp`, `fxch`, `fxsave`, `fyl2x`, `hlt`, `idiv`, `imul`, `in`, `inc`, `insb`, `insd`, `insw`, `int`, `int1`, `int3`, `into`, `invd`, `iretd`, `ja`, `jae`, `jb`, `jbe`, `jcxz`, `je`, `jecxz`, `jg`, `jge`, `jl`, `jle`, `jmp`, `jne`, `jno`, `jnp`, `jns`, `jo`, `jp`, `js`, `lahf`, `lcall`, `ldmxcsr`, `lds`, `lea`, `leave`, `les`, `ljmp`, `lock add`, `lock cmpxchg`, `lock cmpxchg8b`, `lock xadd`, `lock xchg`, `lodsb`, `lodsd`, `loop`, `loope`, `loopne`, `lsl`, `maxps`, `maxss`, `minps`, `minss`, `mov`, `movapd`, `movaps`, `movd`, `movdq2q`, `movdqa`, `movdqu`, `movhlps`, `movhps`, `movlhps`, `movlps`, `movmskps`, `movnti`, `movntps`, `movntq`, `movq`, `movsb`, `movsd`, `movss`, `movsw`, `movsx`, `movups`, `movzx`, `mul`, `mulps`, `mulss`, `neg`, `nop`, `not`, `notrack jmp`, `or`, `orps`, `out`, `outsb`, `outsd`, `packssdw`, `packsswb`, `packuswb`, `paddb`, `paddd`, `paddsw`, `paddusb`, `paddusw`, `paddw`, `pand`, `pause`, `pcmpgtd`, `pextrw`, `pmaddwd`, `pmaxub`, `pminub`, `pmovmskb`, `pmulhw`, `pmullw`, `pop`, `popal`, `popfd`, `por`, `prefetchw`, `pshufd`, `pshufw`, `pslld`, `psllq`, `psllw`, `psrad`, `psraw`, `psrld`, `psrldq`, `psrlq`, `psrlw`, `psubd`, `psubsw`, `psubw`, `punpckhbw`, `punpckhdq`, `punpckhqdq`, `punpckhwd`, `punpcklbw`, `punpckldq`, `punpcklqdq`, `punpcklwd`, `push`, `pushal`, `pushfd`, `pxor`, `rcl`, `rcpps`, `rcr`, `rdtsc`, `rep movsb`, `rep movsd`, `rep stosb`, `rep stosd`, `rep stosw`, `repe cmpsb`, `repe cmpsd`, `repz ret`, `ret`, `retf`, `rol`, `ror`, `rsqrtps`, `rsqrtss`, `sahf`, `sal`, `salc`, `sar`, `sbb`, `scasb`, `scasd`, `seta`, `setae`, `setb`, `setbe`, `sete`, `setg`, `setge`, `setl`, `setle`, `setne`, `seto`, `sets`, `sfence`, `sgdt`, `shl`, `shld`, `shr`, `shrd`, `shufps`, `sqrtps`, `stc`, `std`, `sti`, `stmxcsr`, `stosb`, `stosd`, `stosw`, `sub`, `subps`, `subss`, `sysret`, `test`, `ucomiss`, `ud0`, `unpckhps`, `unpcklps`, `wait`, `wbinvd`, `xchg`, `xlatb`, `xor`, `xorps`, `xrelease xchg`

# AVR ASM Revelator v1.0 — Operator Notes

## Purpose

AVR ASM Revelator brings the PIC/XC8 Revelator idea to AVR-GCC.

It reads:

```text
.lst / .s / .S / .asm      instruction truth
.map                       linker and memory truth
```

It explains AVR-GCC output in terms of:

```text
AVR instructions
AVR ABI conventions
register use
X/Y/Z pointer use
I/O register access
stack frames
interrupt vectors
runtime helper pulls
.text/.data/.bss/.eeprom memory layout
```

## Recommended build commands

```bash
avr-gcc -mmcu=atmega328p -Os -g -Wl,-Map=main.map -o main.elf main.c
avr-objdump -d -S main.elf > main.lst
```

## Recommended Revelator command

```bash
python avr_asm_revelator_v1_0.py main.lst \
  --map main.map \
  --mcu atmega328p \
  --triage \
  --triage-report main_avr_triage.md \
  --report main_avr_report.md \
  --json main_avr_report.json \
  --annotate
```

## What to read first

Read the triage output first. It ranks likely memory/code-size suspects:

```text
runtime helpers
flash usage
SRAM usage
largest functions
long CALL/JMP use
I/O access profile
X/Y/Z pointer use
```

## Important AVR interpretations

### `clr r1`

AVR-GCC treats `r1` as a zero register. `clr r1` is normal ABI maintenance.

Do not remove it.

### `push r28`, `push r29`, `in r28,SPL`, `in r29,SPH`

This usually means a Y-based stack frame.

Interpretation:

```text
The function has local stack storage or debug-friendly frame access.
```

If many functions have stack frames and memory is tight, simplify locals and check optimization settings.

### `in`, `out`, `sbi`, `cbi`, `sbic`, `sbis`

These touch AVR I/O registers.

For ATmega328P the tool can map common operands to names such as:

```text
PORTB
DDRB
PIND
SREG
SPL
SPH
TCCR0A
SPCR
```

Do not remove individual I/O instructions. Remove the whole unused peripheral feature instead.

### `cp`, `cpi`, `tst` followed by `brne`, `breq`, etc.

This is normal AVR-GCC conditional logic.

Fix repeated patterns at the C/source level, not by hand-editing the branch pair.

### `dec` / `sbiw` followed by `brne`

Likely delay or counted loop.

Keep if timing is deliberate. If it is accidental busy-waiting, consider a timer.

### `call` / `jmp`

Absolute transfers may cost more space than relative `rcall` / `rjmp`.

Do not replace manually. Check linker relaxation and function layout.

### Runtime helpers in map

Findings such as:

```text
__udivmodhi4
__divmodhi4
__floatunsisf
printf
memcpy
memset
```

are high-value size suspects.

Best fixes:

```text
avoid printf
avoid float
avoid division/modulus where possible
use smaller integer types
replace generic formatting with tiny output routines
```

### `.data`, `.bss`, `.eeprom`

`.data` uses SRAM at runtime and also has a flash load image.

`.bss` uses SRAM but does not need flash initialization data.

`.eeprom` is separate EEPROM placement.

If SRAM is tight, reduce globals, buffers, and initialized data.

## Practical optimization order

```text
1. Read triage report.
2. Check flash and SRAM usage.
3. Look for runtime helpers.
4. Look for printf/float/division.
5. Check largest functions.
6. Check stack-frame-heavy functions.
7. Check .data/.bss size.
8. Remove unused feature families.
9. Rebuild and compare reports.
```

## Rule of thumb

If Revelator points to one instruction, be careful.

If Revelator points to a repeated pattern or runtime helper, act there first.

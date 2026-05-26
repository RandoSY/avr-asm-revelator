#!/usr/bin/env python3
"""
avr_asm_revelator_v1_0.py

AVR ASM Revelator v1.0

A conservative programmer-facing review tool for AVR-GCC / avr-objdump /
avr-ld output.

Inputs
------
Required:
    AVR assembly, listing, or disassembly text:
        *.s, *.S, *.asm, *.lst
        avr-objdump -d -S firmware.elf > firmware.lst

Optional:
    AVR linker map:
        --map firmware.map
        produced by -Wl,-Map=firmware.map

Outputs
-------
    Markdown report
    Optional JSON report
    Optional annotated listing

Purpose
-------
The listing/disassembly file reveals instruction truth:
    What AVR instructions were emitted?

The linker map reveals memory/layout truth:
    Where did .text, .data, .bss, .eeprom, functions, and helpers land?

The report reveals programmer meaning:
    Which patterns are normal compiler structure?
    Which patterns are likely source-level code-size suspects?
    What should the developer change first?

This tool does not rewrite code.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_MARKDOWN_FINDING_LIMIT = 250


# =============================================================================
# Data model
# =============================================================================

@dataclasses.dataclass
class AsmLine:
    number: int
    raw: str
    cleaned: str
    address: Optional[int]
    address_text: Optional[str]
    opcode_text: Optional[str]
    code: str
    comment: str
    label: Optional[str]
    mnemonic: Optional[str]
    operands: str
    source_context: Optional[str] = None
    section: Optional[str] = None
    symbol_kind: Optional[str] = None

    @property
    def is_executable(self) -> bool:
        return self.mnemonic in AVR_EXEC_MNEMONICS

    @property
    def is_directive(self) -> bool:
        return bool(self.mnemonic) and self.mnemonic in AVR_DIRECTIVES


@dataclasses.dataclass
class Finding:
    severity: str
    category: str
    line: int
    message: str
    why: str
    suggestion: str
    raw: str
    cleaned: str = ""
    address_text: Optional[str] = None
    source_context: Optional[str] = None
    map_note: Optional[str] = None
    context: List[str] = dataclasses.field(default_factory=list)
    related_lines: List[int] = dataclasses.field(default_factory=list)

    # Interpretation layer
    compiler_reason: Optional[str] = None
    programmer_intent: Optional[str] = None
    actionability: str = "Review"
    fix_strategy: Optional[str] = None
    group_key: Optional[str] = None
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class SectionInfo:
    name: str
    address: Optional[int] = None
    size: Optional[int] = None
    load_address: Optional[int] = None
    raw_lines: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class SymbolInfo:
    name: str
    address: Optional[int] = None
    section: Optional[str] = None
    kind: Optional[str] = None
    size: Optional[int] = None
    raw: str = ""


@dataclasses.dataclass
class MapInfo:
    path: Optional[str] = None
    raw_line_count: int = 0
    memory_regions: Dict[str, Dict[str, Any]] = dataclasses.field(default_factory=dict)
    sections: Dict[str, SectionInfo] = dataclasses.field(default_factory=dict)
    symbols: Dict[str, SymbolInfo] = dataclasses.field(default_factory=dict)
    runtime_helpers: Dict[str, SymbolInfo] = dataclasses.field(default_factory=dict)
    interrupt_vectors: Dict[str, SymbolInfo] = dataclasses.field(default_factory=dict)
    raw_memory_lines: List[str] = dataclasses.field(default_factory=list)
    warnings: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class GroupedInsight:
    category: str
    count: int
    severity: str
    title: str
    compiler_reason: str
    programmer_intent: str
    actionability: str
    fix_strategy: str
    representative_lines: List[int] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class TriageItem:
    rank: int
    category: str
    score: int
    title: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# =============================================================================
# AVR knowledge
# =============================================================================

AVR_EXEC_MNEMONICS = {
    # Arithmetic / logic
    "add", "adc", "adiw", "sub", "subi", "sbc", "sbci", "sbiw",
    "and", "andi", "or", "ori", "eor", "com", "neg", "inc", "dec",
    "mul", "muls", "mulsu", "fmul", "fmuls", "fmulsu",
    # Register / memory movement
    "mov", "movw", "ldi", "clr", "ser",
    "ld", "ldd", "lds", "st", "std", "sts",
    "lpm", "elpm", "in", "out", "push", "pop",
    "xch", "lac", "las", "lat",
    # Branches / calls / returns
    "rjmp", "ijmp", "eijmp", "jmp",
    "rcall", "icall", "eicall", "call",
    "ret", "reti",
    "brbs", "brbc", "breq", "brne", "brcs", "brcc", "brsh", "brlo",
    "brmi", "brpl", "brge", "brlt", "brhs", "brhc",
    "brts", "brtc", "brvs", "brvc", "brie", "brid",
    "cpse", "sbrc", "sbrs", "sbic", "sbis",
    # Compare / test
    "cp", "cpc", "cpi", "tst",
    # Bit operations
    "sbi", "cbi", "bst", "bld", "sec", "clc", "sen", "cln", "sez", "clz",
    "sei", "cli", "ses", "cls", "sev", "clv", "set", "clt", "seh", "clh",
    # Shifts / rotates
    "lsl", "lsr", "rol", "ror", "asr", "swap",
    # Control / timing
    "nop", "sleep", "wdr", "break",
}

AVR_DIRECTIVES = {
    ".text", ".data", ".bss", ".rodata", ".eeprom", ".noinit",
    ".section", ".global", ".globl", ".type", ".size",
    ".word", ".byte", ".long", ".ascii", ".asciz",
    ".org", ".equ", ".set", ".macro", ".endm",
    ".file", ".loc", ".cfi_startproc", ".cfi_endproc",
}

AVR_KNOWN_TOKENS = AVR_EXEC_MNEMONICS | AVR_DIRECTIVES

AVR_BRANCHES = {
    "rjmp", "ijmp", "eijmp", "jmp",
    "brbs", "brbc", "breq", "brne", "brcs", "brcc", "brsh", "brlo",
    "brmi", "brpl", "brge", "brlt", "brhs", "brhc",
    "brts", "brtc", "brvs", "brvc", "brie", "brid",
}
AVR_UNCONDITIONAL_BRANCHES = {"rjmp", "jmp", "ijmp", "eijmp"}
AVR_CALLS = {"rcall", "call", "icall", "eicall"}
AVR_RETURNS = {"ret", "reti"}
AVR_SKIPS = {"cpse", "sbrc", "sbrs", "sbic", "sbis"}
AVR_COMPARE_TESTS = {"cp", "cpc", "cpi", "tst", "sbiw", "subi", "sbci", "dec"}
AVR_CONDITIONAL_BRANCHES = AVR_BRANCHES - AVR_UNCONDITIONAL_BRANCHES
AVR_IO_OPS = {"in", "out", "sbi", "cbi", "sbic", "sbis"}
AVR_PROGMEM_OPS = {"lpm", "elpm"}

ROUGH_CYCLES = {
    "nop": "1",
    "ldi": "1",
    "mov": "1",
    "movw": "1",
    "clr": "1",
    "in": "1",
    "out": "1",
    "sbi": "2",
    "cbi": "2",
    "rjmp": "2",
    "jmp": "3",
    "rcall": "3",
    "call": "4",
    "ret": "4",
    "reti": "4",
    "brne": "1/2",
    "breq": "1/2",
    "cpse": "1/2/3",
    "sbrc": "1/2/3",
    "sbrs": "1/2/3",
    "sbic": "1/2/3",
    "sbis": "1/2/3",
    "push": "2",
    "pop": "2",
    "lds": "2",
    "sts": "2",
    "lpm": "3",
    "elpm": "3+",
}

ATMEGA328P_IO = {
    # I/O space addresses, common names. Not exhaustive.
    0x03: "PINB", 0x04: "DDRB", 0x05: "PORTB",
    0x06: "PINC", 0x07: "DDRC", 0x08: "PORTC",
    0x09: "PIND", 0x0A: "DDRD", 0x0B: "PORTD",
    0x1E: "GPIOR0", 0x1F: "EECR", 0x20: "EEDR", 0x21: "EEARL", 0x22: "EEARH",
    0x23: "GTCCR", 0x24: "TCCR0A", 0x25: "TCCR0B", 0x26: "TCNT0",
    0x27: "OCR0A", 0x28: "OCR0B",
    0x2B: "GPIOR1", 0x2C: "GPIOR2",
    0x2D: "SPCR", 0x2E: "SPSR", 0x2F: "SPDR",
    0x30: "ACSR", 0x33: "SMCR", 0x34: "MCUSR", 0x35: "MCUCR",
    0x37: "SPMCSR", 0x3B: "RAMPZ",
    0x3D: "SPL", 0x3E: "SPH", 0x3F: "SREG",
}

ATMEGA328P_DATA_MEM_IO_ALIASES = {addr + 0x20: name for addr, name in ATMEGA328P_IO.items()}

RUNTIME_HELPER_PATTERNS = [
    "__udivmod", "__divmod", "__mul", "__float", "__addsf", "__subsf",
    "__mulsf", "__divsf", "printf", "sprintf", "vfprintf", "puts",
    "malloc", "free", "memcpy", "memset", "strcpy", "strcmp",
]


# =============================================================================
# Helpers
# =============================================================================

def parse_int_maybe(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    s = str(text).strip().rstrip(",")
    if not s:
        return None
    s = s.replace("$", "0x")
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        if re.fullmatch(r"[0-9A-Fa-f]+", s) and re.search(r"[A-Fa-f]", s):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None


def split_comment(line: str) -> Tuple[str, str]:
    # AVR asm often uses ;, objdump often uses # for comments.
    semi = line.find(";")
    hash_ = line.find("#")
    positions = [p for p in [semi, hash_] if p >= 0]
    if not positions:
        return line.rstrip(), ""
    p = min(positions)
    return line[:p].rstrip(), line[p:].rstrip()


def first_operand(ops: str) -> str:
    return ops.split(",", 1)[0].strip() if ops else ""


def operands_list(ops: str) -> List[str]:
    return [x.strip() for x in ops.split(",") if x.strip()]


def target_symbol(ops: str) -> str:
    return first_operand(ops).strip()


def first_token(text: str) -> str:
    return text.strip().split(None, 1)[0].rstrip(":").lower() if text.strip() else ""


def looks_like_avr_asm(text: str) -> bool:
    s = text.strip()
    if not s:
        return False
    t = first_token(s)
    if t in AVR_KNOWN_TOKENS:
        return True
    if re.match(r"^[_.$A-Za-z][\w.$]*:\s*$", s):
        return True
    if re.match(r"^[_.$A-Za-z][\w.$]*:\s+[A-Za-z.]", s):
        return True
    if re.match(r"^[0-9A-Fa-f]{4,8}\s+<[^>]+>:", s):
        return True
    return False


def local_context(lines: List[AsmLine], i: int, span: int = 4) -> List[str]:
    a = max(0, i - span)
    b = min(len(lines), i + span + 1)
    rows = []
    for j in range(a, b):
        ln = lines[j]
        if ln.cleaned.strip():
            addr = f" addr={ln.address_text}" if ln.address_text else ""
            rows.append(f"{ln.number}{addr}: {ln.cleaned}")
    return rows


def classify_symbol_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if re.match(r"^\.L", name):
        return "local_compiler_label"
    if name.startswith("__vector"):
        return "interrupt_vector"
    if name == "__vectors":
        return "interrupt_vector_table"
    if any(p in name for p in RUNTIME_HELPER_PATTERNS):
        return "runtime_helper"
    if name.startswith("__"):
        return "runtime_symbol"
    if name.startswith("."):
        return "local_compiler_label"
    return "code_label"


def resolve_io_register(operand: str, mcu: str = "atmega328p") -> Optional[str]:
    op = operand.strip()
    if not op:
        return None
    # Already symbolic.
    if re.match(r"^[A-Za-z_][\w_]*$", op):
        return op
    num = parse_int_maybe(op)
    if num is None:
        return None
    if mcu.lower() == "atmega328p":
        return ATMEGA328P_IO.get(num) or ATMEGA328P_DATA_MEM_IO_ALIASES.get(num)
    return None


# =============================================================================
# Listing parser
# =============================================================================

def strip_listing_line(raw: str) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
    """
    Supports:
      objdump function label:
        00000080 <main>:
      objdump instruction:
          80:   25 9a           sbi 0x04, 5
      compiler assembly:
        main:
            ldi r24,lo8(32)
    """
    line = raw.rstrip("\n")
    s = line.strip()
    if not s:
        return line, None, None, None

    # objdump function label
    m = re.match(r"^\s*(?P<addr>[0-9A-Fa-f]+)\s+<(?P<label>[^>]+)>:\s*$", line)
    if m:
        addr_text = m.group("addr")
        return f"{m.group('label')}:", addr_text, parse_int_maybe(addr_text), None

    # objdump instruction line:
    m = re.match(
        r"^\s*(?P<addr>[0-9A-Fa-f]+):\s+"
        r"(?P<bytes>(?:[0-9A-Fa-f]{2}\s+)+)\s*"
        r"(?P<body>.*?)\s*$",
        line,
    )
    if m:
        body = m.group("body").strip()
        addr_text = m.group("addr")
        bytes_text = m.group("bytes").strip()
        if body:
            return body, addr_text, parse_int_maybe(addr_text), bytes_text
        return ";" + s, addr_text, parse_int_maybe(addr_text), bytes_text

    # Raw assembly or source. Keep source as comment if it doesn't look asm.
    if looks_like_avr_asm(s):
        return s, None, None, None

    return ";" + s, None, None, None


def parse_asm_line(
    number: int,
    raw: str,
    source_context: Optional[str],
    current_section: Optional[str],
) -> AsmLine:
    cleaned, addr_text, addr_int, opcode_text = strip_listing_line(raw)
    code, comment = split_comment(cleaned)
    stripped = code.strip()

    label = None
    mnemonic = None
    operands = ""

    if stripped:
        m = re.match(r"^([_.$A-Za-z][\w.$]*):\s*(.*)$", stripped)
        rest = stripped
        if m:
            label = m.group(1)
            rest = m.group(2).strip()

        if rest:
            parts = rest.split(None, 1)
            maybe = parts[0].lower()
            if maybe in AVR_KNOWN_TOKENS:
                mnemonic = maybe
                operands = parts[1].strip() if len(parts) > 1 else ""

    symbol_kind = classify_symbol_name(label)

    return AsmLine(
        number=number,
        raw=raw.rstrip("\n"),
        cleaned=cleaned.rstrip("\n"),
        address=addr_int,
        address_text=addr_text,
        opcode_text=opcode_text,
        code=code,
        comment=comment,
        label=label,
        mnemonic=mnemonic,
        operands=operands,
        source_context=source_context,
        section=current_section,
        symbol_kind=symbol_kind,
    )


def parse_listing_file(path: Path) -> List[AsmLine]:
    raw_lines = path.read_text(errors="replace").splitlines()
    lines: List[AsmLine] = []
    source_context: Optional[str] = None
    current_section: Optional[str] = None

    for i, raw in enumerate(raw_lines, 1):
        stripped = raw.strip()

        # Track C source context in mixed -S/-d -S output. Avoid treating asm as source.
        if stripped and not looks_like_avr_asm(stripped) and not re.match(r"^[0-9A-Fa-f]+:", stripped):
            if any(tok in stripped for tok in ["if", "while", "for", "return", "{", "}", "PORT", "DDR", "PIN", "main"]):
                source_context = stripped

        ln = parse_asm_line(i, raw, source_context, current_section)

        if ln.mnemonic in {".text", ".data", ".bss", ".eeprom", ".rodata", ".noinit"}:
            current_section = ln.mnemonic
            ln.section = current_section
        elif ln.mnemonic == ".section":
            current_section = first_operand(ln.operands)
            ln.section = current_section

        lines.append(ln)

    return lines


# =============================================================================
# Map parser
# =============================================================================

def classify_map_symbol(name: str) -> str:
    if name.startswith("__vector") or name == "__vectors":
        return "interrupt_vector"
    if any(p in name for p in RUNTIME_HELPER_PATTERNS):
        return "runtime_helper"
    if name.startswith(".L"):
        return "local_compiler_label"
    if name.startswith("__"):
        return "runtime_symbol"
    return "map_symbol"


def parse_map_file(path: Optional[Path]) -> MapInfo:
    info = MapInfo(path=str(path) if path else None)
    if path is None:
        return info
    if not path.exists():
        info.warnings.append(f"Map file not found: {path}")
        return info

    raw_lines = path.read_text(errors="replace").splitlines()
    info.raw_line_count = len(raw_lines)

    in_memory_config = False
    for line in raw_lines:
        s = line.rstrip()
        if not s:
            continue

        if "Memory Configuration" in s:
            in_memory_config = True
            info.raw_memory_lines.append(s)
            continue
        if in_memory_config and "Linker script and memory map" in s:
            in_memory_config = False

        if in_memory_config:
            info.raw_memory_lines.append(s)
            # Typical:
            # Name             Origin             Length             Attributes
            # text             0x00000000         0x00008000         xr
            m = re.match(r"^\s*(?P<name>\w+)\s+(?P<origin>0x[0-9A-Fa-f]+)\s+(?P<length>0x[0-9A-Fa-f]+)\s*(?P<attrs>\w*)", s)
            if m and m.group("name").lower() not in {"name"}:
                info.memory_regions[m.group("name")] = {
                    "origin": int(m.group("origin"), 16),
                    "length": int(m.group("length"), 16),
                    "attributes": m.group("attrs"),
                    "raw": s,
                }

        # Section line:
        # .text          0x0000000000000000      0x1aa
        m = re.match(r"^\s*(?P<section>\.[A-Za-z0-9_.$]+)\s+(?P<addr>0x[0-9A-Fa-f]+)\s+(?P<size>0x[0-9A-Fa-f]+)", s)
        if m:
            sec = m.group("section")
            if sec not in info.sections:
                info.sections[sec] = SectionInfo(name=sec)
            si = info.sections[sec]
            si.address = int(m.group("addr"), 16)
            si.size = int(m.group("size"), 16)
            si.raw_lines.append(s)
            # Load address sometimes appears later on line.
            lm = re.search(r"load address\s+(0x[0-9A-Fa-f]+)", s)
            if lm:
                si.load_address = int(lm.group(1), 16)
            continue

        # Symbol line inside map:
        #                0x0000000000000080                main
        m = re.match(r"^\s*(?P<addr>0x[0-9A-Fa-f]+)\s+(?P<name>[_.$A-Za-z][\w.$]*)\s*$", s)
        if m:
            name = m.group("name")
            addr = int(m.group("addr"), 16)
            kind = classify_map_symbol(name)
            sym = SymbolInfo(name=name, address=addr, kind=kind, raw=s)
            info.symbols[name] = sym
            if kind == "runtime_helper":
                info.runtime_helpers[name] = sym
            if kind == "interrupt_vector":
                info.interrupt_vectors[name] = sym

    return info


# =============================================================================
# Analysis helpers
# =============================================================================

def label_map(lines: List[AsmLine]) -> Dict[str, int]:
    return {ln.label: i for i, ln in enumerate(lines) if ln.label}


def next_code_index(lines: List[AsmLine], start: int) -> Optional[int]:
    for i in range(start + 1, len(lines)):
        if lines[i].mnemonic or lines[i].label:
            return i
    return None


def previous_code_index(lines: List[AsmLine], start: int) -> Optional[int]:
    for i in range(start - 1, -1, -1):
        if lines[i].mnemonic or lines[i].label:
            return i
    return None


def function_regions(lines: List[AsmLine]) -> List[Dict[str, Any]]:
    labels = [(i, ln) for i, ln in enumerate(lines) if ln.label and ln.symbol_kind not in {"local_compiler_label"}]
    regions = []
    for idx, (i, ln) in enumerate(labels):
        end = labels[idx + 1][0] if idx + 1 < len(labels) else len(lines)
        region = lines[i:end]
        execs = [x for x in region if x.is_executable]
        if not execs:
            continue
        addrs = [x.address for x in execs if x.address is not None]
        calls = sum(1 for x in execs if x.mnemonic in AVR_CALLS)
        branches = sum(1 for x in execs if x.mnemonic in AVR_BRANCHES)
        pushes = sum(1 for x in execs if x.mnemonic == "push")
        pops = sum(1 for x in execs if x.mnemonic == "pop")
        local_labels = sum(1 for x in region if x.label and x.symbol_kind == "local_compiler_label")
        regions.append({
            "name": ln.label,
            "line": ln.number,
            "start_address": min(addrs) if addrs else ln.address,
            "end_address": max(addrs) if addrs else ln.address,
            "instruction_count": len(execs),
            "call_count": calls,
            "branch_count": branches,
            "push_count": pushes,
            "pop_count": pops,
            "local_labels": local_labels,
        })
    return regions


def instruction_mix(lines: List[AsmLine]) -> Counter:
    return Counter(ln.mnemonic for ln in lines if ln.is_executable)


def register_observations(lines: List[AsmLine]) -> Dict[str, Any]:
    regs = Counter()
    pointer_uses = Counter()
    pushes = Counter()
    pops = Counter()
    zero_reg_events = []

    for ln in lines:
        if not ln.is_executable:
            continue
        for r in re.findall(r"\br(?:[0-9]|[12][0-9]|3[01])\b", ln.operands):
            regs[r] += 1
        if re.search(r"\bX\b|\bX\+", ln.operands):
            pointer_uses["X:r27:r26"] += 1
        if re.search(r"\bY\b|\bY\+", ln.operands):
            pointer_uses["Y:r29:r28"] += 1
        if re.search(r"\bZ\b|\bZ\+", ln.operands):
            pointer_uses["Z:r31:r30"] += 1
        if ln.mnemonic == "push":
            pushes[first_operand(ln.operands)] += 1
        if ln.mnemonic == "pop":
            pops[first_operand(ln.operands)] += 1
        if ln.mnemonic in {"clr", "eor"} and "r1" in operands_list(ln.operands):
            zero_reg_events.append(ln.number)

    return {
        "register_counts": regs.most_common(),
        "pointer_uses": dict(pointer_uses),
        "pushes": dict(pushes),
        "pops": dict(pops),
        "zero_register_events": zero_reg_events,
    }


def io_observations(lines: List[AsmLine], mcu: str) -> Counter:
    obs = Counter()
    for ln in lines:
        if ln.mnemonic not in AVR_IO_OPS:
            continue
        ops = operands_list(ln.operands)
        if not ops:
            continue
        io_operand = ops[0] if ln.mnemonic in {"out", "sbi", "cbi", "sbic", "sbis"} else (ops[1] if len(ops) > 1 else "")
        name = resolve_io_register(io_operand, mcu) or io_operand
        obs[f"{ln.mnemonic} {name}"] += 1
    return obs


def map_note_for_line(ln: AsmLine, map_info: MapInfo) -> Optional[str]:
    if ln.address is None:
        return None
    for name, sec in map_info.sections.items():
        if sec.address is not None and sec.size is not None:
            if sec.address <= ln.address < sec.address + sec.size:
                return f"Address {ln.address_text} appears in map section `{name}`."
    return None


# =============================================================================
# Analyzer
# =============================================================================

class Analyzer:
    def __init__(self, lines: List[AsmLine], map_info: Optional[MapInfo] = None, mcu: str = "atmega328p"):
        self.lines = lines
        self.labels = label_map(lines)
        self.map_info = map_info or MapInfo()
        self.mcu = mcu
        self.findings: List[Finding] = []

    def add(self, severity: str, category: str, i: int, message: str, why: str, suggestion: str, related: Optional[List[int]] = None) -> None:
        ln = self.lines[i]
        self.findings.append(Finding(
            severity=severity,
            category=category,
            line=ln.number,
            message=message,
            why=why,
            suggestion=suggestion,
            raw=ln.raw,
            cleaned=ln.cleaned,
            address_text=ln.address_text,
            source_context=ln.source_context,
            map_note=map_note_for_line(ln, self.map_info),
            context=local_context(self.lines, i),
            related_lines=related or [],
        ))

    def analyze(self) -> List[Finding]:
        self.find_avr_skip_patterns()
        self.find_compare_branch_patterns()
        self.find_delay_loops()
        self.find_io_access()
        self.find_stack_frames()
        self.find_zero_register_restores()
        self.find_long_calls_jumps()
        self.find_interrupt_vectors()
        self.find_progmem_access()
        self.find_nops()
        self.find_branch_to_next_label()
        self.find_self_jumps()
        self.find_call_return_wrappers()
        self.find_hot_call_targets()
        self.find_runtime_helpers_from_map()
        self.find_eeprom_sections()
        return sorted(self.findings, key=lambda f: (f.line, f.category))

    def find_avr_skip_patterns(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic not in AVR_SKIPS:
                continue
            ni = next_code_index(self.lines, i)
            next_text = self.lines[ni].cleaned if ni is not None else "(none)"
            self.add(
                "INFO", "AVR_SKIP_PATTERN", i,
                f"{ln.mnemonic.upper()} skips the next instruction conditionally.",
                f"AVR skip instructions discard the following instruction when their condition is met. Next instruction: `{next_text}`.",
                "Read the skip instruction and the following instruction as one conditional unit.",
                related=[self.lines[ni].number] if ni is not None else [],
            )

    def find_compare_branch_patterns(self) -> None:
        for i, ln in enumerate(self.lines[:-1]):
            if ln.mnemonic not in AVR_COMPARE_TESTS:
                continue
            ni = next_code_index(self.lines, i)
            if ni is None:
                continue
            nxt = self.lines[ni]
            if nxt.mnemonic in AVR_CONDITIONAL_BRANCHES:
                self.add(
                    "INFO", "AVR_COMPARE_BRANCH_PATTERN", i,
                    f"{ln.mnemonic.upper()} followed by {nxt.mnemonic.upper()} forms a C conditional pattern.",
                    "AVR-GCC commonly emits compare/test instructions followed by BRxx conditional branches for if/while logic.",
                    "Do not optimize the pair directly; simplify repeated source-level conditions if this pattern appears many times.",
                    related=[nxt.number],
                )

    def find_delay_loops(self) -> None:
        for i, ln in enumerate(self.lines[:-1]):
            ni = next_code_index(self.lines, i)
            if ni is None:
                continue
            nxt = self.lines[ni]
            if ln.mnemonic in {"dec", "sbiw", "subi", "sbci"} and nxt.mnemonic == "brne":
                self.add(
                    "INFO", "AVR_DELAY_LOOP", i,
                    "Counter update followed by BRNE looks like a delay or counted loop.",
                    "DEC/SBIW/SUBI/SBCI plus BRNE is a common AVR counted-loop pattern, often used for delays.",
                    "Keep if deliberate timing. If accidental busy-waiting, consider a timer peripheral or event-driven structure.",
                    related=[nxt.number],
                )

    def find_io_access(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic not in AVR_IO_OPS:
                continue
            ops = operands_list(ln.operands)
            if not ops:
                continue
            io_operand = ops[0] if ln.mnemonic in {"out", "sbi", "cbi", "sbic", "sbis"} else (ops[1] if len(ops) > 1 else "")
            resolved = resolve_io_register(io_operand, self.mcu)
            msg = f"{ln.mnemonic.upper()} touches AVR I/O register operand `{io_operand}`"
            if resolved:
                msg += f" (`{resolved}` for {self.mcu})"
            msg += "."
            self.add(
                "INFO", "AVR_IO_ACCESS", i, msg,
                "AVR I/O instructions access low I/O space directly. This often corresponds to DDRx, PORTx, PINx, SREG, SPL/SPH, timers, UART, SPI, or ADC control.",
                "Treat as hardware intent. Optimize by removing whole unused peripherals/features, not by deleting individual I/O instructions.",
            )

    def find_stack_frames(self) -> None:
        for i in range(len(self.lines) - 4):
            window = self.lines[i:i+8]
            txt = " ".join(x.cleaned for x in window).lower()
            if "push r28" in txt and "push r29" in txt and ("in r28" in txt or "in r29" in txt):
                self.add(
                    "INFO", "AVR_STACK_FRAME", i,
                    "Function prologue appears to set up a Y-based stack frame.",
                    "AVR-GCC uses r29:r28 (Y) as a frame pointer when local stack storage or debug-friendly frames are needed.",
                    "If code size is tight, check optimization level and whether local variables/large stack objects can be simplified.",
                )

    def find_zero_register_restores(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic == "clr" and first_operand(ln.operands) == "r1":
                self.add(
                    "INFO", "AVR_ZERO_REGISTER_RESTORE", i,
                    "CLR r1 restores AVR-GCC's zero register convention.",
                    "The AVR-GCC ABI expects r1 to remain zero. Multiplication and some helper code may require clearing it again.",
                    "Normal ABI scaffolding; do not remove.",
                )
            elif ln.mnemonic == "eor":
                ops = operands_list(ln.operands)
                if len(ops) == 2 and ops[0] == "r1" and ops[1] == "r1":
                    self.add(
                        "INFO", "AVR_ZERO_REGISTER_RESTORE", i,
                        "EOR r1,r1 restores AVR-GCC's zero register convention.",
                        "AVR-GCC treats r1 as a zero register.",
                        "Normal ABI scaffolding; do not remove.",
                    )

    def find_long_calls_jumps(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic in {"call", "jmp"}:
                self.add(
                    "INFO", "AVR_LONG_CALL_OR_JUMP", i,
                    f"{ln.mnemonic.upper()} is an absolute long control-transfer instruction.",
                    "CALL/JMP can be larger than RCALL/RJMP, but may be required by range, linker choices, or target architecture.",
                    "If many appear in tiny code, inspect linker relaxation and optimization settings. Do not replace blindly.",
                )

    def find_interrupt_vectors(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.label in {"__vectors"} or (ln.label and ln.label.startswith("__vector")):
                self.add(
                    "INFO", "AVR_INTERRUPT_VECTOR", i,
                    f"Interrupt vector symbol `{ln.label}` found.",
                    "AVR programs begin with a vector table. Unused vectors often jump to a default handler.",
                    "Normal structure. Reduce only by changing startup/vector strategy with care.",
                )
            if "__bad_interrupt" in ln.cleaned:
                self.add(
                    "INFO", "AVR_BAD_INTERRUPT_VECTOR", i,
                    "Reference to __bad_interrupt/default interrupt handler.",
                    "Unused interrupt vectors may point to a default trap/reset handler.",
                    "Normal unless unexpected interrupts are enabled.",
                )

    def find_progmem_access(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic in AVR_PROGMEM_OPS:
                self.add(
                    "INFO", "AVR_PROGMEM_FLASH_ACCESS", i,
                    f"{ln.mnemonic.upper()} reads from program memory.",
                    "LPM/ELPM are used to read flash/program memory, often for PROGMEM strings/tables.",
                    "Useful when constant tables or strings are deliberately stored in flash instead of SRAM.",
                )

    def find_nops(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic != "nop":
                continue
            pi = previous_code_index(self.lines, i)
            pm = self.lines[pi].mnemonic if pi is not None else None
            if pm in AVR_UNCONDITIONAL_BRANCHES or pm in AVR_RETURNS:
                self.add(
                    "WARN", "NOP_AFTER_BRANCH_OR_RETURN", i,
                    "NOP follows unconditional control transfer.",
                    "This may be dead padding unless used for timing/alignment.",
                    "Review only after larger source-level code-size suspects.",
                )
            else:
                self.add(
                    "INFO", "NOP_GENERAL", i,
                    "NOP found.",
                    "NOP may be timing padding, alignment, or compiler filler.",
                    "Keep if timing-critical; otherwise review only after major size issues.",
                )

    def find_branch_to_next_label(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic not in AVR_UNCONDITIONAL_BRANCHES:
                continue
            tgt = target_symbol(ln.operands)
            ni = next_code_index(self.lines, i)
            if ni is not None and self.lines[ni].label == tgt:
                self.add(
                    "WARN", "BRANCH_TO_NEXT_LABEL", i,
                    f"{ln.mnemonic.upper()} targets the next label `{tgt}`.",
                    "A branch to the next executable location usually wastes space/cycles.",
                    "Review source-level flow or compiler output; do not patch generated code casually.",
                    related=[self.lines[ni].number],
                )

    def find_self_jumps(self) -> None:
        for i, ln in enumerate(self.lines):
            if ln.mnemonic not in AVR_UNCONDITIONAL_BRANCHES:
                continue
            tgt = target_symbol(ln.operands)
            if ln.label and tgt == ln.label:
                self.add(
                    "WARN", "SELF_JUMP", i,
                    "Unconditional branch appears to jump to itself.",
                    "This is often a deliberate halt/trap/idle loop.",
                    "Keep if intentional; otherwise inspect source control flow.",
                )

    def find_call_return_wrappers(self) -> None:
        for i, ln in enumerate(self.lines):
            if not ln.label:
                continue
            first = next_code_index(self.lines, i)
            if first is None or self.lines[first].mnemonic not in AVR_CALLS:
                continue
            second = next_code_index(self.lines, first)
            if second is None or self.lines[second].mnemonic not in AVR_RETURNS:
                continue
            self.add(
                "WARN", "CALL_RETURN_WRAPPER", first,
                f"Function `{ln.label}` appears to call another function and return immediately.",
                "Tiny wrappers can cost call/return overhead and prologue/epilogue space.",
                "Consider source-level inline/static inline or direct call only after measuring.",
                related=[ln.number, self.lines[second].number],
            )

    def find_hot_call_targets(self) -> None:
        calls = Counter()
        line_for = {}
        for i, ln in enumerate(self.lines):
            if ln.mnemonic in AVR_CALLS:
                tgt = target_symbol(ln.operands)
                if tgt:
                    calls[tgt] += 1
                    line_for.setdefault(tgt, i)
        for tgt, count in calls.items():
            if count >= 4:
                self.add(
                    "INFO", "HOT_CALL_TARGET", line_for[tgt],
                    f"Function/helper `{tgt}` is called {count} times.",
                    "Frequently called helpers may be important size or speed targets, especially if tiny.",
                    "Inspect function size and call overhead before deciding to inline or restructure.",
                )

    def find_runtime_helpers_from_map(self) -> None:
        for name, sym in self.map_info.runtime_helpers.items():
            self.findings.append(Finding(
                severity="WARN",
                category="AVR_RUNTIME_HELPER_PULL",
                line=0,
                message=f"Runtime/library helper `{name}` appears in the map.",
                why="C operations such as division, floating point, printf, memcpy, or string handling can pull in substantial helper code.",
                suggestion="Check whether source can avoid this helper: remove printf/float/division, use smaller integer math, or use minimal output routines.",
                raw=sym.raw,
                cleaned=sym.raw,
                actionability="High",
                group_key="AVR_RUNTIME_HELPER_PULL",
            ))

    def find_eeprom_sections(self) -> None:
        if ".eeprom" in self.map_info.sections:
            sec = self.map_info.sections[".eeprom"]
            self.findings.append(Finding(
                severity="INFO",
                category="AVR_EEPROM_SECTION",
                line=0,
                message=f".eeprom section present; size={sec.size}.",
                why="EEPROM content is placed separately from flash/SRAM runtime code.",
                suggestion="Verify EEPROM data is intentional and not confused with flash/SRAM usage.",
                raw="; map: .eeprom",
                cleaned="; map: .eeprom",
            ))


# =============================================================================
# Interpretation and grouping
# =============================================================================

def interpret_finding(f: Finding) -> Finding:
    if f.group_key is None:
        f.group_key = f.category

    if f.category == "AVR_SKIP_PATTERN":
        f.compiler_reason = "AVR-GCC or assembler output uses skip instructions for compact bit/test control flow."
        f.programmer_intent = "Implement a conditional without a full branch sequence."
        f.actionability = "Low"
        f.fix_strategy = "Read with the next instruction; reduce repeated source-level tests rather than editing skips."

    elif f.category == "AVR_COMPARE_BRANCH_PATTERN":
        f.compiler_reason = "AVR-GCC commonly emits compare/test followed by BRxx for C if/while conditions."
        f.programmer_intent = "Implement a source-level conditional or loop."
        f.actionability = "Low"
        f.fix_strategy = "Only act if many repeated compare chains indicate source-level dispatch bloat."
        f.group_key = "AVR_COMPARE_BRANCH_CHAINS"

    elif f.category == "AVR_DELAY_LOOP":
        f.compiler_reason = "A counted loop was emitted using DEC/SBIW/SUBI/SBCI plus BRNE."
        f.programmer_intent = "Delay, polling wait, or count down a loop."
        f.actionability = "Medium"
        f.fix_strategy = "If this is a deliberate delay, keep it. If code size or responsiveness matters, consider a timer/peripheral."

    elif f.category == "AVR_IO_ACCESS":
        f.compiler_reason = "Compiler emitted direct I/O access for hardware register operations."
        f.programmer_intent = "Configure or drive AVR hardware."
        f.actionability = "Ignore"
        f.fix_strategy = "Remove whole unused peripherals/features, not individual I/O instructions."
        f.suppressed = True
        f.suppression_reason = "Expected hardware register access."

    elif f.category == "AVR_STACK_FRAME":
        f.compiler_reason = "AVR-GCC emitted a frame-pointer prologue using Y."
        f.programmer_intent = "Support locals, stack objects, or debug-friendly access."
        f.actionability = "Medium"
        f.fix_strategy = "Check optimization level and simplify local variables if many stack frames are large."
        f.group_key = "AVR_STACK_FRAME_OVERHEAD"

    elif f.category == "AVR_ZERO_REGISTER_RESTORE":
        f.compiler_reason = "AVR-GCC ABI requires r1 to remain zero."
        f.programmer_intent = "Restore ABI invariant after helper/multiply code."
        f.actionability = "Ignore"
        f.fix_strategy = "Do not remove."
        f.suppressed = True
        f.suppression_reason = "Normal ABI scaffolding."

    elif f.category == "AVR_LONG_CALL_OR_JUMP":
        f.compiler_reason = "Compiler/linker emitted absolute CALL/JMP rather than relative RCALL/RJMP."
        f.programmer_intent = "Reach a target reliably within architecture/linker constraints."
        f.actionability = "Review"
        f.fix_strategy = "Check linker relaxation and function placement; do not replace blindly."
        f.group_key = "AVR_LONG_CONTROL_TRANSFERS"

    elif f.category == "AVR_RUNTIME_HELPER_PULL":
        f.compiler_reason = "Linker pulled a runtime/library helper due to source-level operations."
        f.programmer_intent = "Perform division, formatting, floating point, memory/string handling, or helper math."
        f.actionability = "High"
        f.fix_strategy = "Avoid expensive C constructs: printf, float, division/modulus, large string/memory functions."

    elif f.category == "AVR_PROGMEM_FLASH_ACCESS":
        f.compiler_reason = "LPM/ELPM was emitted to read flash/program memory."
        f.programmer_intent = "Read PROGMEM/flash constants or strings."
        f.actionability = "Review"
        f.fix_strategy = "Usually good for SRAM savings; check flash footprint if tables/strings are large."

    elif f.category == "HOT_CALL_TARGET":
        f.compiler_reason = "A helper/function is called repeatedly."
        f.programmer_intent = "Reuse functionality."
        f.actionability = "Medium"
        f.fix_strategy = "If tiny and very hot, consider static inline; if large, keep as function."

    return f


def filter_findings(findings: List[Finding], profile: str, show_structural: bool) -> List[Finding]:
    interpreted = [interpret_finding(f) for f in findings]
    if profile == "raw" or show_structural:
        return interpreted
    return [f for f in interpreted if not f.suppressed]


def build_grouped_insights(findings: List[Finding]) -> List[GroupedInsight]:
    groups: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.group_key or f.category].append(f)

    insights = []
    for key, items in groups.items():
        if len(items) < 3 and key not in {"AVR_RUNTIME_HELPER_PULL"}:
            continue
        first = items[0]
        insights.append(GroupedInsight(
            category=key,
            count=len(items),
            severity=first.severity,
            title=f"{key}: {len(items)} occurrence(s)",
            compiler_reason=first.compiler_reason or first.why,
            programmer_intent=first.programmer_intent or "See representative lines.",
            actionability=first.actionability,
            fix_strategy=first.fix_strategy or first.suggestion,
            representative_lines=[f.line for f in items[:12] if f.line],
        ))

    rank = {"Critical": 0, "High": 1, "Medium": 2, "Review": 3, "Low": 4, "Ignore": 5}
    insights.sort(key=lambda gi: (rank.get(gi.actionability, 3), -gi.count, gi.category))
    return insights


# =============================================================================
# Triage
# =============================================================================

def estimate_memory_usage(map_info: MapInfo) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "flash_used": None,
        "flash_total": None,
        "flash_percent": None,
        "sram_static": None,
        "sram_total": None,
        "sram_percent": None,
        "eeprom_used": None,
    }

    # Memory regions
    flash_total = None
    sram_total = None
    for name, region in map_info.memory_regions.items():
        lname = name.lower()
        if lname in {"text", "flash", "rom"} or "text" in lname:
            flash_total = region.get("length")
        if lname in {"data", "ram", "sram"} or "data" in lname:
            sram_total = region.get("length")

    text_size = map_info.sections.get(".text").size if ".text" in map_info.sections else None
    data_size = map_info.sections.get(".data").size if ".data" in map_info.sections else 0
    bss_size = map_info.sections.get(".bss").size if ".bss" in map_info.sections else 0
    eeprom_size = map_info.sections.get(".eeprom").size if ".eeprom" in map_info.sections else None

    if text_size is not None:
        out["flash_used"] = text_size + (data_size or 0)  # initialized data has flash load image
    if flash_total and out["flash_used"] is not None:
        out["flash_total"] = flash_total
        out["flash_percent"] = 100.0 * out["flash_used"] / flash_total

    static_ram = (data_size or 0) + (bss_size or 0)
    if static_ram:
        out["sram_static"] = static_ram
    if sram_total and static_ram:
        out["sram_total"] = sram_total
        out["sram_percent"] = 100.0 * static_ram / sram_total

    if eeprom_size is not None:
        out["eeprom_used"] = eeprom_size

    return out


def build_triage(lines: List[AsmLine], map_info: MapInfo, mcu: str) -> Tuple[List[TriageItem], Dict[str, Any]]:
    items: List[TriageItem] = []
    details: Dict[str, Any] = {}

    def add(category: str, score: int, title: str, evidence: str, recommendation: str) -> None:
        items.append(TriageItem(0, category, score, title, evidence, recommendation))

    memory = estimate_memory_usage(map_info)
    details["memory"] = memory
    if memory.get("flash_percent") is not None:
        pct = memory["flash_percent"]
        add(
            "FLASH_USAGE",
            int(pct * 10),
            f"Flash usage estimated at {pct:.1f}%.",
            f"flash_used={memory.get('flash_used')} bytes, flash_total={memory.get('flash_total')} bytes.",
            "If tight, inspect runtime helpers, strings/PROGMEM, large functions, and repeated dispatch code.",
        )
    if memory.get("sram_percent") is not None:
        pct = memory["sram_percent"]
        add(
            "SRAM_STATIC_USAGE",
            int(pct * 10),
            f"Static SRAM usage estimated at {pct:.1f}%.",
            f"static_ram={memory.get('sram_static')} bytes, sram_total={memory.get('sram_total')} bytes.",
            "Reduce globals, buffers, .data/.bss, or move constants to PROGMEM.",
        )

    helpers = list(map_info.runtime_helpers)
    details["runtime_helpers"] = helpers
    if helpers:
        add(
            "RUNTIME_HELPERS",
            900 + 20 * len(helpers),
            f"{len(helpers)} runtime/library helper(s) detected.",
            ", ".join(helpers[:12]),
            "Avoid expensive source constructs such as printf, float, division/modulus, malloc, or large memory/string functions.",
        )

    mix = instruction_mix(lines)
    details["instruction_mix"] = dict(mix)
    call_count = sum(mix.get(m, 0) for m in AVR_CALLS)
    long_transfers = mix.get("call", 0) + mix.get("jmp", 0)
    if long_transfers:
        add(
            "LONG_CONTROL_TRANSFERS",
            20 * long_transfers,
            f"{long_transfers} CALL/JMP instruction(s) detected.",
            "Absolute call/jump can cost more flash than relative forms.",
            "Check linker relaxation and whether large function layout or target architecture requires them.",
        )

    io_counts = io_observations(lines, mcu)
    details["io_observations"] = dict(io_counts)
    if io_counts:
        add(
            "IO_ACCESS_PROFILE",
            min(300, 5 * sum(io_counts.values())),
            f"{sum(io_counts.values())} AVR I/O access instruction(s) detected.",
            ", ".join(f"{k}:{v}" for k, v in io_counts.most_common(8)),
            "This explains hardware behavior. Remove whole unused peripheral features rather than individual I/O lines.",
        )

    regs = register_observations(lines)
    details["register_observations"] = regs
    if regs["pointer_uses"]:
        add(
            "POINTER_REGISTER_USE",
            100,
            "X/Y/Z pointer-register use detected.",
            str(regs["pointer_uses"]),
            "Normal for array/string/table access. If excessive, inspect large tables, buffers, or PROGMEM reads.",
        )

    funcs = function_regions(lines)
    details["function_regions_top"] = sorted(funcs, key=lambda r: r["instruction_count"], reverse=True)[:20]
    if funcs:
        largest = max(funcs, key=lambda r: r["instruction_count"])
        add(
            "LARGEST_FUNCTION",
            largest["instruction_count"],
            f"Largest function/region appears to be `{largest['name']}`.",
            f"{largest['instruction_count']} executable instruction lines; calls={largest['call_count']}; branches={largest['branch_count']}.",
            "Inspect this region first if code size is tight.",
        )

    items.sort(key=lambda x: x.score, reverse=True)
    for i, item in enumerate(items, 1):
        item.rank = i
    return items, details


def render_triage_console(lines: List[AsmLine], map_info: MapInfo, mcu: str, limit: int = 12) -> str:
    items, details = build_triage(lines, map_info, mcu)
    out = ["AVR Revelator triage: ranked suspects", "=" * 60]
    mem = details.get("memory", {})
    if mem.get("flash_percent") is not None:
        out.append(f"Flash: {mem['flash_used']} / {mem['flash_total']} bytes ({mem['flash_percent']:.1f}%).")
    if mem.get("sram_percent") is not None:
        out.append(f"SRAM static: {mem['sram_static']} / {mem['sram_total']} bytes ({mem['sram_percent']:.1f}%).")
    if details.get("runtime_helpers"):
        out.append(f"Runtime helpers: {', '.join(details['runtime_helpers'][:12])}")
    out.append("")
    for item in items[:limit]:
        out.append(f"{item.rank}. [{item.category}] score={item.score}")
        out.append(f"   {item.title}")
        out.append(f"   Evidence: {item.evidence}")
        out.append(f"   Do: {item.recommendation}")
        out.append("")
    return "\n".join(out)


def render_triage_markdown(lines: List[AsmLine], map_info: MapInfo, mcu: str) -> str:
    items, details = build_triage(lines, map_info, mcu)
    out = ["# AVR ASM Revelator Triage Report", ""]
    out += ["## Ranked suspects", "", "| Rank | Category | Score | Suspect | Evidence | Recommendation |", "|---:|---|---:|---|---|---|"]
    for item in items:
        out.append(f"| {item.rank} | `{item.category}` | {item.score} | {item.title} | {item.evidence} | {item.recommendation} |")
    out += ["", "## Details", "", "```json", json.dumps(details, indent=2, default=str), "```", ""]
    return "\n".join(out)


# =============================================================================
# Reporting
# =============================================================================

def render_map_summary(map_info: MapInfo) -> List[str]:
    out = ["## Linker Map Summary", ""]
    if not map_info.path:
        out += ["No map file supplied. Use `--map firmware.map` for memory/section analysis.", ""]
        return out
    out += [f"**Map file:** `{map_info.path}`", f"**Map lines:** {map_info.raw_line_count}", ""]
    if map_info.memory_regions:
        out += ["### Memory Regions", "", "| Region | Origin | Length | Attributes |", "|---|---:|---:|---|"]
        for name, r in map_info.memory_regions.items():
            out.append(f"| `{name}` | `0x{r['origin']:X}` | `{r['length']}` | `{r.get('attributes','')}` |")
        out.append("")
    if map_info.sections:
        out += ["### Sections", "", "| Section | Address | Size | Load address |", "|---|---:|---:|---:|"]
        for name, sec in sorted(map_info.sections.items()):
            addr = f"0x{sec.address:X}" if sec.address is not None else "-"
            size = str(sec.size) if sec.size is not None else "-"
            load = f"0x{sec.load_address:X}" if sec.load_address is not None else "-"
            out.append(f"| `{name}` | {addr} | {size} | {load} |")
        out.append("")
    if map_info.runtime_helpers:
        out += ["### Runtime / Library Helpers", ""]
        for name in sorted(map_info.runtime_helpers):
            out.append(f"- `{name}`")
        out.append("")
    if map_info.interrupt_vectors:
        out += ["### Interrupt Vector Symbols", ""]
        for name in sorted(map_info.interrupt_vectors):
            out.append(f"- `{name}`")
        out.append("")
    return out


def render_markdown_report(path: Path, lines: List[AsmLine], findings: List[Finding], map_info: MapInfo, mcu: str) -> str:
    execs = [ln for ln in lines if ln.is_executable]
    directives = [ln for ln in lines if ln.is_directive]
    labels = [ln for ln in lines if ln.label]
    grouped = build_grouped_insights(findings)
    mix = instruction_mix(lines)
    regions = function_regions(lines)
    regs = register_observations(lines)
    io_counts = io_observations(lines, mcu)
    sev = Counter(f.severity for f in findings)
    cats = Counter(f.category for f in findings)

    addrs = [ln.address for ln in execs if ln.address is not None]
    out = ["# AVR ASM Revelator v1.0 Report", ""]
    out += [
        f"**Input listing:** `{path}`",
        f"**MCU profile:** `{mcu}`",
        f"**Physical lines:** {len(lines)}",
        f"**Executable instruction lines:** {len(execs)}",
        f"**Directive lines:** {len(directives)}",
        f"**Labels:** {len(labels)}",
        f"**Findings shown:** {len(findings)}",
        "",
    ]
    if addrs:
        out += [
            "## Executable Address Orientation",
            "",
            f"- Lowest address: `0x{min(addrs):X}`",
            f"- Highest address: `0x{max(addrs):X}`",
            f"- Approx listing span: `{max(addrs) - min(addrs) + 1}` bytes",
            "",
        ]

    out += ["## First Recognized Executable Lines", "", "```asm"]
    for ln in execs[:50]:
        cyc = ROUGH_CYCLES.get(ln.mnemonic, "?")
        out.append(f"{ln.number:>5} addr={ln.address_text or '-':>8} cyc={cyc:<4} :: {ln.cleaned}")
    if len(execs) > 50:
        out.append(f"... {len(execs)-50} more executable lines omitted ...")
    out += ["```", ""]

    out += ["## Developer-Facing Grouped Insights", ""]
    if grouped:
        out += ["| Category | Count | Actionability | Interpretation | Fix strategy | Representative lines |", "|---|---:|---|---|---|---|"]
        for gi in grouped:
            out.append(f"| `{gi.category}` | {gi.count} | **{gi.actionability}** | {gi.title} | {gi.fix_strategy} | {', '.join(map(str, gi.representative_lines))} |")
    else:
        out.append("No grouped insights were produced.")
    out.append("")

    out += ["## Register / ABI Observations", ""]
    out += [
        "- AVR-GCC convention: `r1` is the zero register and should remain zero.",
        "- `r0` is commonly scratch.",
        "- `X = r27:r26`, `Y = r29:r28`, `Z = r31:r30`.",
        "- `Y` often appears in stack-frame code.",
        "",
        "### Pointer use",
        "",
    ]
    if regs["pointer_uses"]:
        for k, v in regs["pointer_uses"].items():
            out.append(f"- `{k}`: {v}")
    else:
        out.append("- No X/Y/Z pointer use detected.")
    out.append("")

    out += ["### I/O Register Observations", ""]
    if io_counts:
        for k, v in io_counts.most_common(25):
            out.append(f"- `{k}`: {v}")
    else:
        out.append("- No low-I/O access instructions detected.")
    out.append("")

    out += ["## Function / Region Summary", ""]
    if regions:
        out += ["| Function/region | Line | Start | End | Instructions | Calls | Branches | Pushes | Pops | Local labels |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for r in sorted(regions, key=lambda x: x["instruction_count"], reverse=True)[:80]:
            start = f"0x{r['start_address']:X}" if r["start_address"] is not None else "-"
            end = f"0x{r['end_address']:X}" if r["end_address"] is not None else "-"
            out.append(f"| `{r['name']}` | {r['line']} | {start} | {end} | {r['instruction_count']} | {r['call_count']} | {r['branch_count']} | {r['push_count']} | {r['pop_count']} | {r['local_labels']} |")
    else:
        out.append("No function regions recognized.")
    out.append("")

    out += ["## Severity Summary", ""]
    for s in ["STRONG", "WARN", "INFO"]:
        out.append(f"- **{s}:** {sev.get(s, 0)}")
    out += ["", "## Category Summary", ""]
    if cats:
        for cat, n in cats.most_common():
            out.append(f"- **{cat}:** {n}")
    else:
        out.append("- No findings.")
    out.append("")

    out += ["## Instruction Mix", "", "| Mnemonic | Count | Rough cycle note |", "|---|---:|---|"]
    for k, v in mix.most_common():
        out.append(f"| `{k}` | {v} | `{ROUGH_CYCLES.get(k, '?')}` |")
    out.append("")

    out.extend(render_map_summary(map_info))

    out += ["## Programmer Findings", ""]
    if not findings:
        out.append("No findings at selected severity/profile.")
    elif len(findings) > DEFAULT_MARKDOWN_FINDING_LIMIT:
        out += [
            f"Showing first {DEFAULT_MARKDOWN_FINDING_LIMIT} findings out of {len(findings)}.",
            "The JSON report contains the complete finding set.",
            "",
        ]

    for f in findings[:DEFAULT_MARKDOWN_FINDING_LIMIT]:
        addr = f" addr={f.address_text}" if f.address_text else ""
        out += [f"### Line {f.line}{addr}: {f.category} [{f.severity}]", "", "```asm", f.cleaned or f.raw, "```"]
        if f.source_context:
            out += [f"**Source context:** `{f.source_context}`", ""]
        out += [f"**Meaning:** {f.message}", "", f"**Why it matters:** {f.why}", ""]
        if f.compiler_reason:
            out += [f"**Compiler/AVR reason:** {f.compiler_reason}", ""]
        if f.programmer_intent:
            out += [f"**Likely programmer intent:** {f.programmer_intent}", ""]
        out += [f"**Actionability:** `{f.actionability}`", ""]
        if f.fix_strategy:
            out += [f"**Fix strategy:** {f.fix_strategy}", ""]
        if f.map_note:
            out += [f"**Map cross-reference:** {f.map_note}", ""]
        out += [f"**Suggested action:** {f.suggestion}", ""]
        if f.context:
            out += ["Local context:", "```asm"]
            out.extend(f.context)
            out += ["```", ""]

    out += ["## Operator Notes", ""]
    out += [
        "- The listing reveals instruction truth.",
        "- The map reveals linker/memory truth.",
        "- AVR ABI scaffolding such as `clr r1`, stack frames, and interrupt vectors is usually normal.",
        "- Runtime helpers and formatting/math libraries are often better size targets than individual instructions.",
        "- Optimize source first; do not hand-edit generated assembly unless you are deliberately writing assembly.",
        "",
    ]
    return "\n".join(out)


def write_json_report(path: Path, lines: List[AsmLine], findings: List[Finding], map_info: MapInfo, mcu: str) -> None:
    payload = {
        "summary": {
            "physical_lines": len(lines),
            "executable_instruction_lines": sum(1 for ln in lines if ln.is_executable),
            "directive_lines": sum(1 for ln in lines if ln.is_directive),
            "labels": sum(1 for ln in lines if ln.label),
            "findings": len(findings),
            "instruction_mix": dict(instruction_mix(lines)),
        },
        "register_observations": register_observations(lines),
        "io_observations": dict(io_observations(lines, mcu)),
        "map_summary": {
            "path": map_info.path,
            "raw_line_count": map_info.raw_line_count,
            "memory_regions": map_info.memory_regions,
            "sections": {k: dataclasses.asdict(v) for k, v in map_info.sections.items()},
            "runtime_helpers": {k: dataclasses.asdict(v) for k, v in map_info.runtime_helpers.items()},
            "interrupt_vectors": {k: dataclasses.asdict(v) for k, v in map_info.interrupt_vectors.items()},
            "warnings": map_info.warnings,
        },
        "function_regions": function_regions(lines),
        "grouped_insights": [gi.to_dict() for gi in build_grouped_insights(findings)],
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_annotated_listing(lines: List[AsmLine], findings: List[Finding], path: Path) -> None:
    by_line = defaultdict(list)
    for f in findings:
        by_line[f.line].append(f)
    out = []
    for ln in lines:
        for f in by_line.get(ln.number, []):
            out.append("; -----------------------------------------------------------------------------")
            out.append(f"; AVR REVELATOR {f.severity} {f.category}: {f.message}")
            out.append(f"; WHY: {f.why}")
            if f.fix_strategy:
                out.append(f"; FIX: {f.fix_strategy}")
            out.append(f"; DO: {f.suggestion}")
            out.append("; -----------------------------------------------------------------------------")
        out.append(ln.raw)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


# =============================================================================
# CLI
# =============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="AVR ASM Revelator: AVR-GCC/avr-objdump listing and map diagnostic tool."
    )
    parser.add_argument("input", type=Path, help="Input AVR .lst/.s/.S/.asm/disassembly text")
    parser.add_argument("--map", type=Path, default=None, help="Optional avr-ld linker map")
    parser.add_argument("--mcu", default="atmega328p", help="MCU profile for I/O naming; default atmega328p")
    parser.add_argument("--report", type=Path, default=None, help="Markdown report output")
    parser.add_argument("--json", type=Path, default=None, help="JSON report output")
    parser.add_argument("--annotate", action="store_true", help="Write annotated listing")
    parser.add_argument("--annotated-output", type=Path, default=None, help="Annotated listing output path")
    parser.add_argument("--triage", action="store_true", help="Print ranked triage suspects")
    parser.add_argument("--triage-report", type=Path, default=None, help="Write focused triage Markdown report")
    parser.add_argument("--triage-limit", type=int, default=12)
    parser.add_argument("--profile", choices=["raw", "default"], default="default")
    parser.add_argument("--show-structural", action="store_true")
    parser.add_argument("--raw-findings", action="store_true")
    parser.add_argument("--min-severity", choices=["INFO", "WARN", "STRONG"], default="INFO")
    args = parser.parse_args(argv)

    if not args.input.exists():
        raise SystemExit(f"Input file not found: {args.input}")

    rank = {"INFO": 0, "WARN": 1, "STRONG": 2}

    lines = parse_listing_file(args.input)
    map_info = parse_map_file(args.map)
    raw_findings = Analyzer(lines, map_info, mcu=args.mcu).analyze()
    raw_findings = [interpret_finding(f) for f in raw_findings]

    findings = raw_findings if args.raw_findings else filter_findings(raw_findings, args.profile, args.show_structural)
    findings = [f for f in findings if rank[f.severity] >= rank[args.min_severity]]
    grouped = build_grouped_insights(findings)

    execs = [ln for ln in lines if ln.is_executable]
    directives = [ln for ln in lines if ln.is_directive]
    labels = [ln for ln in lines if ln.label]
    sev = Counter(f.severity for f in findings)

    print(f"Input physical lines: {len(lines)}")
    print(f"Executable instruction lines: {len(execs)}")
    print(f"Directive lines: {len(directives)}")
    print(f"Labels: {len(labels)}")
    if args.map:
        print(f"Map lines: {map_info.raw_line_count}")
        print(f"Map sections: {len(map_info.sections)}")
        print(f"Runtime helpers: {len(map_info.runtime_helpers)}")
    else:
        print("Map file: not supplied")
    print(f"Findings shown: {len(findings)}")
    print(f"Raw findings: {len(raw_findings)}")
    print(f"Grouped insights: {len(grouped)}")
    for s in ["STRONG", "WARN", "INFO"]:
        print(f"  {s}: {sev.get(s, 0)}")
    if grouped:
        print("Top grouped insights:")
        for gi in grouped[:6]:
            print(f"  {gi.category}: {gi.count}, actionability={gi.actionability}")

    print("First recognized executable lines:")
    for ln in execs[:20]:
        print(f"  {ln.number} addr={ln.address_text or '-'} :: {ln.cleaned}")

    if args.triage:
        print()
        print(render_triage_console(lines, map_info, args.mcu, limit=args.triage_limit))

    if args.triage_report:
        args.triage_report.write_text(render_triage_markdown(lines, map_info, args.mcu), encoding="utf-8")
        print(f"Triage report written: {args.triage_report}")

    report = args.report or args.input.with_suffix(args.input.suffix + ".avr_revelator.md")
    report.write_text(render_markdown_report(args.input, lines, findings, map_info, args.mcu), encoding="utf-8")
    print(f"Markdown report written: {report}")

    if args.json:
        write_json_report(args.json, lines, findings, map_info, args.mcu)
        print(f"JSON report written: {args.json}")

    if args.annotate or args.annotated_output:
        annotated = args.annotated_output or args.input.with_suffix(args.input.suffix + ".avr_revelator.annotated.lst")
        write_annotated_listing(lines, findings, annotated)
        print(f"Annotated listing written: {annotated}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

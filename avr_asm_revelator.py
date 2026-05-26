#!/usr/bin/env python3
"""
avr_asm_revelator_v4_0.py

Smarter conservative AVR assembly/listing review tool, v4.0.

Reads Atmel/Microchip AVR avr-gcc assembly source (.s, .asm) or avr-objdump listings (.lst, .lss, .txt)
and produces a programmer-focused Markdown report, JSON report, and optionally an annotated listing.
Explains what the emitted assembly appears to do and where a human should inspect possible
inefficiency or runtime hazard.

Python 3.9+, no third-party dependencies.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

KNOWN_MNEMONICS = {
    # Data Transfer
    "mov", "movw", "ldi", "lds", "ld", "ldd", "st", "sts", "std", "lpm", "elpm", "spm", "in", "out", "push", "pop",
    # Arithmetic & Logic
    "add", "adc", "sub", "subi", "sbc", "sbci", "and", "andi", "or", "ori", "eor", "com", "neg", "sbr", "cbr", "inc", "dec", "tst", "clr", "ser",
    # Branch
    "jmp", "rjmp", "ijmp", "eijmp", "call", "rcall", "icall", "eicall", "ret", "reti",
    # Conditional Branches
    "cpse", "cp", "cpc", "cpi", "sbrc", "sbrs", "sbic", "sbis",
    "breq", "brne", "brcs", "brcc", "brsh", "brlo", "brmi", "brpl", "brge", "brlt", "brhs", "brhc", "brts", "brtc", "brvs", "brvc", "brie", "brid",
    # Bit and Bit-Test
    "lsl", "lsr", "rol", "ror", "asr", "swap", "bset", "bclr", "sbi", "cbi", "bst", "bld",
    "sec", "clc", "sen", "cln", "sez", "clz", "sei", "cli", "ses", "cls", "sev", "clv", "set", "clt", "seh", "clh",
    # MCU Control
    "nop", "sleep", "wdr", "break",
    # Directives
    "section", "global", "extern", "byte", "word", "long", "set", "equ", "macro", "endm", "align", "org", "file", "line", "type", "size", "data", "text", "bss", "ascii", "asciz"
}

BRANCHES = {
    "jmp", "rjmp", "ijmp", "eijmp", "breq", "brne", "brcs", "brcc", "brsh", "brlo", 
    "brmi", "brpl", "brge", "brlt", "brhs", "brhc", "brts", "brtc", "brvs", "brvc", "brie", "brid"
}
CALLS = {"call", "rcall", "icall", "eicall"}
RETURNS = {"return", "retlw", "retfie"}
SKIPS = {"cpse", "sbrc", "sbrs", "sbic", "sbis"}
BARRIERS = BRANCHES | CALLS | RETURNS | {"section", "org", "endm", "global", "type", "size"}
DIRECTIVES = {
    "section", "global", "extern", "byte", "word", "long", "set", "equ", "macro", 
    "endm", "align", "org", "file", "line", "type", "size", "data", "text", "bss", "ascii", "asciz"
}

# LDI can only operate on high registers (r16 to r31)
LDI_REG_PATTERN = re.compile(r"^[rR](1[6-9]|2[0-9]|3[01])$")

COMMON_AVR_SFRS = {
    0x3F: "SREG (Status Register)",
    0x3E: "SPH (Stack Pointer High)",
    0x3D: "SPL (Stack Pointer Low)",
    0x3C: "OCDR (On-Chip Debug Register)",
    0x3B: "GIMSK (General Interrupt Mask Register)",
    0x3A: "GIFR (General Interrupt Flag Register)",
    0x39: "TIMSK (Timer/Counter Interrupt Mask)",
    0x38: "TIFR (Timer/Counter Interrupt Flag)",
    0x37: "SPMCR (Store Program Memory Control)",
    0x35: "MCUCR (MCU Control Register)",
    0x34: "MCUSR (MCU Status Register)",
    0x33: "TCCR0B (Timer/Counter 0 Control Register B)",
    0x32: "TCNT0 (Timer/Counter 0 Value)",
    0x31: "OSCCAL (Oscillator Calibration)",
    0x30: "TCCR0A (Timer/Counter 0 Control Register A)",
    0x2F: "SFIOR (Special Function IO Register)",
    0x2E: "WDTCR (Watchdog Timer Control)",
    0x2D: "EEARH (EEPROM Address Register High)",
    0x2C: "EEARL (EEPROM Address Register Low)",
    0x2B: "EEDR (EEPROM Data Register)",
    0x2A: "EECR (EEPROM Control Register)",
    0x28: "PORTB (Port B Data Register)",
    0x27: "DDRB (Port B Data Direction Register)",
    0x26: "PINB (Port B Input Pins)",
    0x25: "PORTC (Port C Data Register)",
    0x24: "DDRC (Port C Data Direction Register)",
    0x23: "PINC (Port C Input Pins)",
    0x22: "PORTD (Port D Data Register)",
    0x21: "DDRD (Port D Data Direction Register)",
    0x20: "PIND (Port D Input Pins)",
    0x18: "ADCL (ADC Data Register Low)",
    0x19: "ADCH (ADC Data Register High)",
    0x1A: "ADCSRA (ADC Control and Status Register A)",
    0x1B: "ADMUX (ADC Multiplexer Selection)",
    0x1C: "ACSR (Analog Comparator Control and Status)",
    0x16: "UBRRL (USART Bureau Rate Register Low)",
    0x17: "UCSRB (USART Control and Status Register B)",
    0x15: "UDR (USART I/O Data Register)",
    0x14: "UCSRA (USART Control and Status Register A)",
}

def rough_cycles(mnemonic: Optional[str], operands: str = "") -> Tuple[float, str]:
    if not mnemonic:
        return 0.0, "not an instruction"
    m = mnemonic.lower()
    if m in DIRECTIVES or m.startswith("."):
        return 0.0, "directive/pseudo-op"
    if m in {"jmp", "rjmp", "call", "rcall", "ret", "reti"}:
        return 2.0, "control transfer instruction, takes 2 cycles"
    if m in {"ijmp", "icall", "eijmp", "eicall"}:
        return 2.0, "indirect branch, takes 2 cycles"
    if m in {"lds", "sts", "ldd", "std"}:
        return 2.0, "direct/indirect SRAM memory transfer, takes 2 cycles"
    if m in {"breq", "brne", "brcs", "brcc", "brsh", "brlo", "brmi", "brpl", "brge", "brlt", "brhs", "brhc", "brts", "brtc", "brvs", "brvc", "brie", "brid"}:
        return 1.5, "conditional branch; 1 cycle if false, 2 cycles if true"
    if m in {"cpse", "sbrc", "sbrs", "sbic", "sbis"}:
        return 1.5, "conditional skip; 1 cycle if no skip, 2/3 cycles if skip taken"
    if m in {"mul", "muls", "mulsu", "fmul", "fmuls", "fmulsu"}:
        return 2.0, "hardware multiplication; takes 2 cycles on most cores"
    return 1.0, "standard single-cycle instruction"

def extract_registers_modified(mnemonic: str, operands: str) -> List[str]:
    m = mnemonic.lower()
    ops = [o.strip().lower() for o in operands.split(",")]
    if not ops or not ops[0]:
        return []
    
    first = ops[0]
    
    if m == "movw":
        reg_num = re.search(r"r(\d+)", first)
        if reg_num:
            n = int(reg_num.group(1))
            return [f"r{n}", f"r{n+1}"]
        if first == "x": return ["r26", "r27"]
        if first == "y": return ["r28", "r29"]
        if first == "z": return ["r30", "r31"]
        return [first]

    if m in {
        "ldi", "lds", "ld", "ldd", "mov", "add", "adc", "sub", "subi", "sbc", "sbci", 
        "and", "andi", "or", "ori", "eor", "com", "neg", "inc", "dec", "clr", "ser",
        "lsl", "lsr", "rol", "ror", "asr", "swap", "pop", "in"
    }:
        if re.match(r"^[rR]\d+$", first):
            return [first]
        if first in {"x", "y", "z"}:
            if first == "x": return ["r26", "r27"]
            if first == "y": return ["r28", "r29"]
            if first == "z": return ["r30", "r31"]
        return [first]
        
    return []

@dataclasses.dataclass
class AsmLine:
    physical_line: int
    raw: str
    list_line: Optional[int] = None
    address: Optional[int] = None
    address_text: str = ""
    opcode_text: str = ""
    asm_text: str = ""
    code: str = ""
    comment: str = ""
    label: Optional[str] = None
    mnemonic: Optional[str] = None
    operands: str = ""
    psect: Optional[str] = None
    source_ref: Optional[str] = None

    def is_instruction(self) -> bool:
        return self.mnemonic is not None and self.mnemonic not in DIRECTIVES and not self.mnemonic.startswith(".")

@dataclasses.dataclass
class Finding:
    severity: str
    category: str
    line: int
    message: str
    why: str
    suggestion: str
    raw: str
    parsed: str = ""
    source_ref: Optional[str] = None
    address: str = ""
    related_lines: List[int] = dataclasses.field(default_factory=list)
    context: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

def split_comments_all(s: str) -> Tuple[str, str]:
    if ";" in s:
        a, b = s.split(";", 1)
        return a.rstrip(), ";" + b
    if "//" in s:
        a, b = s.split("//", 1)
        return a.rstrip(), "//" + b
    if "/*" in s and "*/" in s:
        idx_start = s.find("/*")
        idx_end = s.find("*/")
        if idx_start < idx_end:
            return s[:idx_start].rstrip(), s[idx_start:idx_end+2]
    return s.rstrip(), ""

def hex_to_int(s: str) -> Optional[int]:
    try:
        return int(s, 16)
    except ValueError:
        return None

def parse_line(n: int, raw: str, current_section: Optional[str], last_source_ref: Optional[str]) -> AsmLine:
    line = raw.rstrip("\n")
    out = AsmLine(physical_line=n, raw=line, psect=current_section, source_ref=last_source_ref)
    s = line.strip()

    if not s:
        return out

    # 1. Detect disassembly section headers in .lss files (e.g., "Disassembly of section .text:")
    m_sec = re.match(r"^Disassembly of section \.?([\w$.-]+):", s, re.I)
    if m_sec:
        out.psect = m_sec.group(1)
        out.mnemonic = "section"
        out.operands = m_sec.group(1)
        out.asm_text = s
        return out

    # 2. Capture source reference lines generated by compiler or objdump
    msrc = re.search(r"^(?:[a-zA-Z]:)?[^:;*]+\.(?:c|h|cpp|s|asm):(\d+)(?::\s*(.*))?$", s, re.I)
    if not msrc:
        msrc = re.search(r";\s*([^;*]+\.(?:c|h|cpp|s|asm)):\s*(\d+)\s*:\s*(.*)$", s, re.I)
    
    if msrc:
        file_part = ""
        if ":" in s and not s.startswith(";"):
            file_part = s.split(":")[0].strip()
        elif msrc.lastindex and msrc.lastindex >= 3:
            file_part = msrc.group(1).strip()
        
        line_part = msrc.group(2).strip() if (msrc.lastindex and msrc.lastindex >= 3) else msrc.group(1).strip()
        code_part = msrc.group(3).strip() if (msrc.lastindex and msrc.lastindex >= 3) else ""
        out.source_ref = f"{file_part}:{line_part} {code_part}".strip()
        out.comment = s
        return out

    # 3. Handle avr-objdump listing format: "<hex_addr>: \t <opcode bytes> \t <asm>"
    m_objdump = re.match(r"^\s*([0-9A-Fa-f]+):\s*((?:[0-9A-Fa-f]{2}\s+){1,4}|[0-9A-Fa-f]{4,8})\s*(.*)$", s)
    candidate = s
    if m_objdump:
        addr_str = m_objdump.group(1)
        opcode_str = m_objdump.group(2).strip()
        candidate = m_objdump.group(3).strip()
        out.address_text = addr_str.upper()
        out.address = hex_to_int(addr_str)
        out.opcode_text = opcode_str

    if not candidate:
        return out

    code, comment = split_comments_all(candidate)
    out.asm_text = candidate
    out.code = code
    out.comment = comment

    stripped = code.strip()
    if not stripped:
        return out

    # 4. Handle Objdump/LSS style function boundary labels, e.g. "00000084 <__vector_12>:"
    m_obj_lbl = re.match(r"^([0-9A-Fa-f]+)\s+<([^>]+)>:\s*(.*)$", stripped)
    rest = stripped
    if m_obj_lbl:
        out.label = m_obj_lbl.group(2)
        out.address_text = m_obj_lbl.group(1).upper()
        out.address = hex_to_int(m_obj_lbl.group(1))
        rest = m_obj_lbl.group(3).strip()
    else:
        # Handle standard assembler local labels
        m_lbl = re.match(r"^([A-Za-z_0-9.$<>@]+):\s*(.*)$", stripped)
        if m_lbl:
            lbl = m_lbl.group(1).strip()
            if lbl.startswith("<") and lbl.endswith(">"):
                lbl = lbl[1:-1]
            elif "<" in lbl and ">" in lbl:
                m_sub = re.search(r"<([^>]+)>", lbl)
                if m_sub:
                    lbl = m_sub.group(1)
            out.label = lbl
            rest = m_lbl.group(2).strip()

    if rest:
        parts = rest.split(None, 1)
        tok = parts[0].strip()
        tok_clean = tok.lower().lstrip('.')
        
        if tok_clean in KNOWN_MNEMONICS or tok.startswith('.'):
            out.mnemonic = tok_clean
            out.operands = parts[1].strip() if len(parts) > 1 else ""
            if tok_clean == "section":
                sec_parts = out.operands.split(",")
                if sec_parts:
                    out.psect = sec_parts[0].strip().strip('"')
    return out

def parse_file(path: Path) -> List[AsmLine]:
    raw_lines = path.read_text(errors="replace").splitlines()
    out: List[AsmLine] = []
    current_section: Optional[str] = None
    last_source_ref: Optional[str] = None
    for i, raw in enumerate(raw_lines, 1):
        ln = parse_line(i, raw, current_section, last_source_ref)
        if ln.source_ref and not (ln.mnemonic or ln.label):
            last_source_ref = ln.source_ref
        if ln.mnemonic == "section":
            current_section = ln.psect
        else:
            ln.psect = current_section
        if ln.mnemonic or ln.label:
            ln.source_ref = last_source_ref
        out.append(ln)
    return out

def normalize_symbol(op: str) -> str:
    if not op:
        return ""
    first = op.split(",", 1)[0].strip()
    return first.lstrip("#").strip()

def target_label(op: str) -> str:
    val = normalize_symbol(op)
    if val.startswith("."):
        val = val.split("+")[0].split("-")[0]
    return val

def label_map(lines: List[AsmLine]) -> Dict[str, int]:
    return {ln.label: i for i, ln in enumerate(lines) if ln.label}

def next_code(lines: List[AsmLine], i: int) -> Optional[int]:
    for j in range(i + 1, len(lines)):
        if lines[j].mnemonic or lines[j].label:
            return j
    return None

def prev_code(lines: List[AsmLine], i: int) -> Optional[int]:
    for j in range(i - 1, -1, -1):
        if lines[j].mnemonic or lines[j].label:
            return j
    return None

def line_window(lines: List[AsmLine], i: int, radius: int = 3) -> List[str]:
    lo = max(0, i - radius)
    hi = min(len(lines), i + radius + 1)
    rows = []
    for k in range(lo, hi):
        ln = lines[k]
        if ln.mnemonic or ln.label:
            pointer = "=>" if k == i else "  "
            rows.append(f"{pointer} {ln.physical_line}: {ln.asm_text or ln.raw.strip()}")
    return rows

def operand_display_for(mnemonic: Optional[str], operands: str, sfr_by_addr: Dict[int, List[str]]) -> str:
    parts = [p.strip() for p in operands.split(",")]
    m = mnemonic.lower() if mnemonic else ""
    
    if m in {"in", "out", "sbi", "cbi", "sbic", "sbis"} and parts:
        addr_idx = 0 if m != "in" else 1
        if addr_idx < len(parts):
            param = parts[addr_idx]
            try:
                val = int(param, 0) if param.lower().startswith("0x") else int(param)
                names = sfr_by_addr.get(val)
                if names:
                    parts[addr_idx] = f"{param} ({'/'.join(names[:2])})"
            except ValueError:
                pass
                
    return ", ".join(parts)

class Analyzer:
    def __init__(self, lines: List[AsmLine], focus: str = "program"):
        self.lines = lines
        self.focus = focus
        self.labels = label_map(lines)
        self.findings: List[Finding] = []
        self.sfr_by_addr, self.addr_by_sfr = self.extract_symbols()
        self.program_indices = self.compute_program_indices()

    def extract_symbols(self) -> Tuple[Dict[int, List[str]], Dict[str, int]]:
        by_addr: Dict[int, List[str]] = defaultdict(list)
        by_name: Dict[str, int] = {}
        
        for addr, name in COMMON_AVR_SFRS.items():
            by_addr[addr].append(name)
            by_name[name.split()[0]] = addr

        for ln in self.lines:
            text = ln.asm_text or ln.raw
            m = re.match(r"^\s*\.?(equ|set)\s+([A-Za-z_][\w$]*)\s*,\s*([0-9A-Fa-fx]+|\d+)\b", text, re.I)
            if not m:
                m = re.match(r"^\s*([A-Za-z_][\w$]*)\s*=\s*([0-9A-Fa-fx]+|\d+)\b", text)
                
            if m:
                name = m.group(2) if m.lastindex >= 2 else m.group(1)
                val_s = m.group(3) if m.lastindex >= 3 else m.group(2)
                try:
                    val = int(val_s, 0) if val_s.lower().startswith("0x") else int(val_s)
                except ValueError:
                    try:
                        val = int(val_s, 16)
                    except ValueError:
                        continue
                if len(by_addr[val]) < 12:
                    by_addr[val].append(name)
                by_name[name] = val
                
        return dict(by_addr), by_name

    def compute_program_indices(self) -> List[int]:
        idx = []
        in_maintext = False
        for i, ln in enumerate(self.lines):
            if ln.mnemonic == "section":
                ps = ln.operands.split(",", 1)[0].strip().lower()
                in_maintext = ps in {".text", "text", ".init", ".vectors"} or "text" in ps
            if self.focus == "all":
                if ln.mnemonic or ln.label:
                    idx.append(i)
            elif self.focus == "maintext":
                if in_maintext and (ln.mnemonic or ln.label):
                    idx.append(i)
            else:
                if (ln.mnemonic or ln.label) and (in_maintext or ln.mnemonic not in {"equ", "set"}):
                    idx.append(i)
        return idx

    def add(self, sev: str, cat: str, i: int, msg: str, why: str, sug: str, related: Optional[List[int]] = None):
        ln = self.lines[i]
        parsed = ln.asm_text or ln.code or ln.raw.strip()
        if ln.mnemonic and ln.operands:
            parsed = f"{ln.mnemonic} {operand_display_for(ln.mnemonic, ln.operands, self.sfr_by_addr)}"
        self.findings.append(Finding(
            severity=sev, category=cat, line=ln.physical_line, message=msg, why=why,
            suggestion=sug, raw=ln.raw, parsed=parsed, source_ref=ln.source_ref,
            address=ln.address_text, related_lines=related or [], context=line_window(self.lines, i)
        ))

    def parse_immediate_value(self, s: str) -> Optional[int]:
        s = s.strip()
        if s.lower().startswith("0x"):
            try:
                return int(s, 16)
            except ValueError:
                return None
        if s.lower().startswith("0b"):
            try:
                return int(s, 2)
            except ValueError:
                return None
        try:
            return int(s)
        except ValueError:
            pass
        
        m_fn = re.match(r"^[lh]i8\((.+)\)$", s, re.I)
        if m_fn:
            inner = m_fn.group(1).strip()
            inner_val = self.parse_immediate_value(inner)
            if inner_val is not None:
                if s.lower().startswith("lo8"):
                    return inner_val & 0xFF
                else:
                    return (inner_val >> 8) & 0xFF
        return None

    def analyze(self) -> List[Finding]:
        self.find_nops()
        self.find_branches()
        self.find_delay_loops()
        self.find_ldi_patterns()
        self.find_ldi_zero_patterns()
        self.analyze_routines()
        return sorted(self.findings, key=lambda f: (f.line, f.category))

    def consider(self, i: int) -> bool:
        return i in self.program_indices

    def find_nops(self):
        for i, ln in enumerate(self.lines):
            if ln.mnemonic != "nop" or not self.consider(i):
                continue
            p = prev_code(self.lines, i)
            n = next_code(self.lines, i)
            pm = self.lines[p].mnemonic if p is not None else None
            nm = self.lines[n].mnemonic if n is not None else None
            if pm in SKIPS:
                self.add("INFO", "NOP_AFTER_SKIP", i, "NOP follows a conditional skip-class instruction.", "A NOP after CPSE/SBRC/etc. is often structural compiler alignment.", "Keep for timing precision; remove only if analyzing pure logic.", [self.lines[p].physical_line] if p else [])
            elif pm in BRANCHES or pm in RETURNS:
                self.add("WARN", "NOP_AFTER_CONTROL_TRANSFER", i, "NOP follows an unconditional branch or return.", "Normal code path execution cannot fall through to this location.", "Verify if this is an aligned branch landing site, a debug breakpoint, or dead code.", [self.lines[p].physical_line] if p else [])
            elif nm in RETURNS:
                self.add("WARN", "NOP_BEFORE_RETURN", i, "NOP immediately precedes a return instruction.", "Wastes 1 cycle and 1 flash instruction slot immediately before routine exit.", "Confirm timing intent. If not strictly required for port pin delay or hardware synchronization, discard.", [self.lines[n].physical_line] if n else [])

    def find_branches(self):
        for i, ln in enumerate(self.lines):
            if not self.consider(i) or not ln.mnemonic:
                continue
            m = ln.mnemonic.lower()
            if m not in BRANCHES:
                continue
            
            tgt = target_label(ln.operands)
            if tgt and tgt in self.labels:
                ni = next_code(self.lines, i)
                if ni is not None and self.lines[ni].label == tgt:
                    self.add("STRONG", "BRANCH_TO_NEXT_LABEL", i, f"Branch '{m.upper()} {tgt}' targets the next physical statement.", "Executing an explicit branch to the very next programmatic line wastes processing clock cycles.", "Remove the branch statement. If it is a conditional branch, evaluate if inverting the condition helps compact code.", [self.lines[ni].physical_line])
                if self.labels[tgt] == i or self.lines[i].label == tgt:
                    self.add("WARN", "SELF_BRANCH", i, f"Branch '{m.upper()} {tgt}' targets its own line.", "Creates a hard loop execution deadlock (trap).", "Verify if this trap loop is a designed safety exit or hardware error-trap mechanism. Otherwise, fix loop destination.", [self.lines[self.labels[tgt]].physical_line])

    def find_delay_loops(self):
        for i, ln in enumerate(self.lines):
            if not self.consider(i) or not ln.label:
                continue
            
            lbl = ln.label
            for offset in range(1, 5):
                k = i + offset
                if k >= len(self.lines):
                    break
                target_ln = self.lines[k]
                if not target_ln.mnemonic:
                    continue
                
                m = target_ln.mnemonic.lower()
                if m == "brne":
                    tgt = target_label(target_ln.operands)
                    if tgt == lbl:
                        intermediates = [self.lines[idx] for idx in range(i, k) if self.lines[idx].mnemonic]
                        loop_mnemonics = {ln.mnemonic.lower() for ln in intermediates if ln.mnemonic}
                        
                        if any(op in loop_mnemonics for op in {"dec", "subi", "sbc", "sbiw"}):
                            self.add("INFO", "DELAY_LOOP", i, f"Routine '{lbl}' forms a busy delay loop structure.", "A decrementation conditional branch loop blocks the main thread of execution.", "If non-critical, offload execution timing to hardware Timers or use interrupts to perform background actions.", [target_ln.physical_line])

    def find_ldi_patterns(self):
        reg_states: Dict[str, int] = {}
        CALL_CLOBBERED_REGS = {"r0", "r1", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r30", "r31"}

        for i, ln in enumerate(self.lines):
            if not self.consider(i) or not ln.mnemonic:
                continue
            
            m = ln.mnemonic.lower()
            if ln.label or m in BARRIERS:
                reg_states.clear()
                if m in BARRIERS and m not in CALLS:
                    continue

            if m in CALLS:
                for r in CALL_CLOBBERED_REGS:
                    if r in reg_states:
                        del reg_states[r]
                continue

            if m == "ldi":
                ops = [o.strip() for o in ln.operands.split(",")]
                if len(ops) >= 2:
                    reg = ops[0].lower()
                    val_s = ops[1]
                    
                    if LDI_REG_PATTERN.match(reg):
                        val = self.parse_immediate_value(val_s)
                        if val is not None:
                            if reg in reg_states and reg_states[reg] == val:
                                hex_val = f"0x{val:02X}" if val >= 0 else str(val)
                                self.add("WARN", "REPEATED_LDI", i, f"LDI reloads register {reg.upper()} with the value {val_s} ({hex_val}) it already contains.", "A register reloaded with the exact same literal without structural usage degrades cycle budget.", "Inspect register data paths. If the data state remains guaranteed, eliminate this load statement.", [])
                            reg_states[reg] = val
                        else:
                            if reg in reg_states:
                                del reg_states[reg]
                continue
                
            if m == "clr":
                reg = ln.operands.strip().lower()
                if re.match(r"^[rR]\d+$", reg):
                    reg_states[reg] = 0
                continue
                
            if m == "ser":
                reg = ln.operands.strip().lower()
                if re.match(r"^[rR]\d+$", reg):
                    reg_states[reg] = 255
                continue

            mod_regs = extract_registers_modified(m, ln.operands)
            for r in mod_regs:
                r_lower = r.lower()
                if r_lower in reg_states:
                    del reg_states[r_lower]

    def find_ldi_zero_patterns(self):
        for i, ln in enumerate(self.lines):
            if not self.consider(i) or not ln.mnemonic:
                continue
            m = ln.mnemonic.lower()
            if m == "ldi":
                ops = [o.strip() for o in ln.operands.split(",")]
                if len(ops) >= 2:
                    reg = ops[0].lower()
                    val_s = ops[1]
                    val = self.parse_immediate_value(val_s)
                    if val == 0:
                        self.add("INFO", "LDI_ZERO_OPTIMIZATION", i, f"LDI {reg.upper()}, {val_s} can be optimized to CLR {reg.upper()}.", "CLR Rd executes as 'eor Rd, Rd' which resets the register. CLR works on all registers (r0-r31) whereas LDI is limited to high registers (r16-r31). Note that CLR modifies the Zero (Z), Negative (N), Overflow (V), and Signed (S) status flags of the SREG, while LDI leaves status flags unaffected.", "If the status register flags are don't-care at this boundary, substitute with CLR.", [])

    def analyze_routines(self):
        label_indices = [i for i, ln in enumerate(self.lines) if ln.label]
        if not label_indices:
            return
            
        for idx, l_idx in enumerate(label_indices):
            lbl = self.lines[l_idx].label
            next_lbl_idx = label_indices[idx + 1] if idx + 1 < len(label_indices) else len(self.lines)
            
            end_idx = None
            isr_flag = False
            
            for k in range(l_idx, next_lbl_idx):
                ln = self.lines[k]
                if ln.mnemonic in {"ret", "reti"}:
                    end_idx = k
                    if ln.mnemonic == "reti":
                        isr_flag = True
                    break
                    
            if end_idx is not None:
                self.check_push_pop_balance(l_idx, end_idx)
                if isr_flag:
                    self.check_isr_sreg_preservation(l_idx, end_idx)

    def check_push_pop_balance(self, start_idx: int, end_idx: int):
        pushes = []
        pops = []
        for k in range(start_idx, end_idx + 1):
            ln = self.lines[k]
            if not ln.mnemonic:
                continue
            m = ln.mnemonic.lower()
            if m == "push":
                pushes.append(ln)
            elif m == "pop":
                pops.append(ln)
                
        if len(pushes) != len(pops):
            self.add(
                "STRONG", "PUSH_POP_MISMATCH", start_idx,
                f"Asymmetric stack frames found: push operations ({len(pushes)}) do not match pop operations ({len(pops)}).",
                "Unbalanced structural stack changes corrupt the return address path. Executing RET or RETI will crash the CPU or jump to undefined program memory.",
                "Thoroughly analyze all decision paths inside this routine. Ensure that every push operation has a corresponding pop statement before leaving the block.",
                [p.physical_line for p in pushes] + [p.physical_line for p in pops]
            )

    def check_isr_sreg_preservation(self, start_idx: int, end_idx: int):
        has_in_sreg = False
        has_out_sreg = False
        
        for k in range(start_idx, end_idx + 1):
            ln = self.lines[k]
            if not ln.mnemonic:
                continue
            m = ln.mnemonic.lower()
            ops = [o.strip() for o in ln.operands.split(",")]
            
            if m == "in" and len(ops) >= 2:
                src = ops[1].lower()
                if src in {"0x3f", "0x3f", "63", "__sreg__", "sreg"}:
                    has_in_sreg = True
                    
            if m == "out" and len(ops) >= 2:
                dest = ops[0].lower()
                if dest in {"0x3f", "0x3f", "63", "__sreg__", "sreg"}:
                    has_out_sreg = True
                    
        if not has_in_sreg:
            self.add(
                "STRONG", "ISR_MISSING_SREG_SAVE", start_idx,
                "Interrupt Service Routine (ISR) does not preserve SREG (Status Register).",
                "An ISR must save SREG immediately upon entry. Failing to save arithmetic flags causes random and untraceable data corruption in interrupted thread operations.",
                "Ensure SREG (I/O address 0x3F) is read via an IN instruction and pushed to the stack right after saving your working registers.",
                [self.lines[end_idx].physical_line]
            )
        elif not has_out_sreg:
            self.add(
                "STRONG", "ISR_MISSING_SREG_RESTORE", start_idx,
                "Interrupt Service Routine (ISR) contains an SREG read sequence but misses the write/restore statement.",
                "Any SREG saved in an ISR prologue must be popped and loaded back into the SREG I/O register before finishing with RETI.",
                "Inject an 'OUT 0x3F, Rd' instruction in the routine's exit sequence to restore original operational status flags.",
                [self.lines[end_idx].physical_line]
            )

def build_summary(lines: List[AsmLine], analyzer: Analyzer) -> Dict[str, Any]:
    rec = [ln for ln in lines if ln.mnemonic or ln.label]
    instr = [ln for ln in lines if ln.is_instruction()]
    directives = [ln for ln in lines if ln.mnemonic in DIRECTIVES or (ln.mnemonic and ln.mnemonic.startswith("."))]
    psects = Counter(ln.psect or "<none>" for ln in instr)
    mn = Counter(ln.mnemonic for ln in instr if ln.mnemonic)
    
    branches = [ln for ln in instr if ln.mnemonic in BRANCHES]
    skips = [ln for ln in instr if ln.mnemonic in SKIPS]
    calls = [ln for ln in instr if ln.mnemonic in CALLS]
    returns = [ln for ln in instr if ln.mnemonic in RETURNS]
    cycles = sum(rough_cycles(ln.mnemonic, ln.operands)[0] for ln in instr)
    src = Counter(ln.source_ref for ln in instr if ln.source_ref)
    
    return {
        "physical_lines": len(lines),
        "recognized_lines": len(rec),
        "instruction_lines": len(instr),
        "directive_lines": len(directives),
        "labels": len([ln for ln in lines if ln.label]),
        "rough_static_cycle_sum": cycles,
        "mnemonics": dict(mn.most_common()),
        "psects": dict(psects.most_common()),
        "branches": len(branches),
        "skips": len(skips),
        "calls": len(calls),
        "returns": len(returns),
        "source_refs": dict(src.most_common(20)),
    }

def render_report(path: Path, lines: List[AsmLine], analyzer: Analyzer, findings: List[Finding]) -> str:
    summary = build_summary(lines, analyzer)
    instr = [ln for ln in lines if ln.is_instruction()]
    rec = [ln for ln in lines if ln.mnemonic or ln.label]
    sev = Counter(f.severity for f in findings)

    meanings = {
        "ldi": "load immediate byte into register",
        "mov": "copy register",
        "movw": "copy 16-bit register pair",
        "lds": "load direct from SRAM",
        "sts": "store direct to SRAM",
        "ld": "load indirect from pointer (X, Y, or Z)",
        "st": "store indirect to pointer (X, Y, or Z)",
        "in": "read from I/O address",
        "out": "write to I/O address",
        "push": "push register onto stack",
        "pop": "pop register from stack",
        "add": "add without carry",
        "adc": "add with carry",
        "sub": "subtract without carry",
        "subi": "subtract immediate from register",
        "and": "bitwise AND",
        "andi": "bitwise AND immediate",
        "or": "bitwise OR",
        "ori": "bitwise OR immediate",
        "eor": "bitwise XOR (often used to clear register)",
        "clr": "clear register (alias of eor Rd, Rd)",
        "ser": "set register to 0xFF",
        "jmp": "unconditional long jump",
        "rjmp": "unconditional relative jump",
        "call": "direct function call",
        "rcall": "relative function call",
        "ret": "return from function",
        "reti": "return from interrupt (restores global interrupts)",
        "cp": "compare registers",
        "cpc": "compare with carry",
        "cpi": "compare register with immediate",
        "breq": "branch if equal (Zero flag set)",
        "brne": "branch if not equal (Zero flag cleared)",
        "sbi": "set bit in I/O register",
        "cbi": "clear bit in I/O register",
        "sbrc": "skip next instruction if register bit is clear",
        "sbrs": "skip next instruction if register bit is set",
        "nop": "no operation/timing padding",
    }

    out = [
        "# AVR Assembly Programmer Review", "",
        f"**Input:** `{path}`", "",
        "## Executive summary", "",
        f"- Physical listing lines: **{summary['physical_lines']}**",
        f"- Recognized assembly/directive/label lines: **{summary['recognized_lines']}**",
        f"- Executable instruction lines: **{summary['instruction_lines']}**",
        f"- Labels: **{summary['labels']}**",
        f"- Rough static cycle sum, one pass through listed instructions: **{summary['rough_static_cycle_sum']:.1f}** cycles",
        f"- Findings: **{len(findings)}** — STRONG {sev.get('STRONG',0)}, WARN {sev.get('WARN',0)}, INFO {sev.get('INFO',0)}", "",
        "The cycle number is a static metric. Dynamic loops, interrupts, pipeline stalls, and branch decisions alter runtime timing.", "",
        "## First recognized program lines", "", "```asm"
    ]
    for ln in rec[:30]:
        addr = f"{ln.address_text} " if ln.address_text else ""
        out.append(f"{ln.physical_line:5d}: {addr}{ln.asm_text or ln.raw.strip()}")
    
    out.extend([
        "```", 
        "", 
        "## Instruction mix", 
        "", 
        "| Mnemonic | Count | Programmer meaning |", 
        "|---|---:|---|"
    ])
    
    for m, c in Counter(ln.mnemonic for ln in instr if ln.mnemonic).most_common():
        out.append(f"| `{m}` | {c} | {meanings.get(m, 'instruction')} |")
    
    out.extend(["", "## Special Function Register (SFR) Mapping", ""])
    used = []
    for ln in instr:
        if ln.operands and ln.mnemonic in {"in", "out", "sbi", "cbi", "sbic", "sbis"}:
            parts = [p.strip() for p in ln.operands.split(",")]
            addr_idx = 0 if ln.mnemonic.lower() != "in" else 1
            if addr_idx < len(parts):
                param = parts[addr_idx]
                try:
                    val = int(param, 0) if param.lower().startswith("0x") else int(param)
                    names = analyzer.sfr_by_addr.get(val)
                    if names:
                        used.append((ln.physical_line, param, "/".join(names[:4]), ln.asm_text))
                except ValueError:
                    pass
    if used:
        out.extend(["| Line | Numeric Address | Mapped SFR | Instruction |", "|---:|---:|---|---|"])
        for l, num, names, text in used[:40]:
            out.append(f"| {l} | {num} | `{names}` | `{text}` |")
    else:
        out.append("No numeric SFR or Port addresses were mapped in the evaluated instruction paths.")
        
    out.extend(["", "## Source-line map", ""])
    if summary["source_refs"]:
        out.extend(["| Source reference | Instruction count |", "|---|---:|"])
        for src, c in summary["source_refs"].items():
            out.append(f"| `{src}` | {c} |")
    else:
        out.append("No compiler source line mappings found.")
        
    out.extend(["", "## Findings", ""])
    if not findings:
        out.append("No suspicious patterns were detected in the evaluated program boundaries.")
    for f in findings:
        rel = f" Related lines: {', '.join(map(str, f.related_lines))}." if f.related_lines else ""
        out.append(f"### Line {f.line}: {f.category} [{f.severity}]")
        if f.source_ref:
            out.append(f"Source context: `{f.source_ref}`")
        if f.address:
            out.append(f"Address: `{f.address}`")
        out.extend(["", "```asm", f.raw, "```"])
        if f.parsed:
            out.append(f"Parsed / interpreted as: `{f.parsed}`")
        out.extend(["", f"**Finding:** {f.message}", "", f"**Why it matters:** {f.why}{rel}", "", f"**Suggested action:** {f.suggestion}"])
        if f.context:
            out.extend(["", "Local context:", "```asm"])
            out.extend(f.context)
            out.append("```")
        out.append("")

    return "\n".join(out)

def write_annotated(lines: List[AsmLine], findings: List[Finding], path: Path):
    by = defaultdict(list)
    for f in findings:
        by[f.line].append(f)
    out = []
    for ln in lines:
        if ln.physical_line in by:
            out.append("; " + "-"*77)
            for f in by[ln.physical_line]:
                out.append(f"; REVIEW {f.severity} {f.category}: {f.message}")
                if f.source_ref:
                    out.append(f"; SOURCE: {f.source_ref}")
                if f.parsed:
                    out.append(f"; PARSED: {f.parsed}")
                out.append(f"; WHY: {f.why}")
                out.append(f"; DO: {f.suggestion}")
            out.append("; " + "-"*77)
        out.append(ln.raw)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Smarter AVR avr-gcc and avr-objdump programmer review tool")
    ap.add_argument("input", type=Path)
    ap.add_argument("--report", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--annotate", action="store_true")
    ap.add_argument("--annotated-output", type=Path)
    ap.add_argument("--min-severity", choices=["INFO", "WARN", "STRONG"], default="INFO")
    ap.add_argument("--focus", choices=["program", "maintext", "all"], default="program")
    args = ap.parse_args(argv)

    if not args.input.exists():
        raise SystemExit(f"Input file not found: {args.input}")

    rank = {"INFO": 0, "WARN": 1, "STRONG": 2}
    lines = parse_file(args.input)
    an = Analyzer(lines, focus=args.focus)
    findings = [f for f in an.analyze() if rank[f.severity] >= rank[args.min_severity]]
    summary = build_summary(lines, an)

    print(f"Input physical lines: {summary['physical_lines']}")
    print(f"Findings: {len(findings)}")

    rpt = args.report or args.input.with_suffix(args.input.suffix + ".programmer_review.md")
    rpt.write_text(render_report(args.input, lines, an, findings), encoding="utf-8")
    
    if args.json:
        payload = {"summary": summary, "findings": [f.to_dict() for f in findings]}
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.annotate or args.annotated_output:
        out = args.annotated_output or args.input.with_suffix(args.input.suffix + ".annotated.lst")
        write_annotated(lines, findings, out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
"""
Minimal x86-64 length disassembler.

Returns (instr_length, rip_disp_off, rel32_disp_off) where:
  instr_length    > 0 on success, 0 on undecodable
  rip_disp_off    byte offset within instruction of RIP-relative disp32, or -1
  rel32_disp_off  byte offset of REL32 displacement (E8/E9/0F 8x), or -1

Covers the subset MSVC /Os /O1 emits for our codebase. Unknown opcodes
return length=0 so the caller falls back to NOP-fill packing.
"""

# Opcode flag bits
F_MODRM   = 0x01    # has ModR/M byte
F_IB      = 0x02    # has 1-byte immediate (after disp)
F_IW      = 0x04    # has 2-byte immediate (RET imm16)
F_IV      = 0x08    # has var-size immediate: 16 if 66-prefix, 32 otherwise (most ALU)
F_IO      = 0x10    # has op-size imm with possible 64-bit (only B8+r with REX.W)
F_REL8    = 0x20    # 1-byte rel branch (Jcc, JMP rel8, CALL has no rel8)
F_REL32   = 0x40    # 4-byte rel branch (E8/E9, 0F 8x: encoded separately)
F_ESC0F   = 0x80    # 0F two-byte escape

# Primary 1-byte opcode table
OP1 = [0] * 256

def _set_op(table, start, end, flags):
    for i in range(start, end + 1):
        table[i] = flags

# ALU r/m + r forms (00-3F): pattern repeats in 8-byte groups
for base in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
    OP1[base + 0] = F_MODRM        # op r/m8, r8
    OP1[base + 1] = F_MODRM        # op r/m, r
    OP1[base + 2] = F_MODRM        # op r8, r/m8
    OP1[base + 3] = F_MODRM        # op r, r/m
    OP1[base + 4] = F_IB           # op AL, imm8
    OP1[base + 5] = F_IV           # op rAX, imm
    # +6, +7: PUSH/POP seg (invalid in 64-bit) - leave as 0 (decode will fail if hit)

# 0x0F: escape to two-byte opcode
OP1[0x0F] = F_ESC0F

# 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67: prefixes (handled before opcode dispatch)

# REX 0x40-0x4F: handled before opcode dispatch

# 0x50-0x5F: PUSH/POP reg, 1 byte
_set_op(OP1, 0x50, 0x5F, 0)

# 0x63: MOVSXD (modrm)
OP1[0x63] = F_MODRM

# 0x68: PUSH imm32
OP1[0x68] = F_IV
# 0x69: IMUL r,r/m,imm32 (modrm + imm)
OP1[0x69] = F_MODRM | F_IV
# 0x6A: PUSH imm8
OP1[0x6A] = F_IB
# 0x6B: IMUL r,r/m,imm8 (modrm + imm8)
OP1[0x6B] = F_MODRM | F_IB

# 0x70-0x7F: Jcc rel8
_set_op(OP1, 0x70, 0x7F, F_REL8)

# 0x80: ALU r/m8, imm8 (modrm + imm8)
OP1[0x80] = F_MODRM | F_IB
# 0x81: ALU r/m, imm32 (modrm + imm)
OP1[0x81] = F_MODRM | F_IV
# 0x82: invalid in 64-bit (alias for 80)
OP1[0x82] = F_MODRM | F_IB    # treat as 0x80 for safety
# 0x83: ALU r/m, imm8 (modrm + imm8)
OP1[0x83] = F_MODRM | F_IB

# 0x84-0x87: TEST/XCHG (modrm)
_set_op(OP1, 0x84, 0x87, F_MODRM)
# 0x88-0x8B: MOV (modrm)
_set_op(OP1, 0x88, 0x8B, F_MODRM)
# 0x8C: MOV seg (modrm)
OP1[0x8C] = F_MODRM
# 0x8D: LEA (modrm)
OP1[0x8D] = F_MODRM
# 0x8E: MOV seg (modrm)
OP1[0x8E] = F_MODRM
# 0x8F: POP r/m (modrm)
OP1[0x8F] = F_MODRM

# 0x90: NOP
OP1[0x90] = 0
# 0x91-0x97: XCHG rAX, r
_set_op(OP1, 0x91, 0x97, 0)
# 0x98: CBW/CWDE/CDQE
OP1[0x98] = 0
# 0x99: CWD/CDQ/CQO
OP1[0x99] = 0
# 0x9B: WAIT
OP1[0x9B] = 0
# 0x9C: PUSHF
OP1[0x9C] = 0
# 0x9D: POPF
OP1[0x9D] = 0
# 0x9E: SAHF
OP1[0x9E] = 0
# 0x9F: LAHF
OP1[0x9F] = 0

# 0xA0-0xA3: MOV with moffs64 - 8-byte displacement (no modrm, no imm but has 8-byte offset)
# MSVC won't emit these typically; flag as unsupported by leaving 0... actually they need 8 bytes
# Mark them as "has IO" flag to consume 8 bytes? That's a stretch. Use a special handler.
# For now, mark as 0 (will hopefully not appear).
_set_op(OP1, 0xA0, 0xA3, 0)
# 0xA4-0xA7: string ops
_set_op(OP1, 0xA4, 0xA7, 0)
# 0xA8: TEST AL, imm8
OP1[0xA8] = F_IB
# 0xA9: TEST rAX, imm
OP1[0xA9] = F_IV
# 0xAA-0xAF: string ops
_set_op(OP1, 0xAA, 0xAF, 0)

# 0xB0-0xB7: MOV r8, imm8
_set_op(OP1, 0xB0, 0xB7, F_IB)
# 0xB8-0xBF: MOV r32/r64, imm32/imm64 (depends on REX.W)
_set_op(OP1, 0xB8, 0xBF, F_IO)

# 0xC0, 0xC1: shift r/m, imm8 (modrm + imm8)
OP1[0xC0] = F_MODRM | F_IB
OP1[0xC1] = F_MODRM | F_IB
# 0xC2: RET imm16
OP1[0xC2] = F_IW
# 0xC3: RET
OP1[0xC3] = 0
# 0xC6: MOV r/m8, imm8 (modrm + imm8)
OP1[0xC6] = F_MODRM | F_IB
# 0xC7: MOV r/m, imm32 (modrm + imm)
OP1[0xC7] = F_MODRM | F_IV
# 0xC8: ENTER imm16, imm8 (2-byte + 1-byte imm)
OP1[0xC8] = F_IW | F_IB
# 0xC9: LEAVE
OP1[0xC9] = 0
# 0xCA: RET far imm16
OP1[0xCA] = F_IW
# 0xCB: RET far
OP1[0xCB] = 0
# 0xCC: INT3
OP1[0xCC] = 0
# 0xCD: INT imm8
OP1[0xCD] = F_IB
# 0xCF: IRET
OP1[0xCF] = 0

# 0xD0-0xD3: shift r/m by 1 / CL (modrm)
_set_op(OP1, 0xD0, 0xD3, F_MODRM)
# 0xD4, 0xD5: AAM/AAD invalid in 64-bit
# 0xD7: XLAT
OP1[0xD7] = 0

# 0xE0-0xE3: LOOPcc/JCXZ rel8
_set_op(OP1, 0xE0, 0xE3, F_REL8)
# 0xE4-0xE5: IN imm8
_set_op(OP1, 0xE4, 0xE5, F_IB)
# 0xE6-0xE7: OUT imm8
_set_op(OP1, 0xE6, 0xE7, F_IB)
# 0xE8: CALL rel32
OP1[0xE8] = F_REL32
# 0xE9: JMP rel32
OP1[0xE9] = F_REL32
# 0xEB: JMP rel8
OP1[0xEB] = F_REL8
# 0xEC-0xEF: IN/OUT DX
_set_op(OP1, 0xEC, 0xEF, 0)

# 0xF0, 0xF2, 0xF3: prefixes (handled before)
# 0xF1: ICEBP
OP1[0xF1] = 0
# 0xF4: HLT
OP1[0xF4] = 0
# 0xF5: CMC
OP1[0xF5] = 0
# 0xF6: group 3 (TEST r/m8, imm8 OR NOT/NEG/MUL/etc) - modrm + maybe imm8
# Need to check ModR/M.reg to decide. /0 and /1 have imm8; others don't.
# We'll handle this specially.
OP1[0xF6] = F_MODRM  # default; special-case in decoder
# 0xF7: group 3 (modrm + maybe imm32 for /0,/1)
OP1[0xF7] = F_MODRM  # special-case
# 0xF8-0xFD: CLC/STC/etc
_set_op(OP1, 0xF8, 0xFD, 0)
# 0xFE: INC/DEC group (modrm only)
OP1[0xFE] = F_MODRM
# 0xFF: group 5 - modrm only (INC/DEC/CALL/JMP/PUSH r/m)
OP1[0xFF] = F_MODRM


# 0F escape table
OP2 = [0] * 256

# 0F 00: SLDT/STR/LLDT etc (group 6) - modrm
OP2[0x00] = F_MODRM
# 0F 01: SGDT/SIDT etc - modrm
OP2[0x01] = F_MODRM
# 0F 05: SYSCALL
OP2[0x05] = 0
# 0F 06: CLTS
OP2[0x06] = 0
# 0F 07: SYSRET
OP2[0x07] = 0
# 0F 08: INVD
OP2[0x08] = 0
# 0F 09: WBINVD
OP2[0x09] = 0
# 0F 0B: UD2
OP2[0x0B] = 0
# 0F 0D: PREFETCH (modrm)
OP2[0x0D] = F_MODRM
# 0F 0E: FEMMS
OP2[0x0E] = 0

# 0F 10-17: SSE MOV (modrm)
_set_op(OP2, 0x10, 0x17, F_MODRM)
# 0F 18-1F: prefetch/NOP variants (modrm)
_set_op(OP2, 0x18, 0x1F, F_MODRM)
# 0F 20-23: MOV CR/DR
_set_op(OP2, 0x20, 0x23, F_MODRM)
# 0F 28-2F: SSE
_set_op(OP2, 0x28, 0x2F, F_MODRM)
# 0F 30-37: RDMSR/RDTSC etc
_set_op(OP2, 0x30, 0x37, 0)
# 0F 38, 3A: 3-byte opcode escape (we treat as unsupported for now)
# 0F 40-4F: CMOVcc (modrm)
_set_op(OP2, 0x40, 0x4F, F_MODRM)
# 0F 50-7F: SSE/MMX (modrm) - usually
_set_op(OP2, 0x50, 0x7F, F_MODRM)
# 0F 80-8F: Jcc rel32
_set_op(OP2, 0x80, 0x8F, F_REL32)
# 0F 90-9F: SETcc r/m8 (modrm)
_set_op(OP2, 0x90, 0x9F, F_MODRM)
# 0F A0-A1: PUSH/POP FS
OP2[0xA0] = 0
OP2[0xA1] = 0
# 0F A2: CPUID
OP2[0xA2] = 0
# 0F A3: BT (modrm)
OP2[0xA3] = F_MODRM
# 0F A4: SHLD r/m, r, imm8
OP2[0xA4] = F_MODRM | F_IB
# 0F A5: SHLD r/m, r, CL
OP2[0xA5] = F_MODRM
# 0F A8-A9: PUSH/POP GS
OP2[0xA8] = 0
OP2[0xA9] = 0
# 0F AB: BTS (modrm)
OP2[0xAB] = F_MODRM
# 0F AC: SHRD r/m, r, imm8
OP2[0xAC] = F_MODRM | F_IB
# 0F AD: SHRD r/m, r, CL
OP2[0xAD] = F_MODRM
# 0F AE: misc (modrm)
OP2[0xAE] = F_MODRM
# 0F AF: IMUL (modrm)
OP2[0xAF] = F_MODRM
# 0F B0, B1: CMPXCHG (modrm)
OP2[0xB0] = F_MODRM
OP2[0xB1] = F_MODRM
# 0F B2-B5: LSS/LFS/LGS (modrm)
_set_op(OP2, 0xB2, 0xB5, F_MODRM)
# 0F B6, B7: MOVZX (modrm)
OP2[0xB6] = F_MODRM
OP2[0xB7] = F_MODRM
# 0F B8: POPCNT (with F3 prefix) / JMPE (modrm); also POPCNT (modrm)
OP2[0xB8] = F_MODRM
# 0F B9: UD1 (modrm)
OP2[0xB9] = F_MODRM
# 0F BA: BT/BTS/BTR/BTC r/m, imm8
OP2[0xBA] = F_MODRM | F_IB
# 0F BB: BTC (modrm)
OP2[0xBB] = F_MODRM
# 0F BC: BSF (modrm)
OP2[0xBC] = F_MODRM
# 0F BD: BSR (modrm)
OP2[0xBD] = F_MODRM
# 0F BE, BF: MOVSX (modrm)
OP2[0xBE] = F_MODRM
OP2[0xBF] = F_MODRM
# 0F C0, C1: XADD (modrm)
OP2[0xC0] = F_MODRM
OP2[0xC1] = F_MODRM
# 0F C2: CMPSS/CMPPS (modrm + imm8)
OP2[0xC2] = F_MODRM | F_IB
# 0F C3: MOVNTI (modrm)
OP2[0xC3] = F_MODRM
# 0F C4: PINSRW (modrm + imm8)
OP2[0xC4] = F_MODRM | F_IB
# 0F C5: PEXTRW (modrm + imm8)
OP2[0xC5] = F_MODRM | F_IB
# 0F C6: SHUFPS (modrm + imm8)
OP2[0xC6] = F_MODRM | F_IB
# 0F C7: group 9 (CMPXCHG8B etc) (modrm)
OP2[0xC7] = F_MODRM
# 0F C8-CF: BSWAP (single byte +r)
_set_op(OP2, 0xC8, 0xCF, 0)
# 0F D0-FF: SSE/MMX (modrm)
_set_op(OP2, 0xD0, 0xFF, F_MODRM)


def decode(buf, pos, max_pos):
    """Decode one instruction at buf[pos:max_pos].
    Returns (length, rip_disp_off, rel32_disp_off) or (0, -1, -1) on failure.
    """
    start = pos
    op_size_16 = False
    addr_size_32 = False
    rex_w = False

    # 1. Legacy prefixes (skip)
    while pos < max_pos:
        b = buf[pos]
        if b == 0x66:
            op_size_16 = True
            pos += 1
        elif b == 0x67:
            addr_size_32 = True
            pos += 1
        elif b in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0xF0, 0xF2, 0xF3):
            pos += 1
        else:
            break
        if pos - start > 4:
            return (0, -1, -1)  # excessive prefixes

    if pos >= max_pos:
        return (0, -1, -1)

    # 2. REX prefix
    if 0x40 <= buf[pos] <= 0x4F:
        rex_w = bool(buf[pos] & 0x08)
        pos += 1
        if pos >= max_pos:
            return (0, -1, -1)

    # 3. Opcode (1 or 2 bytes via 0F escape)
    op = buf[pos]
    pos += 1
    is_0f = False
    flags = OP1[op]
    if flags & F_ESC0F:
        # 0F escape
        if pos >= max_pos:
            return (0, -1, -1)
        op2 = buf[pos]
        pos += 1
        # 0F 38 / 0F 3A: 3-byte opcodes (unsupported)
        if op2 in (0x38, 0x3A):
            return (0, -1, -1)
        is_0f = True
        flags = OP2[op2]
        op = op2

    if flags == 0 and op not in (
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,  # XCHG rAX, r
        0x98, 0x99, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xC3, 0xC9, 0xCB, 0xCC, 0xCF,
        0xF1, 0xF4, 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
    ) and not (0x50 <= op <= 0x5F) and not (0xEC <= op <= 0xEF) and not (is_0f and (0xC8 <= op <= 0xCF)) and not (is_0f and (op in (0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9))):
        # Hit "0" for an opcode that isn't a real zero-operand opcode -> unsupported
        return (0, -1, -1)

    rip_disp_off = -1
    rel32_disp_off = -1

    # 4. ModR/M + SIB + disp
    if flags & F_MODRM:
        if pos >= max_pos:
            return (0, -1, -1)
        modrm = buf[pos]
        mod = (modrm >> 6) & 3
        rm = modrm & 7
        pos += 1

        # Group 3 special case: 0xF6 /0 /1 has imm8; 0xF7 /0 /1 has imm
        reg = (modrm >> 3) & 7
        if op == 0xF6 and not is_0f and reg in (0, 1):
            flags |= F_IB
        elif op == 0xF7 and not is_0f and reg in (0, 1):
            flags |= F_IV

        sib_present = (mod != 3 and rm == 4)
        disp_size = 0
        if mod == 3:
            pass  # register operand, no disp
        elif mod == 0:
            if rm == 5:
                # [RIP + disp32] in 64-bit mode (or [disp32] if addr_size_32)
                if not addr_size_32:
                    rip_disp_off = pos - start + (1 if sib_present else 0)
                disp_size = 4
            elif rm == 4:
                # SIB; check SIB.base==5 for disp32
                if pos >= max_pos:
                    return (0, -1, -1)
                sib = buf[pos]
                pos += 1
                base = sib & 7
                if base == 5:
                    disp_size = 4
        elif mod == 1:
            if rm == 4:
                if pos >= max_pos: return (0, -1, -1)
                pos += 1  # SIB
            disp_size = 1
        elif mod == 2:
            if rm == 4:
                if pos >= max_pos: return (0, -1, -1)
                pos += 1  # SIB
            disp_size = 4

        # Note: for sib_present mod==0 case, we already consumed sib above
        if sib_present and mod == 0:
            pass  # already consumed
        # Adjust disp_off if SIB was added in the no-sib branch (oops, complicated)
        if rip_disp_off >= 0:
            # rip-rel: we already computed offset before pos += sib byte. But for mod=0 rm=5,
            # there's no SIB - so this is fine.
            rip_disp_off = pos - start

        pos += disp_size
        if pos > max_pos:
            return (0, -1, -1)

    # 5. Immediate
    if flags & F_IB:
        pos += 1
    if flags & F_IW:
        pos += 2
    if flags & F_IV:
        # 16 if 66-prefix; 32 otherwise
        pos += 2 if op_size_16 else 4
    if flags & F_IO:
        # 16 if 66; 64 if REX.W; 32 otherwise
        if rex_w:
            pos += 8
        elif op_size_16:
            pos += 2
        else:
            pos += 4
    if flags & F_REL8:
        pos += 1
    if flags & F_REL32:
        rel32_disp_off = pos - start
        # 16 if 66; 32 otherwise
        pos += 2 if op_size_16 else 4

    if pos > max_pos:
        return (0, -1, -1)

    return (pos - start, rip_disp_off, rel32_disp_off)


# --- self-test: walk loader and count instructions ---

if __name__ == '__main__':
    import sys, struct
    sys.path.insert(0, 'tools')
    from pack_proto import parse_pe, parse_pdata, section_bytes

    pe = parse_pe(sys.argv[1] if len(sys.argv) > 1 else 'loader_peb1.exe')
    code_secs = [s for s in pe['sections'] if s['is_code']]

    all_call_e8 = []
    all_jmp_e9 = []
    all_jcc = []
    all_lea_rip = []
    all_mov_rip = []
    decode_failures = []

    for sec in code_secs:
        sb = section_bytes(pe, sec)
        L = len(sb)
        pos = 0
        while pos < L:
            length, rip_off, rel32_off = decode(sb, pos, L)
            if length == 0:
                decode_failures.append((sec['name'], pos, sb[pos:pos+8].hex()))
                pos += 1
                continue
            # Identify which opcode
            # Walk through prefixes to find opcode
            scan = pos
            # skip legacy + REX prefixes
            while scan < pos + length and sb[scan] in (0x26,0x2E,0x36,0x3E,0x64,0x65,0x66,0x67,0xF0,0xF2,0xF3):
                scan += 1
            if scan < pos + length and 0x40 <= sb[scan] <= 0x4F:
                scan += 1
            if scan < pos + length:
                op = sb[scan]
                if op == 0xE8:
                    all_call_e8.append((sec, pos, rel32_off))
                elif op == 0xE9:
                    all_jmp_e9.append((sec, pos, rel32_off))
                elif op == 0x0F and scan + 1 < pos + length and (sb[scan+1] & 0xF0) == 0x80:
                    all_jcc.append((sec, pos, rel32_off))
                elif op == 0x8D and rip_off >= 0:
                    all_lea_rip.append((sec, pos, rip_off))
                elif op in (0x88,0x89,0x8A,0x8B) and rip_off >= 0:
                    all_mov_rip.append((sec, pos, op, rip_off))
            pos += length

    print(f"Decode failures: {len(decode_failures)}")
    for sec, pos, bs in decode_failures[:20]:
        print(f"  [{sec}] 0x{pos:05X}: bytes={bs}")
    print(f"E8 CALLs:  {len(all_call_e8)}")
    print(f"E9 JMPs:   {len(all_jmp_e9)}")
    print(f"0F 8x Jccs: {len(all_jcc)}")
    print(f"LEAs w/ RIP-rel: {len(all_lea_rip)}")
    print(f"MOVs w/ RIP-rel: {len(all_mov_rip)}")

    # Cross-section check
    def section_of_rva(rva):
        for s in pe['sections']:
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                return s
        return None

    cross_call = 0
    for sec, pos, rel_off in all_call_e8:
        inst_rva = sec['vaddr'] + pos
        disp = struct.unpack_from('<i', section_bytes(pe, sec), pos + rel_off)[0]
        target = (inst_rva + 5 + disp) & 0xFFFFFFFF
        tgt_sec = section_of_rva(target)
        if tgt_sec and tgt_sec['name'] != sec['name']:
            cross_call += 1
    print(f"Cross-section E8 CALLs: {cross_call}")

    cross_lea = 0
    for sec, pos, rip_off in all_lea_rip:
        inst_rva = sec['vaddr'] + pos
        sb = section_bytes(pe, sec)
        # Find inst length - actually we have rip_off, disp is at rip_off
        # The instruction ends at pos + length where length we lost; let's recompute
        length, _, _ = decode(sb, pos, len(sb))
        disp = struct.unpack_from('<i', sb, pos + rip_off)[0]
        target = (inst_rva + length + disp) & 0xFFFFFFFF
        tgt_sec = section_of_rva(target)
        if tgt_sec and tgt_sec['name'] != sec['name']:
            cross_lea += 1
    print(f"Cross-section LEAs: {cross_lea}")

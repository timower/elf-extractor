#!/usr/bin/env python3

import lief
import capstone

import re
import sys
import argparse
from dataclasses import dataclass, field
from collections import defaultdict

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# Utilities
def is_return(inst):
    if inst.mnemonic == "bx" and inst.op_str == "lr":
        return True

    if inst.mnemonic == "pop" and "pc" in inst.op_str:
        return True

    if inst.mnemonic == "ldr" and inst.op_str.startswith("pc"):
        return True

    return False


def is_branch(inst):
    return capstone.CS_GRP_JUMP in inst.groups

def is_branch_reg(inst):
    return inst.mnemonic.startswith("bx") or inst.mnemonic.startswith("blx")

def is_call(inst):
    return inst.mnemonic.startswith("bl") or inst.mnemonic.startswith("blx")

def is_pic_add(inst):
    if len(inst.operands) != 3:
        return False
    op1 = inst.operands[0]
    op2 = inst.operands[1]
    op3 = inst.operands[2]

    reg_type = capstone.arm.ARM_OP_REG

    return inst.mnemonic == "add" and \
            op1.type == reg_type and \
            op2.type == reg_type and \
            op3.type == reg_type and \
            op1.value.reg == op3.value.reg and \
            op2.value.reg == capstone.arm.ARM_REG_PC

def is_plt(section):
    return section.name == ".plt"

def is_data(section):
    return section.name == ".data" or section.name == ".rodata"

def is_bss(section):
    return section.name == ".bss"

def is_text(section):
    return section.name == ".text"


def ror(n, rotations, width):
    return (2 ** width - 1) & (n >> rotations | n << (width - rotations))

def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

def to_i32(content):
    assert len(content) == 4
    val = content[3] << 24 | content[2] << 16 | content[1] << 8 | content[0]
    return sign_extend(val, 32)


# Binary model
class Binary:
    def __init__(self, lief_binary):
        self.lief_binary = lief_binary

        # TODO: base on ELF header, ARM vs Thumb
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.cs.detail = True

    def get_entry(self):
        return self.lief_binary.header.entrypoint

    def read_i32(self, va):
        return to_i32(self.lief_binary.get_content_from_virtual_address(va, 4))

    def decode_plt(self, content, va):
        content = content[:4*3] # PLT is 3 instructions
        instrs = list(self.cs.disasm(content, va))

        # add ip, pc, #offset, (#offset)
        assert instrs[0].mnemonic == "add"
        # add ip, ip, #offset, (#offset)
        assert instrs[1].mnemonic == "add"
        # ldr pc, [ip, #offset]!
        assert instrs[2].mnemonic == "ldr"

        def get_add_imm(inst):
            if len(inst.operands) == 3:
                assert inst.operands[2].type == capstone.arm.ARM_OP_IMM
                return inst.operands[2].value.imm

            assert len(inst.operands) == 4
            op1 = inst.operands[2].value.imm
            op2 = inst.operands[3].value.imm
            return ror(op1, op2, 32)

        offset1 = get_add_imm(instrs[0])
        offset2 = get_add_imm(instrs[1])

        assert instrs[2].operands[1].type == capstone.arm.ARM_OP_MEM
        offset3 = instrs[2].operands[1].value.mem.disp

        got_addr = va + 8 + offset1 + offset2 + offset3

        relocation = self.lief_binary.get_relocation(got_addr)
        assert relocation.has_symbol and relocation.addend == 0
        return relocation.symbol

    def is_plt_addr(self, addr):
        return is_plt(self.lief_binary.section_from_virtual_address(addr))

    def is_end_of_function(self, inst):
        if is_return(inst):
            return True

        # Tail call to plt function
        if inst.mnemonic == "b": # and self.is_plt_addr(inst.operands[0].value.imm):
            return True

        return False

def dictdict(*args, **kwargs):
    return defaultdict(dict, *args, **kwargs)

@dataclass
class DisAsmCtx:
    binary: Binary

    addresses: list
    instructions: dict = field(default_factory=dict)
    labels: dict = field(default_factory=dict)

    data_in_code: dict = field(default_factory=dict)
    reg_state: dict = field(default_factory=dict)

    # data sections to emit
    data_labels: dictdict = field(default_factory=dictdict)

    def reset_state(self):
        self.reg_state = {}

    def get_label(self, address):
        section = self.binary.lief_binary.section_from_virtual_address(address)
        if is_plt(section):
            offset = address - section.virtual_address
            assert offset > 0
            content = bytes(section.content[offset:])

            return self.binary.decode_plt(content, address).name

        assert is_text(section)

        if address in self.labels:
            return self.labels[address]

        label = f".L{hex(address)}"
        self.labels[address] = label
        self.addresses.append(address)
        return label

    def get_data_label(self, section, address):
        offset = address - section.virtual_address
        section_labels = self.data_labels[section]

        if offset in section_labels:
            return section_labels[offset]

        name = f".Ldata{hex(address)}"
        section_labels[offset] = name
        return name

    def handle_pc_ldr(self, inst, label):
        assert inst.operands[0].type == capstone.arm.ARM_OP_REG
        self.reg_state[inst.operands[0].value.reg] = label

    def inst_to_str(self, inst):
        default = f"{inst.mnemonic} {inst.op_str}"
        if len(inst.operands) == 0:
            return default

        last_op = inst.operands[-1]
        if last_op.type == capstone.arm.ARM_OP_MEM and \
                last_op.mem.base == capstone.arm.ARM_REG_PC:

            if last_op.mem.index != 0:
                # ldr rx, [ry, pc] handled by pic data refs
                return default

            op_va = inst.address + last_op.mem.disp + 8
            op_value = self.binary.read_i32(op_va)

            name = f".LDIC{hex(op_va)}"
            self.data_in_code[name] = op_value

            if inst.mnemonic == "ldr":
                self.handle_pc_ldr(inst, name)

            return re.sub(r'\[.*\]', name, default)

        return default

def disassemble_at(binary, address, name=None):
    if name is None:
        name = "extracted_func"

    # TODO: branch to other section?
    section = binary.lief_binary.section_from_virtual_address(address)
    eprint(f"Extracting function @ {hex(address)} in {section.name}\n")

    ctx = DisAsmCtx(binary, [address])
    ctx.labels[address] = name

    while len(ctx.addresses) != 0:
        cur_va = ctx.addresses.pop()
        if cur_va in ctx.instructions:
            continue

        section = binary.lief_binary.section_from_virtual_address(cur_va)
        offset = cur_va - section.virtual_address
        assert offset > 0

        content = bytes(section.content[offset:])

        if is_plt(section):
            continue

        ctx.reset_state()

        for inst in binary.cs.disasm(content, cur_va):
            if (is_branch_reg(inst) and \
                    inst.operands[0].value.reg != capstone.arm.ARM_REG_LR) or \
               (len(inst.operands) > 1 and \
                    inst.operands[0].value.reg == capstone.arm.ARM_REG_PC):
                print(f"TODO: indirect branch {inst}")

            if is_branch(inst) and not is_branch_reg(inst):
                target_addr = inst.operands[0].value.imm
                label = ctx.get_label(target_addr)
                ctx.instructions[inst.address] = f"{inst.mnemonic} {label}"
            else:
                ctx.instructions[inst.address] = ctx.inst_to_str(inst)

            if is_pic_add(inst):
                reg = inst.operands[2].value.reg
                assert reg in ctx.reg_state

                pic_name = ctx.reg_state[reg]
                pic_va = ctx.data_in_code[pic_name] + inst.address + 8
                pic_label = ctx.get_label(inst.address)

                pic_section = binary.lief_binary.section_from_virtual_address(pic_va)
                if is_data(pic_section) or is_bss(pic_section):
                    data_label = ctx.get_data_label(pic_section, pic_va)
                    ctx.data_in_code[pic_name] = f"{data_label} - ({pic_label} + 8)"
                elif is_text(pic_section):
                    label = ctx.get_label(pic_va)
                    ctx.data_in_code[pic_name] = f"{label} - ({pic_label} + 8)"
                else:
                    print(f"TODO PIC ref @ {hex(inst.address)}: {pic_name} -> {hex(pic_va)}")

            if binary.is_end_of_function(inst):
                break

    print(f".global {name}")
    for addr in sorted(ctx.instructions):
        inst = ctx.instructions[addr]
        if addr in ctx.labels:
            print(f"\n{ctx.labels[addr]}:")
        print(inst)

    print()

    # TODO: interleave with instructions
    for name, val in ctx.data_in_code.items():
        print(f"{name}:")
        print(f".word {val}")

    print()

    for section, labels in ctx.data_labels.items():
        label_offsets = list(sorted(labels))
        first_offset = label_offsets[0]

        print(f".section {section.name}")
        if is_bss(section):
            for i in range(len(label_offsets)):
                offset = label_offsets[i]

                next_offset = section.size
                if i < len(label_offsets) - 1:
                    next_offset = label_offsets[i + 1]

                print(f"{labels[offset]}:")
                print(f".fill {next_offset - offset}")
        else:
            content = section.content
            for i in range(first_offset, section.size):
                if i in label_offsets:
                    print(f"{labels[i]}:")
                print(f".byte {content[i]}")

        print()


# Tool
def main(args):
    binary = Binary(lief.parse(args.input))

    address = binary.get_entry()

    if args.address:
        address = args.address
    elif args.symbol:
        symbol = binary.lief_binary.get_symbol(args.symbol)
        address = symbol.value

    disassemble_at(binary, address, args.name)


if __name__ == "__main__":
    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=str, help="Input binary")

    parser.add_argument('--address', type=auto_int, help="Address of func to extract")
    parser.add_argument('--symbol', type=str, help="Symbol of func to extract")

    parser.add_argument('--name', type=str, help="Name of extracted function")

    main(parser.parse_args())

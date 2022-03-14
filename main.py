#!/usr/bin/env python3

import lief
import capstone

import re
import sys
import argparse
from dataclasses import dataclass, field
from collections import defaultdict

GOT_NAME = "_GLOBAL_OFFSET_TABLE_"

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
    """ add r3, pc, r """
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

def is_pic_load(inst):
    """
      ldr r3, [r4, r3]
      with r4 == got, r3 == got offset
      or r4 == pc, r3 == PIC offset
    """
    if len(inst.operands) != 2:
      return False
    op1 = inst.operands[0]
    op2 = inst.operands[1]

    reg_type = capstone.arm.ARM_OP_REG
    mem_type = capstone.arm.ARM_OP_MEM

    return inst.mnemonic == "ldr" and \
            op1.type == reg_type and op2.type == mem_type and \
            op2.value.mem.disp == 0 and op2.value.mem.index != 0
            # and \
            # ((op2.value.mem.base == capstone.arm.ARM_REG_PC and \
            #   op2.value.mem.disp == 0)) #  or \


def is_plt(section):
    return section.name == ".plt"

def is_data(section):
    return section.name == ".data" or section.name == ".rodata"

def is_bss(section):
    return section.name == ".bss"

def is_got(section):
    return section.name == ".got"

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
        sect = self.lief_binary.section_from_virtual_address(va)
        if sect.name == ".bss":
            return 0
        return to_i32(self.lief_binary.get_content_from_virtual_address(va, 4))

    def get_symbol(self, got_addr):
        relocation = self.lief_binary.get_relocation(got_addr)
        assert relocation.has_symbol and relocation.addend == 0
        return relocation.symbol

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
        return self.get_symbol(got_addr)

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
    new_reg_state: dict = field(default_factory=dict)

    # data sections to emit
    data_labels: dictdict = field(default_factory=dictdict)

    def reset_state(self):
        self.reg_state = {}

    def update_reg_state(self, inst):
        # Reset regs in reg state
        regs_read, regs_write = inst.regs_access()
        for reg in regs_write:
            if reg in self.reg_state:
                del self.reg_state[reg]

        for reg in self.new_reg_state:
            self.reg_state[reg] = self.new_reg_state[reg]

        self.new_reg_state = {}

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
        self.addresses.append((address, self.reg_state.copy())) # TODO: new reg state?
        return label

    def get_data_label(self, section, address):
        offset = address - section.virtual_address
        section_labels = self.data_labels[section]

        if offset in section_labels:
            return section_labels[offset]

        name = f".Ldata{hex(address)}"
        # for i in range(0, min(0x100, section.size - offset), 4):
        #     test_addr = self.binary.read_i32(address + i)
        #     try:
        #         sect = self.binary.lief_binary.section_from_virtual_address(test_addr)
        #         if sect.virtual_address != 0:
        #             print(f"TODO: ref in data? {name} + {hex(i)}-> {hex(test_addr)} {sect.name}")
        #     except:
        #         pass
        section_labels[offset] = name
        return name

    def handle_pc_ldr(self, inst, label):
        assert inst.operands[0].type == capstone.arm.ARM_OP_REG
        self.new_reg_state[inst.operands[0].value.reg] = label

    def handle_pic_ref(self, address, reg):
        assert reg in self.reg_state

        pic_name = self.reg_state[reg]
        pic_va = self.data_in_code[pic_name] + address + 8
        pic_label = self.get_label(address)

        pic_section = self.binary.lief_binary.section_from_virtual_address(pic_va)
        if is_data(pic_section) or is_bss(pic_section):
            data_label = self.get_data_label(pic_section, pic_va)
            self.data_in_code[pic_name] = f"{data_label} - ({pic_label} + 8)"
        elif is_text(pic_section):
            label = self.get_label(pic_va)
            self.data_in_code[pic_name] = f"{label} - ({pic_label} + 8)"
        elif is_got(pic_section):
            assert pic_section.virtual_address == pic_va
            self.data_in_code[pic_name] = f"{GOT_NAME} - ({pic_label} + 8)"
            self.new_reg_state[reg] = GOT_NAME # TODO: reg state?
        else:
            print(f"TODO PIC ref @ {hex(inst.address)}: {pic_name} -> {hex(pic_va)}")

    def inst_to_str(self, inst):
        default = f"{inst.mnemonic} {inst.op_str}"
        if len(inst.operands) == 0:
            return default

        last_op = inst.operands[-1]
        if last_op.type == capstone.arm.ARM_OP_MEM and \
                last_op.mem.base == capstone.arm.ARM_REG_PC:

            if last_op.mem.index != 0:
                # ldr rx, [ry, pc] handle by `handle_pic_ref`
                return default

            op_va = inst.address + last_op.mem.disp + 8
            op_value = self.binary.read_i32(op_va)

            name = f".LDIC{hex(op_va)}"
            self.data_in_code[name] = op_value

            if inst.mnemonic == "ldr":
                self.handle_pc_ldr(inst, name)

            return re.sub(r'\[.*\]', name, default)

        return default

    def get_jump_table_size(self, inst, prev_inst):
        """
            cmp r3, #5
            addls pc, pc, r3, lsl #
        """
        if inst.mnemonic != "addls" or len(inst.operands) != 3:
            return None

        if prev_inst is None or prev_inst.mnemonic != "cmp" or len(prev_inst.operands) != 2:
            return None

        op1 = inst.operands[0]
        op2 = inst.operands[1]
        op3 = inst.operands[2]

        prev_op1 = prev_inst.operands[0]
        prev_op2 = prev_inst.operands[1]

        reg_type = capstone.arm.ARM_OP_REG
        if op1.type != reg_type or op2.type != reg_type or op3.type != reg_type or \
                prev_op1.type != reg_type or prev_op2.type != capstone.arm.ARM_OP_IMM:
            return None

        pc_reg = capstone.arm.ARM_REG_PC
        if op1.value.reg != pc_reg or op2.value.reg != pc_reg:
            return None

        if op3.value.reg != prev_op1.value.reg:
            return None

        if op3.shift.type != capstone.arm.ARM_SFT_LSL or op3.shift.value != 2:
            return None

        return prev_op2.value.imm


def disassemble_at(binary, address, name=None):
    if name is None:
        name = "extracted_func"

    # TODO: branch to other section?
    section = binary.lief_binary.section_from_virtual_address(address)
    eprint(f"Extracting function @ {hex(address)} in {section.name}\n")

    ctx = DisAsmCtx(binary, [(address, {})])
    ctx.labels[address] = name

    while len(ctx.addresses) != 0:
        cur_va, cur_state = ctx.addresses.pop()
        if cur_va in ctx.instructions:
            continue

        ctx.reg_state = cur_state

        section = binary.lief_binary.section_from_virtual_address(cur_va)
        offset = cur_va - section.virtual_address
        assert offset > 0

        content = bytes(section.content[offset:])

        if is_plt(section):
            continue

        prev_inst = None
        for inst in binary.cs.disasm(content, cur_va):
            jump_table_size = ctx.get_jump_table_size(inst, prev_inst)
            if jump_table_size is None and ((is_branch_reg(inst) and \
                    inst.operands[0].value.reg != capstone.arm.ARM_REG_LR) or \
               (len(inst.operands) > 1 and \
                    inst.operands[0].value.reg == capstone.arm.ARM_REG_PC)):
                print(f"TODO: indirect branch {inst}")

            if is_branch(inst) and not is_branch_reg(inst):
                target_addr = inst.operands[0].value.imm
                label = ctx.get_label(target_addr)
                ctx.instructions[inst.address] = f"{inst.mnemonic} {label}"
            else:
                ctx.instructions[inst.address] = ctx.inst_to_str(inst)

            if jump_table_size is not None:
                ctx.addresses.extend([(inst.address + 8 + i * 4, ctx.reg_state.copy()) for i in range(jump_table_size + 1)])

            if is_pic_add(inst):
                reg = inst.operands[2].value.reg
                ctx.handle_pic_ref(inst.address, reg)

            if is_pic_load(inst):
                mem_op = inst.operands[1]
                base_reg = mem_op.value.mem.base
                idx_reg = mem_op.value.mem.index

                if base_reg == capstone.arm.ARM_REG_PC and idx_reg in ctx.reg_state:
                    ctx.handle_pic_ref(inst.address, idx_reg)
                elif base_reg in ctx.reg_state and ctx.reg_state[base_reg] == GOT_NAME and idx_reg in ctx.reg_state:
                    offset_name = ctx.reg_state[idx_reg]
                    offset_val = ctx.data_in_code[offset_name]

                    got_section = binary.lief_binary.get_section(".got")
                    got_addr = got_section.virtual_address + offset_val
                    got_val = binary.read_i32(got_addr)

                    if got_val == 0:
                        data_label = binary.get_symbol(got_addr).name
                    else:
                        data_section = binary.lief_binary.section_from_virtual_address(got_val)
                        data_label = ctx.get_data_label(data_section, got_val)

                    ctx.data_in_code[offset_name] = f"{data_label}(GOT)"
                elif idx_reg in ctx.reg_state and ctx.reg_state[idx_reg] == GOT_NAME:
                    print("TODO: idx GOT ref")

            ctx.update_reg_state(inst)

            if binary.is_end_of_function(inst):
                break

            prev_inst = inst

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

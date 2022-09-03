#!/usr/bin/env python3

import lief
import capstone

import sys
import argparse


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def ror(n, rotations, width):
    return (2**width - 1) & (n >> rotations | n << (width - rotations))


# TODO: where to put this?
def is_terminator(label):
    if label == "exit":
        return True
    if label == "abort":
        return True
    if "__throw_" in label:
        return True
    return False


class SectionInfo:
    @staticmethod
    def is_plt(section):
        return section.name == ".plt"

    @staticmethod
    def is_data(section):
        return section.name == ".data" or section.name == ".rodata"

    @staticmethod
    def is_bss(section):
        return section.name == ".bss"

    @staticmethod
    def is_got(section):
        return section.name == ".got"

    @staticmethod
    def is_text(section):
        return section.name == ".text"


class InstrInfo:
    instruction_size = 4

    @staticmethod
    def is_return(inst):
        if inst.mnemonic == "bx" and inst.op_str == "lr":
            return True

        if inst.mnemonic == "pop" and "pc" in inst.op_str:
            return True

        if inst.mnemonic == "ldr" and inst.op_str.startswith("pc"):
            return True

        return False

    @staticmethod
    def is_branch(inst):
        return capstone.CS_GRP_JUMP in inst.groups

    @staticmethod
    def is_branch_reg(inst):
        return inst.mnemonic.startswith("bx") or inst.mnemonic.startswith("blx")

    @staticmethod
    def is_call(inst):
        return inst.mnemonic.startswith("bl") or inst.mnemonic.startswith("blx")

    @staticmethod
    def is_end_of_block(inst):
        if InstrInfo.is_return(inst):
            return True

        # Tail call function
        if inst.mnemonic == "b":
            return True

        return False

    @staticmethod
    def is_pic_add(inst):
        """add r3, pc, r"""
        if len(inst.operands) != 3:
            return False
        op1 = inst.operands[0]
        op2 = inst.operands[1]
        op3 = inst.operands[2]

        reg_type = capstone.arm.ARM_OP_REG

        return (
            inst.mnemonic == "add"
            and op1.type == reg_type
            and op2.type == reg_type
            and op3.type == reg_type
            and op1.value.reg == op3.value.reg
            and op2.value.reg == capstone.arm.ARM_REG_PC
        )

    @staticmethod
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

        return (
            inst.mnemonic == "ldr"
            and op1.type == reg_type
            and op2.type == mem_type
            and op2.value.mem.disp == 0
            and op2.value.mem.index != 0
        )
        # and \
        # ((op2.value.mem.base == capstone.arm.ARM_REG_PC and \
        #   op2.value.mem.disp == 0)) #  or \

    @staticmethod
    def decode_plt(instrs):
        plt_size = 3
        if len(instrs) < plt_size:
            return None

        # add ip, pc, #offset, (#offset)
        if instrs[0].mnemonic != "add":
            return None
        # add ip, ip, #offset, (#offset)
        if instrs[1].mnemonic != "add":
            return None
        # ldr pc, [ip, #offset]!
        if instrs[2].mnemonic != "ldr":
            return None

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

        if instrs[2].operands[1].type != capstone.arm.ARM_OP_MEM:
            return None
        offset3 = instrs[2].operands[1].value.mem.disp

        got_addr = instrs[0].address + 8 + offset1 + offset2 + offset3
        return got_addr, plt_size


class Binary:
    def __init__(self, lief_binary):
        self.lief_binary = lief_binary

        # TODO: base on ELF header, ARM vs Thumb
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self.cs.detail = True

    def get_entry(self):
        return self.lief_binary.header.entrypoint

    def get_section_offset(self, address):
        section = self.lief_binary.section_from_virtual_address(address)
        offset = address - section.virtual_address
        assert offset >= 0
        return section, offset

    def get_got_symbol(self, got_addr):
        relocation = self.lief_binary.get_relocation(got_addr)
        assert relocation.has_symbol and relocation.addend == 0
        return relocation.symbol


class Instruction:
    def __init__(self, cs_inst, target_label=None):
        self.cs_inst = cs_inst
        self.target_label = target_label

    def dump(self):
        if self.target_label is not None and InstrInfo.is_branch(self.cs_inst):
            print(f"{self.cs_inst.mnemonic} {self.target_label}")
        else:
            print(f"{self.cs_inst.mnemonic} {self.cs_inst.op_str}")


class BinaryCtx:
    def __init__(self, binary):
        self.binary = binary

        self.addresses = []  # list of address, state pairs
        self.labels = {}  # address -> name map
        self.instructions = {}  # address -> instruction map

        self.reg_state = {}  # current register state

        self.section_instructions = {}

    def get_instructions(self, section):
        if section.virtual_address in self.section_instructions:
            return self.section_instructions[section.virtual_address]

        content = bytes(section.content)
        instructions = []
        while len(instructions) < len(content) // InstrInfo.instruction_size:
            offset = len(instructions) * InstrInfo.instruction_size
            new_instrs = list(
                self.binary.cs.disasm(
                    content[offset:], section.virtual_address + offset
                )
            )
            if len(new_instrs) == 0:
                instructions.append(None)
            else:
                instructions.extend(new_instrs)

        self.section_instructions[section.virtual_address] = instructions
        return instructions

    def add_address(self, address, name=None):
        self.addresses.append((address, {}))
        if name is not None:
            self.labels[address] = name

    def get_label(self, address):
        if address in self.labels:
            return self.labels[address]

        label = f".L{hex(address)}"
        self.labels[address] = label
        return label

    def decode_plt(self):
        plt_section = self.binary.lief_binary.get_section(".plt")
        if plt_section is None:
            return
        content = bytes(plt_section.content)
        plt_address = plt_section.virtual_address
        instrs = list(self.binary.cs.disasm(content, plt_address))

        offset = 0
        while offset < len(instrs):
            got_info = InstrInfo.decode_plt(instrs[offset:])
            if got_info is None:
                offset += 1
                continue

            got_addr, size = got_info
            symbol = self.binary.get_got_symbol(got_addr).name
            address = instrs[offset].address
            self.labels[address] = symbol
            offset += size

    def disassemble(self):
        while len(self.addresses) != 0:
            virt_address, self.reg_state = self.addresses.pop()
            if virt_address in self.instructions:
                continue
            # eprint(f"Disasm @ {hex(virt_address)}")

            section, offset = self.binary.get_section_offset(virt_address)

            if SectionInfo.is_plt(section):
                continue

            instructions = self.get_instructions(section)
            instr_offset = offset // InstrInfo.instruction_size

            prev_inst = None
            for inst in instructions[instr_offset:]:
                if inst is None:
                    print(prev_inst)
                    break

                # TODO: jump tables

                if InstrInfo.is_branch(inst) and not InstrInfo.is_branch_reg(inst):
                    target_addr = inst.operands[0].value.imm
                    label = self.get_label(target_addr)

                    self.instructions[inst.address] = Instruction(
                        inst, target_label=label
                    )

                    if is_terminator(label):
                        break

                    self.addresses.append((target_addr, self.reg_state.copy()))

                else:
                    self.instructions[inst.address] = Instruction(inst)

                if InstrInfo.is_end_of_block(inst):
                    break

                prev_inst = inst

    def dump(self):
        print(".syntax unified")

        for addr in sorted(
            self.instructions.keys()
        ):  # | ctx.data_in_code_addr.keys()):
            if addr in self.labels:
                print(f"\n{self.labels[addr]}:")

            if addr in self.instructions:
                print("  ", end="")
                self.instructions[addr].dump()

            # if addr in ctx.data_in_code_addr:
            #     name = ctx.data_in_code_addr[addr]
            #     val = ctx.data_in_code[name]
            #     print(f"\n{name}:")
            #     print(f".word {val}")


def main(args):
    binary = Binary(lief.parse(args.input))
    ctx = BinaryCtx(binary)

    ctx.add_address(binary.get_entry(), "entry0")
    for symbol in binary.lief_binary.functions:
        ctx.add_address(symbol.value, symbol.name if symbol.name != "" else None)

    eprint("Decoding plt")
    ctx.decode_plt()
    eprint("Disassembling")
    ctx.disassemble()

    ctx.dump()


if __name__ == "__main__":

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="Input binary")

    # parser.add_argument(
    #     "--address", type=auto_int, help="Address of func to extract", action="append"
    # )
    # parser.add_argument(
    #     "--name", type=str, help="Name of extracted function", action="append"
    # )

    # parser.add_argument(
    #     "--symbol", type=str, help="Symbol of func to extract", action="append"
    # )

    main(parser.parse_args())

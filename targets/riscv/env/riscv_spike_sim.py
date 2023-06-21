# Copyright 2011-2021 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Docstring
"""

# Futures
from __future__ import absolute_import

# Own modules
from microprobe.code.address import InstructionAddress
from microprobe.target.env import GenericEnvironment
from microprobe.code.context import Context

# Constants

# Functions

# Classes


class riscv64_spike_sim(GenericEnvironment):
    _elf_code = "" "" ""

    def __init__(self, isa):
        super().__init__(
            "riscv64_spike_sim",
            "RISC-V architecture (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa,
            little_endian=True,
        )

        self._default_wrapper = "CWrapper"

        # TODO: should define this ISA-wide, maybe as a new operand?

        self._CSR_MSTATUS = 0x300
        self._MSTATUS_FS = 0x00006000
        self._MSTATUS_XS = 0x00018000
        self._CSR_MTVEC = 0x305

    @property
    def stack_pointer(self):
        """ """
        return self.isa.registers["X2"]

    @property
    def stack_direction(self):
        """ """
        return "increase"

    def elf_abi(self, stack_size, start_symbol, **kwargs):
        return super(riscv64_spike_sim, self).elf_abi(
            stack_size, start_symbol, stack_alignment=16, **kwargs
        )

    def function_call(self, target, return_address_reg=None, long_jump=False):
        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["X1"]

        if isinstance(target, str):
            target = InstructionAddress(base_address=target)

        if long_jump:
            assert isinstance(target, int)
            instrs = self.target.set_register(
                return_address_reg, target, Context()
            )

            jalr_ins = self.target.new_instruction("JALR_V0")
            jalr_ins.set_operands([0, return_address_reg, return_address_reg])
            jalr_ins.add_comment("Long jump to address 0X%016X" % target)

            instrs.append(jalr_ins)
            return instrs

        else:
            jal_ins = self.target.new_instruction("JAL_V0")
            jal_ins.set_operands([target, return_address_reg])
            return [jal_ins]

    def function_return(self, return_address_reg=None):
        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["X1"]

        ret_ins = self.target.new_instruction("JALR_V0")
        ret_ins.set_operands(
            [0, return_address_reg, self.target.isa.registers["X0"]]
        )
        return [ret_ins]

    @property
    def volatile_registers(self):
        rlist = []

        for idx in [
            1,
            3,
            4,
            5,
            6,
            7,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            28,
            29,
            30,
            31,
        ]:
            rlist += [self.target.registers["X%d" % idx]]

        for idx in [
            0,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            28,
            29,
            30,
            31,
        ]:
            rlist += [self.target.registers["F%d" % idx]]

        return rlist

    def hook_test_init_instructions(self):
        context = Context()
        instructions = []

        # Setup MSTATUS CSR

        status = self._MSTATUS_FS | self._MSTATUS_XS
        instructions += self.target.set_register(
            self.target.isa.registers["X5"], status, context
        )

        ins = self.target.new_instruction("CSRRW_V0")
        ins.set_operands(
            [
                self._CSR_MSTATUS,
                self.target.isa.registers["X5"],
                self.target.isa.registers["X0"],
            ]
        )
        instructions.append(ins)

        # Setup trap handler CSR

        tvec = 0x10000
        instructions += self.target.set_register(
            self.target.isa.registers["X5"], tvec, context
        )

        ins = self.target.new_instruction("CSRRW_V0")
        ins.set_operands(
            [
                self._CSR_MTVEC,
                self.target.isa.registers["X5"],
                self.target.isa.registers["X0"],
            ]
        )
        instructions.append(ins)

        # tohost address
        instructions += self.target.set_register(
            self.target.isa.registers["X1"], 0x11000, context
        )

        # Init itercount to 10
        instructions += self.target.set_register(
            self.target.isa.registers["X2"], 10, context
        )

        # Save itercount (2 long word offset from tohost)
        ins = self.target.new_instruction("SD_V0")
        ins.set_operands(
            [
                16,
                self.target.isa.registers["X2"],
                self.target.isa.registers["X1"],
                0,
            ]
        )
        instructions.append(ins)

        return instructions

    def hook_before_test_instructions(self):
        return []

    def hook_after_test_instructions(self):
        return []

    def hook_after_reset_instructions(self):
        context = Context()
        instructions = []

        # tohost address
        instructions += self.target.set_register(
            self.target.isa.registers["X5"], 0x11000, context
        )

        # load itercount (2 long word offset from tohost)
        ins = self.target.new_instruction("LD_V0")
        ins.set_operands(
            [
                16,
                self.target.isa.registers["X5"],
                self.target.isa.registers["X6"],
            ]
        )
        instructions.append(ins)

        # We performed one iteration, subtract by 1
        ins = self.target.new_instruction("ADDI_V0")
        ins.set_operands(
            [
                -1,
                self.target.isa.registers["X6"],
                self.target.isa.registers["X6"],
            ]
        )
        instructions.append(ins)

        # Save itercount
        ins = self.target.new_instruction("SD_V0")
        ins.set_operands(
            [
                16,
                self.target.isa.registers["X6"],
                self.target.isa.registers["X5"],
                0,
            ]
        )
        instructions.append(ins)

        # Skip tohost write if counter != 0
        ins = self.target.new_instruction("BNE_V0")
        ins.set_operands(
            [
                16,
                self.target.isa.registers["X0"],
                self.target.isa.registers["X6"],
                0,
            ]
        )
        instructions.append(ins)

        # exit code = 0
        instructions += self.target.set_register(
            self.target.isa.registers["X6"], 1, context
        )

        # write tohost
        ins = self.target.new_instruction("SD_V0")
        ins.set_operands(
            [
                0,
                self.target.isa.registers["X6"],
                self.target.isa.registers["X5"],
                0,
            ]
        )
        instructions.append(ins)

        return instructions

    def hook_test_end_instructions(self):
        context = Context()
        instructions = []

        # tohost address
        instructions += self.target.set_register(
            self.target.isa.registers["X1"], 0x11000, context
        )

        # exit code = 0
        instructions += self.target.set_register(
            self.target.isa.registers["X2"], 1, context
        )

        # write tohost
        ins = self.target.new_instruction("SD_V0")
        ins.set_operands(
            [
                0,
                self.target.isa.registers["X2"],
                self.target.isa.registers["X1"],
                0,
            ]
        )
        instructions.append(ins)

        return instructions

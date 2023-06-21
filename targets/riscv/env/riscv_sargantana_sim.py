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


class riscv64_sargantana_sim(GenericEnvironment):
    _elf_code = "" "" ""

    def __init__(self, isa):
        super().__init__(
            "riscv64_sargantana_sim",
            "RISC-V architecture (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa,
            little_endian=True,
        )

        self._default_wrapper = "CWrapper"

        # TODO: should define this ISA-wide, maybe as a new operand?

        self._CSR_MCYCLE = 0xB00
        self._CSR_MINSTRET = 0xB02
        self._CSR_MSTATUS = 0x300
        self._MSTATUS_FS = 0x00006000
        self._MSTATUS_XS = 0x00018000
        self._CSR_WRITE = 0x9F0

    @property
    def stack_pointer(self):
        """ """
        return self.isa.registers["X2"]

    @property
    def stack_direction(self):
        """ """
        return "increase"

    def elf_abi(self, stack_size, start_symbol, **kwargs):
        return super(riscv64_sargantana_sim, self).elf_abi(
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
        status = self._MSTATUS_FS | self._MSTATUS_XS
        instructions = self.target.set_register(
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

        return instructions

    def _print_reg(self, register, context):
        instructions = []

        instructions += self.target.set_register(
            self.target.isa.registers["X7"], 10, context
        )

        instructions += self.target.set_register(
            self.target.isa.registers["X28"], 9, context
        )

        ins = self.target.new_instruction("REM_V0")
        ins.set_operands(
            [
                self.target.isa.registers["X7"],
                register,
                self.target.isa.registers["X29"],
            ]
        )
        instructions.append(ins)

        ins = self.target.new_instruction("ADDI_V0")
        ins.set_operands(
            [
                48,
                self.target.isa.registers["X29"],
                self.target.isa.registers["X29"],
            ]
        )
        instructions.append(ins)

        instructions += self._print_char(
            context, register=self.target.isa.registers["X29"]
        )

        ins = self.target.new_instruction("BGE_V0")
        ins.set_operands([12, register, self.target.isa.registers["X28"], 0])
        instructions.append(ins)

        ins = self.target.new_instruction("DIV_V0")
        ins.set_operands([self.target.isa.registers["X7"], register, register])
        instructions.append(ins)

        ins = self.target.new_instruction("JAL_V0")
        ins.set_operands([-32, self.target.isa.registers["X0"]])
        instructions.append(ins)

        return instructions

    def _print_char(self, context, value=None, register=None):
        instructions = []

        source_register = self.target.isa.registers["X30"]

        assert (value is not None) or (register is not None)

        if value is not None:
            assert register is None
            instructions += self.target.set_register(
                source_register, value, context
            )
        elif register is not None:
            assert value is None
            source_register = register

        ins = self.target.new_instruction("LUI_V0")
        ins.set_operands([0x00400, self.target.isa.registers["X31"]])
        instructions.append(ins)

        ins = self.target.new_instruction("ADD_V0")
        ins.set_operands(
            [
                self.target.isa.registers["X31"],
                source_register,
                self.target.isa.registers["X31"],
            ]
        )
        instructions.append(ins)

        ins = self.target.new_instruction("SLLI_V0")
        ins.set_operands(
            [
                8,
                self.target.isa.registers["X31"],
                self.target.isa.registers["X31"],
            ]
        )
        instructions.append(ins)

        ins = self.target.new_instruction("CSRRW_V0")
        ins.set_operands(
            [
                self._CSR_WRITE,
                self.target.isa.registers["X31"],
                self.target.isa.registers["X0"],
            ]
        )
        instructions.append(ins)

        return instructions

    def _reset_perf_counters(self):
        instructions = []

        # Reset cycle count
        ins = self.target.new_instruction("CSRRW_V0")
        ins.set_operands(
            [
                self._CSR_MCYCLE,
                self.target.isa.registers["X0"],
                self.target.isa.registers["X0"],
            ]
        )
        instructions.append(ins)

        # Reset instruction count
        ins = self.target.new_instruction("CSRRW_V0")
        ins.set_operands(
            [
                self._CSR_MINSTRET,
                self.target.isa.registers["X0"],
                self.target.isa.registers["X0"],
            ]
        )
        instructions.append(ins)

        return instructions

    def _print_perf_counters(self, sentinel1, sentinel2):
        instructions = []
        context = Context()

        # Read cycles
        ins = self.target.new_instruction("CSRRS_V0")
        ins.set_operands(
            [
                self._CSR_MCYCLE,
                self.target.isa.registers["X0"],
                self.target.isa.registers["X5"],
            ]
        )
        instructions.append(ins)

        # Read instructions
        ins = self.target.new_instruction("CSRRS_V0")
        ins.set_operands(
            [
                self._CSR_MINSTRET,
                self.target.isa.registers["X0"],
                self.target.isa.registers["X6"],
            ]
        )
        instructions.append(ins)

        # Send cycle count
        instructions += self._print_reg(
            self.target.isa.registers["X5"], context
        )

        # Send ","
        instructions += self._print_char(context, value=44)

        # Send instruction count
        instructions += self._print_reg(
            self.target.isa.registers["X6"], context
        )

        # Send "~"
        instructions += self._print_char(context, value=sentinel1)

        # Send "@"
        instructions += self._print_char(context, value=sentinel2)

        # Send "\n"
        instructions += self._print_char(context, value=10)

        return instructions

    def hook_before_test_instructions(self):
        return self._reset_perf_counters()

    def hook_after_test_instructions(self):
        return self._print_perf_counters(126, 64)  # ~@

    def hook_after_reset_instructions(self):
        return self._print_perf_counters(36, 37)  # $%

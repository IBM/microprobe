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
from microprobe.utils.misc import twocs_to_int
from microprobe.code.context import Context

# Constants

# Functions

# Classes
class riscv64_riscy_sim(GenericEnvironment):

    _elf_code = ""\
                ""\
                ""

    def __init__(self, isa):
        super().__init__(
            "riscv64_riscy_sim",
            "RISC-V architecture (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa,
            little_endian=True
            )

        self._default_wrapper = "CWrapper"

        # TODO: should define this ISA-wide, maybe as a new operand?

        self._CSR_MCYCLE = 0xb00
        self._CSR_MINSTRET = 0xb02
        self._CSR_MSTATUS = 0x300
        self._MSTATUS_FS = 0x00006000
        self._MSTATUS_XS = 0x00018000

    @property
    def stack_pointer(self):
        """ """
        return self.isa.registers["X2"]

    @property
    def stack_direction(self):
        """ """
        return "increase"

    def elf_abi(self, stack_size, start_symbol, **kwargs):

        return super(riscv64_linux_gcc, self).elf_abi(stack_size,
                                                      start_symbol,
                                                      stack_alignment=16,
                                                      **kwargs)

    def function_call(self, target,
                      return_address_reg=None,
                      long_jump=False):

        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["X1"]

        if isinstance(target, str):
            target = InstructionAddress(base_address=target)

        jal_ins = self.target.new_instruction("JAL_V0")
        jal_ins.set_operands([target, return_address_reg])

        return [jal_ins]

    def function_return(self,
                        return_address_reg=None):

        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["X1"]

        ret_ins = self.target.new_instruction("JALR_V0")
        ret_ins.set_operands([0,
                              return_address_reg,
                              self.target.isa.registers["X0"]])
        return [ret_ins]

    @property
    def volatile_registers(self):

        rlist = []

        for idx in [
                1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17,
                28, 29, 30, 31]:
            rlist += [self.target.registers['X%d' % idx]]

        for idx in [
                0, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17,
                28, 29, 30, 31]:

            rlist += [self.target.registers['F%d' % idx]]

        return rlist

    def test_start_instructions(self):
        context = Context()
        instructions = self.target.set_register(self.target.isa.registers["X5"], self._MSTATUS_FS | self._MSTATUS_XS, context)

        ins = self.target.new_instruction("CSRRW_V0")
        ins.set_operands([self._CSR_MSTATUS, self.target.isa.registers["X5"], self.target.isa.registers["X0"]])
        instructions.append(ins)

        return instructions

    def _wait_uart_free(self):
        instructions = []

        ins = self.target.new_instruction("LW_V0")
        ins.set_operands([0, self.target.isa.registers['X14'], self.target.isa.registers['X15']])
        instructions.append(ins)

        ins = self.target.new_instruction("ADDIW_V0")
        ins.set_operands([0, self.target.isa.registers['X15'], self.target.isa.registers['X15']])
        instructions.append(ins)

        ins = self.target.new_instruction("BLT_V0")
        ins.set_operands([-8, self.target.isa.registers['X0'], self.target.isa.registers['X15'], 0])
        instructions.append(ins)

        return instructions

    def _read_perf_reg(self, csr, context):
        instructions = []

        ins = self.target.new_instruction("CSRRS_V0")
        ins.set_operands([csr, self.target.isa.registers["X0"], self.target.isa.registers["X13"]])
        instructions.append(ins)

        instructions += self.target.set_register(self.target.isa.registers['X11'], 10, context)
        instructions += self.target.set_register(self.target.isa.registers['X14'], 805306368, context)
        instructions += self.target.set_register(self.target.isa.registers['X10'], 9, context)

        ins = self.target.new_instruction("REM_V0")
        ins.set_operands([self.target.isa.registers['X11'], self.target.isa.registers['X13'], self.target.isa.registers['X12']])
        instructions.append(ins)

        instructions += self._wait_uart_free()

        ins = self.target.new_instruction("ADDI_V0")
        ins.set_operands([48, self.target.isa.registers['X12'], self.target.isa.registers['X12']])
        instructions.append(ins)

        ins = self.target.new_instruction("SW_V0")
        ins.set_operands([0, self.target.isa.registers['X12'], self.target.isa.registers['X14'], 0])
        instructions.append(ins)

        ins = self.target.new_instruction("BGE_V0")
        ins.set_operands([12, self.target.isa.registers['X13'], self.target.isa.registers['X10'], 0])
        instructions.append(ins)

        ins = self.target.new_instruction("DIV_V0")
        ins.set_operands([self.target.isa.registers['X11'], self.target.isa.registers['X13'], self.target.isa.registers['X13']])
        instructions.append(ins)

        ins = self.target.new_instruction("JAL_V0")
        ins.set_operands([-32, self.target.isa.registers["X0"]])
        instructions.append(ins)

        return instructions


    def test_end_instructions(self):
        instructions = []
        context = Context()

        # Send cycle count
        instructions += self._read_perf_reg(self._CSR_MCYCLE, context)

        # Send \n
        instructions += self._wait_uart_free()
        instructions += self.target.set_register(self.target.isa.registers['X15'], 44, context)

        ins = self.target.new_instruction("SW_V0")
        ins.set_operands([0, self.target.isa.registers['X15'], self.target.isa.registers['X14'], 0])
        instructions.append(ins)

        # Send instruction count
        instructions += self._read_perf_reg(self._CSR_MINSTRET, context)

        return instructions

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
from microprobe.code.context import Context
from microprobe.target.env import GenericEnvironment

# Constants

# Functions


# Classes
class riscv64_linux_gcc(GenericEnvironment):

    _elf_code = ""\
                ""\
                ""

    def __init__(self, isa):
        super(
            riscv64_linux_gcc,
            self).__init__(
            "riscv64_linux_gcc",
            "RISC-V architecture (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa,
            little_endian=True
            )

        self._default_wrapper = "CWrapper"

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

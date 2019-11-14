# Copyright 2018 IBM Corporation
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

# Constants

# Functions


# Classes
class riscv64_test_p(GenericEnvironment):

    _elf_code = ""\
                ""\
                ""

    def __init__(self, isa):
        super(
            riscv64_test_p,
            self).__init__(
            "riscv64_test_p",
            "RISC-V architecture (64bit addressing mode), "
            "Assembly using RISC-V test environment P",
            isa)

        self._default_wrapper = "RiscvTestsP"

    @property
    def stack_pointer(self):
        """ """
        return self.isa.registers["X2"]

    @property
    def stack_direction(self):
        """ """
        return "increase"

    def elf_abi(self, stack_size, start_symbol, **kwargs):

        return super(riscv64_test_p, self).elf_abi(stack_size,
                                                   start_symbol,
                                                   stack_alignment=16,
                                                   **kwargs)

    def function_call(self, target,
                      return_address_reg=None):

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

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

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
__all__ = ["ppc64_linux_gcc", "ppc64le_linux_gcc"]

# Functions


# Classes
class ppc64_common(GenericEnvironment):

    _elf_code = ""\
                ""\
                ""

    @property
    def stack_pointer(self):
        """ """
        return self.isa.registers["GPR1"]

    @property
    def stack_direction(self):
        """ """
        return "increase"

    def elf_abi(self, stack_size, start_symbol, **kwargs):

        return super(ppc64_common, self).elf_abi(stack_size,
                                                 start_symbol,
                                                 stack_alignment=16,
                                                 **kwargs)

    def function_call(self, target,
                      return_address_reg=None):

        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["LR"]

        if isinstance(target, str):
            target = InstructionAddress(base_address=target)

        bl_ins = self.target.new_instruction("BL_V0")
        bl_ins.set_operands([target])

        return [bl_ins]

    def function_return(self,
                        return_address_reg=None):

        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["LR"]

        bclr_ins = self.target.new_instruction("BCLR_V0")
        bclr_ins.set_operands([20, 0, 0])
        return [bclr_ins]

    @property
    def volatile_registers(self):

        rlist = []
        for idx in [0] + list(range(3, 13)):
            rlist += [self.target.registers['GPR%d' % idx]]

        for idx in range(0, 14):
            rlist += [self.target.registers['FPR%d' % idx]]

        for idx in list(range(0, 15)) + [19]:
            rlist += [self.target.registers['VR%d' % idx]]

        for idx in range(0, 32):
            rlist += [self.target.registers['VSR%d' % idx]]

        return rlist


class ppc64_linux_gcc(ppc64_common):

    _elf_code = ""\
                ""\
                ""

    def __init__(self, isa):
        super(
            ppc64_linux_gcc,
            self).__init__(
            "ppc64_linux_gcc",
            "POWERPC architecture BE (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa)

        self._default_wrapper = "CInfPpc"


class ppc64le_linux_gcc(ppc64_common):

    _elf_code = ""\
                ""\
                ""

    def __init__(self, isa):
        super(
            ppc64le_linux_gcc,
            self).__init__(
            "ppc64le_linux_gcc",
            "POWERPC architecture LE (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa)

        self._default_wrapper = "CInfPpc"
        self._little_endian = True

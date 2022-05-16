"""
Docstring
"""

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Built-in modules

# Third party modules

# Own modules
from microprobe.target.env import GenericEnvironment
from microprobe.code.address import InstructionAddress

# Constants

# Functions


# Classes
class x86_64_linux_gcc(GenericEnvironment):

    _elf_code = ""\
                ""\
                ""

    def __init__(self, isa):
        super(
            x86_64_linux_gcc,
            self).__init__(
            "x86_64_linux_gcc",
            "x86 architecture (64bit addressing mode), "
            "Linux operating system, GCC compiler",
            isa)

        self._default_wrapper = "CInfGen"

    @property
    def stack_pointer(self):
        """ """
        return self.isa.registers["GPR1"]

    @property
    def stack_direction(self):
        """ """
        return "increase"

    def elf_abi(self, stack_size, start_symbol, **kwargs):

        return super(x86_64_linux_gcc, self).elf_abi(stack_size,
                                                     start_symbol,
                                                     stack_alignment=16,
                                                     **kwargs)

    def function_call(self, target,
                      return_address_reg=None):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["LR"]

        if isinstance(target, str):
            target = InstructionAddress(base_address=target)

        bl_ins = self.target.new_instruction("BL_V0")
        bl_ins.set_operands([target])

        return [bl_ins] + self.function_return()

    def function_return(self,
                        return_address_reg=None):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        if return_address_reg is None:
            return_address_reg = self.target.isa.registers["LR"]

        bclr_ins = self.target.new_instruction("BCLR_V0")
        bclr_ins.set_operands([20, 0, 0])
        return[bclr_ins]

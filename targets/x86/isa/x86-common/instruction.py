# Copyright 2022 IBM Corporation
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

# Built-in modules

# Third party modules

# Own modules
from microprobe.utils.logger import get_logger
from microprobe.target.isa.instruction import GenericInstructionType
from microprobe.exceptions import MicroprobeArchitectureDefinitionError, \
    MicroprobeUncheckableEnvironmentWarning
from microprobe.target.isa.operand import OperandConst
from microprobe.target.isa.instruction import GENERIC_INSTRUCTION_CHECKS
from microprobe.code.ins import InstructionOperandValue
from microprobe.target.isa.operand import OperandDescriptor, OperandImmRange
from microprobe.utils.misc import twocs_to_int, int_to_twocs

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
LOG = get_logger(__name__)

_8BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    (2 ** 8),  # Max value
                    1,  # StepUImm1v0
                    True,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0),  # Add
    False,  # Input
    False  # Output
)

_12BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    (2 ** 12),  # Max value
                    1,  # StepUImm1v0
                    True,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0  # Add
                    ),
    False,  # Input
    False  # Output
)


# Functions

# Classes
class X86Instruction(GenericInstructionType):

    """
    X86 Instruction Class
    """

    def __init__(self, name, mnemonic, opcode, descr, iformat,
                 operands, ioperands, moperands, instruction_checks,
                 target_checks):
        super(X86Instruction, self).__init__(name, mnemonic, opcode,
                                             descr, iformat, operands,
                                             ioperands, moperands,
                                             instruction_checks,
                                             target_checks)

        if "opcode_16" in operands:

            if len(opcode) != 4:
                raise MicroprobeArchitectureDefinitionError(
                    "Unsupported opcode length in '%s' definition." % self)

            self.operands["opcode_16"][0] = OperandConst(
                "Opcode", "Instruction opcode", int(self.opcode, 16)
            )

        elif "opcode_8" in operands and "opcode_4" not in operands:

            if len(opcode) != 2:
                raise MicroprobeArchitectureDefinitionError(
                    "Unsupported opcode length in '%s' definition."
                    % self)

            self.operands["opcode_8"][0] = OperandConst(
                "Opcode", "Instruction opcode", int(self.opcode, 16))

        elif "opcode_8A" in operands and "opcode_8B" in operands:

            if len(opcode) != 4:
                raise MicroprobeArchitectureDefinitionError(
                    "Unsupported opcode length in '%s' definition."
                    % self)

            self.operands["opcode_8A"][0] = OperandConst(
                "Opcode higher",
                "Instruction opcode high 8 bits",
                int(self.opcode[0:2], 16)
            )
            self.operands["opcode_8B"][0] = OperandConst(
                "Opcode lower",
                "Instruction opcode low 8 bits",
                int(self.opcode[2:4], 16)
            )

        elif "opcode_8" in operands and "opcode_4" in operands:

            if len(opcode) != 4 or opcode[2] != 'x':
                raise MicroprobeArchitectureDefinitionError(
                    "Unsupported opcode length in '%s' definition." % self)

            self.operands["opcode_8"][0] = OperandConst(
                "Opcode higher",
                "Instruction opcode high 8 bits",
                int(self.opcode[0:2], 16)
            )

            self.operands["opcode_4"][0] = OperandConst(
                "Opcode lower",
                "Instruction opcode low 4 bits",
                int(self.opcode[3:4], 16)
            )

        else:

            raise MicroprobeArchitectureDefinitionError(
                "Unsupported opcode length in '%s' definition." % self)

    def assembly(self, args, dummy_dissabled_fields=None):
        assembly_str = super(X86Instruction, self).assembly(
            args
        )
        return assembly_str

    def binary(self, args, asm_args=None):
        LOG.debug("Start specific X86 codification")
        long_str = super(X86Instruction, self).binary(args, asm_args=asm_args)
        LOG.debug("End specific X86 codification")
        return long_str

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
from __future__ import absolute_import, print_function

# Third party modules
from six.moves import zip

# Own modules
from microprobe.code.ins import InstructionOperandValue
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.target.isa.instruction import GenericInstructionType
from microprobe.target.isa.operand import OperandDescriptor, OperandImmRange
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import getnextf, int_to_twocs, twocs_to_int

# Constants
LOG = get_logger(__name__)

_7BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    (2 ** 7),  # Max value
                    1,  # StepUImm1v0
                    True,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0  # Add
                    ),
    False,  # Input
    False  # Output
)

_5BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    (2 ** 5),  # Max value
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
class RISCVInstruction(GenericInstructionType):

    """
    RISC-V Instruction Class
    """

    def __init__(self, name, mnemonic, opcode, descr, iformat,
                 operands, ioperands, moperands, instruction_checks,
                 target_checks):
        super(RISCVInstruction, self).__init__(name, mnemonic, opcode,
                                               descr, iformat, operands,
                                               ioperands, moperands,
                                               instruction_checks,
                                               target_checks)

        # TODO: Implement target definition checking such as
        # instruction lengths (check other target definitions for
        # details)

    def assembly(self, args, dummy_dissabled_fields=None):

        assembly_str = super(RISCVInstruction, self).assembly(
            args,
            dissabled_fields=['sb_imm7', 'sb_imm5',
                              's_imm7', 's_imm5',
                              'pred', 'succ']
        )

        # sb_imm5 and s_imm5 should be always zero (by definition)
        # s_imm7 and sb_imm7 contain the true 12-bit long value

        def _get_value(cfield, base):
            try:
                value = [arg for arg in args
                         if arg.descriptor.type.name ==
                         self._operand_descriptors[cfield].type.name][0].value
                return self._operand_descriptors[cfield].type.representation(
                    value)
            except KeyError:
                raise MicroprobeArchitectureDefinitionError(
                    "Unable to find sub-field '%s' for the '%s' field" %
                    (cfield, base))

        if assembly_str.find("sb_imm12") > 0:
            assert _get_value("sb_imm5", "sb_imm12") == "0"
            value = _get_value("sb_imm7", "sb_imm12")
            assembly_str = assembly_str.replace("sb_imm12", str(value))

        if assembly_str.find("s_imm12") > 0:
            assert _get_value("s_imm5", "s_imm12") == "0"
            value = _get_value("s_imm7", "s_imm12")
            assembly_str = assembly_str.replace("s_imm12", str(value))

        for field in ['pred', 'succ']:

            if assembly_str.find(field) < 0:
                continue

            value = int(_get_value(field, field))

            str_value = ""
            if value & 0b1000:
                str_value += 'i'
            if value & 0b0100:
                str_value += 'o'
            if value & 0b0010:
                str_value += 'r'
            if value & 0b0001:
                str_value += 'w'

            assembly_str = assembly_str.replace(field, str_value)

            if value == 0:
                print((assembly_str, field, value))
                # exit(-1)

        return assembly_str

    def binary(self, args, asm_args=None):

        LOG.debug("Start specific RISC-V codification")

        # Check if fixing is needed
        fix_needed = False
        fix_fields = ['sb_imm5', 's_imm5']
        base_fields = ['sb_imm7', 's_imm7']

        for fix_field in fix_fields:
            if fix_field in [field.name for field in self.format.fields]:
                fix_needed = True
                break

        if not fix_needed:

            long_str = super(
                RISCVInstruction,
                self).binary(
                args,
                asm_args=asm_args)

            assert len(long_str) in [32], len(long_str)
            LOG.debug("End specific RISC-V codification")

            return long_str

        next_operand_value = getnextf(iter(args))
        newargs = []

        for op_descriptor, field in zip(list(self.operands.items()),
                                        self.format.fields):

            dummy_fieldname, op_descriptor = op_descriptor
            operand, dummy = op_descriptor

            LOG.debug("Field: %s", field)
            LOG.debug("Operand: %s", operand)

            if (operand.constant and
                    (field.name not in fix_fields + base_fields)):

                if field.default_show:
                    arg = next_operand_value()
                    newargs.append(arg)

                continue

            if field.name not in fix_fields + base_fields:
                LOG.debug("Not fixing field: %s", field.name)
                arg = next_operand_value()
                newargs.append(arg)
                continue

            if field.name in base_fields:

                arg = next_operand_value()
                value = int(arg.type.codification(arg.value))
                value_coded = int_to_twocs(value, 12)

                assert twocs_to_int(value_coded, 12) == value

                newarg = InstructionOperandValue(_7BITS_OPERAND_DESCRIPTOR)
                newarg.set_value((value_coded & 0xFE0) >> 5)

                if field.name == "sb_imm7":
                    sb_imm5_value = (value_coded & 0x1F)
                elif field.name == "s_imm7":
                    s_imm5_value = (value_coded & 0x1F)
                else:
                    raise NotImplementedError

                LOG.debug("Set field '%s' value: %s --> %s", field.name, value,
                          (value_coded & 0xFE0) >> 5)
                newargs.append(newarg)

            # Assume variable are previously set
            if field.name in fix_fields:

                newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)

                if field.name == "sb_imm5":
                    value_fixed = sb_imm5_value
                elif field.name == "s_imm5":
                    value_fixed = s_imm5_value
                else:
                    raise NotImplementedError(field.name)

                LOG.debug("Set field '%s' value: %s --> %s", field.name, value,
                          value_fixed)

                newarg.set_value(value_fixed)
                newargs.append(newarg)

        LOG.debug("Args: %s, %s", args, newargs)

        long_str = super(RISCVInstruction, self).binary(newargs, asm_args=args)
        assert len(long_str) in [16, 32, 48], len(long_str)
        LOG.debug("End specific RISC-V codification")
        return long_str

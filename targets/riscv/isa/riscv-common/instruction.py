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

# Built-in modules

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

_20BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    (2 ** 20),  # Max value
                    1,  # StepUImm1v0
                    False,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0  # Add
                    ),
    False,  # Input
    False  # Output
)

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


def _n_bits_operand_descriptor(bits):
    return OperandDescriptor(
        OperandImmRange("dummy",  # Name
                        "dummy",  # Description
                        0,  # Min value
                        (2 ** bits),  # Max value
                        1,  # StepUImm1v0
                        True,  # Address immediate
                        0,  # Shift
                        [],  # No values
                        0  # Add
                        ),
        False,  # Input
        False  # Output
    )


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
                              'c_imm1', 'c_imm2', 'c_imm3',
                              'cw_imm3', 'cd_imm3',
                              'cw_imm5', 'cd_imm5', 'cb_imm5', 'ci_imm5',
                              'cu_imm5', 'cs_imm5', 'cls_imm5',
                              'rs2_jr',
                              'pred', 'succ']
        )

        # sb_imm5 and s_imm5 should be always zero (by definition)
        # sb_imm7 and s_imm7 contain the true 12-bit long value
        #
        # sb_* values has a different encoding

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

        def _fix_field(string, base, dummy, field):
            field_names = [fld.name for fld in self.format.fields]
            if (string.find(base) > 0 and dummy in field_names
                    and field in field_names):
                assert _get_value(dummy, base) == "0"
                value = _get_value(field, base)

                if field == 'cu_imm5':
                    value = str(int_to_twocs(int(value), 20))

                return string.replace(base, str(value))
            else:
                return string

        # Base field   (the assembly language field)
        # Dummy field  (will be 0)
        # Actual field (contains the actual value)
        fix_fields = [
            ("sb_imm12", "sb_imm5", "sb_imm7"),
            ("s_imm12", "s_imm5", "s_imm7"),
            ("c_imm6", "c_imm1", "c_imm5"),
            ("c_imm5", "c_imm2", "cw_imm3"),
            ("c_imm5", "c_imm2", "cd_imm3"),
            ("c_imm8", "c_imm3", "cb_imm5"),
            ("c_imm6", "c_imm1", "cw_imm5"),
            ("c_imm6", "c_imm1", "cd_imm5"),
            ("c_imm6", "c_imm1", "ci_imm5"),
            ("c_imm6", "c_imm1", "cu_imm5"),
            ("c_imm6", "c_imm1", "cs_imm5"),
            ("c_imm6", "c_imm1", "cls_imm5")
        ]

        for fix in fix_fields:
            assembly_str = _fix_field(assembly_str, fix[0], fix[1], fix[2])

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

        # Destination Field
        # Source Field
        # codification bits
        # Operand Descriptor
        # Codification
        # Signed?
        fixes = [
            ('sb_imm7', 'sb_imm7', 13, _7BITS_OPERAND_DESCRIPTOR,
                '12|10:5', True),
            ('sb_imm5', 'sb_imm7', 13, _7BITS_OPERAND_DESCRIPTOR,
                '4:1|11', True),
            ('s_imm7', 's_imm7', 12, _7BITS_OPERAND_DESCRIPTOR,
                '11:5', True),
            ('s_imm5', 's_imm7', 12, _7BITS_OPERAND_DESCRIPTOR,
                '4:0', True),
            ('uj_imm20', 'uj_imm20', 20, _20BITS_OPERAND_DESCRIPTOR,
                '20|10:1|11|19:12', True),
            ('cw_imm3', 'cw_imm3', 7, _7BITS_OPERAND_DESCRIPTOR,
                '5:3', False),
            ('c_imm2', 'cw_imm3', 7, _7BITS_OPERAND_DESCRIPTOR,
                '2|6', False),
            ('cd_imm3', 'cd_imm3', 8, _n_bits_operand_descriptor(8),
                '5:3', False),
            ('c_imm2', 'cd_imm3', 8, _n_bits_operand_descriptor(8),
                '7|6', False),
            ('cb_imm5', 'cb_imm5', 9, _n_bits_operand_descriptor(9),
                '7:6|2:1|5', True),
            ('c_imm3', 'cb_imm5', 9, _n_bits_operand_descriptor(9),
                '8|4:3', False),
            ('cw_imm5', 'cw_imm5', 8, _n_bits_operand_descriptor(8),
                '4:2|7:6', False),
            ('c_imm1', 'cw_imm5', 8, _n_bits_operand_descriptor(8),
                '5', False),
            ('cd_imm5', 'cd_imm5', 9, _n_bits_operand_descriptor(9),
                '4:3|8:6', False),
            ('c_imm1', 'cd_imm5', 9, _n_bits_operand_descriptor(9),
                '5', False),
            ('ci_imm5', 'ci_imm5', 6, _n_bits_operand_descriptor(6),
                '4:0', True),
            ('c_imm1', 'ci_imm5', 6, _n_bits_operand_descriptor(6),
                '5', True),
            ('cu_imm5', 'cu_imm5', 20, _n_bits_operand_descriptor(20),
                '4:0', False),
            ('c_imm1', 'cu_imm5', 20, _n_bits_operand_descriptor(20),
                '5', False),
            ('cs_imm5', 'cs_imm5', 10, _n_bits_operand_descriptor(10),
                '4|6|8:7|5', True),
            ('c_imm1', 'cs_imm5', 10, _n_bits_operand_descriptor(10),
                '9', False),
            ('cls_imm5', 'cls_imm5', 6, _n_bits_operand_descriptor(6),
                '4:0', False),
            ('c_imm1', 'cls_imm5', 6, _n_bits_operand_descriptor(6),
                '5', False),
            ('cw_imm6', 'cw_imm6', 8, _n_bits_operand_descriptor(8),
                '5:2|7:6', False),
            ('cd_imm6', 'cd_imm6', 9, _n_bits_operand_descriptor(9),
                '5:3|8:6', False),
            ('c_imm11', 'c_imm11', 12, _n_bits_operand_descriptor(12),
                '11|4|9:8|10|6|7|3:1|5', True),
            ('cs_imm8', 'cs_imm8', 10, _n_bits_operand_descriptor(10),
                '5:4|9:6|2|3', False),
            ('crs1', 'crs1', 5, _n_bits_operand_descriptor(3), '2:0', False),
            ('crs2', 'crs2', 5, _n_bits_operand_descriptor(3), '2:0', False),
            ('crd', 'crd', 5, _n_bits_operand_descriptor(3), '2:0', False),
            ('fcrs1', 'fcrs1', 5, _n_bits_operand_descriptor(3), '2:0', False),
            ('fcrs2', 'fcrs2', 5, _n_bits_operand_descriptor(3), '2:0', False),
            ('fcrd', 'fcrd', 5, _n_bits_operand_descriptor(3), '2:0', False),
        ]

        # Check if fixing is needed
        fix_needed = False
        for (name, _, _, _, _, _) in fixes:
            if name in [field.name for field in self.format.fields]:
                fix_needed = True
                break

        if not fix_needed:

            long_str = super(
                RISCVInstruction,
                self).binary(
                args,
                asm_args=asm_args)

            assert len(long_str) in [32, 16], len(long_str)
            LOG.debug("End specific RISC-V codification")

            return long_str

        def _code_fixed_field(value, codification):
            coded_value = 0

            segments = codification.split(';')
            for segment in segments:
                tokens = segment.split('|')
                for token in tokens:
                    if ':' in token:
                        start, end = token.split(':')
                        for pos in range(int(start), int(end)-1, -1):
                            bit = (value >> (pos)) & 1
                            coded_value = (coded_value << 1) | bit
                    else:
                        pos = int(token)
                        bit = (value >> (pos)) & 1
                        coded_value = (coded_value << 1) | bit

            return coded_value

        fields = dict(zip([field.name for field in self.format.fields],
                      zip(self.format.fields, list(self.operands.items()))))
        argdict = dict(zip([field.name for field in self.format.fields
                            if field.default_show], args))
        fixed_args = dict()

        for fix in fixes:
            if fix[0] in fields and fix[1] in argdict:
                field, op_descriptor = fields[fix[0]]
                arg = argdict[fix[1]]
                value = int(arg.type.codification(arg.value))
                newarg = InstructionOperandValue(fix[3])

                if fix[5]:
                    value_coded = int_to_twocs(value, fix[2])
                    assert twocs_to_int(value_coded, fix[2]) == value
                    value = value_coded

                try:
                    value <<= arg.type.shift
                except AttributeError:  # Shifting not always will be available
                    pass

                newarg.set_value(_code_fixed_field(value, fix[4]))
                fixed_args[fix[0]] = newarg

        newargs = []

        for op_descriptor, field in zip(list(self.operands.items()),
                                        self.format.fields):

            _, op_descriptor = op_descriptor
            operand, _ = op_descriptor

            LOG.debug("Field: %s", field)
            LOG.debug("Operand: %s", operand)

            if field.name in fixed_args:
                newargs.append(fixed_args[field.name])
            else:
                if ((operand.constant and field.default_show) or
                        (not operand.constant)):
                    LOG.debug("Not fixing field: %s", field.name)
                    newargs.append(argdict[field.name])

        LOG.debug("Args: %s, %s", args, newargs)

        long_str = super(RISCVInstruction, self).binary(newargs, asm_args=args)
        assert len(long_str) in [16, 32], len(long_str)
        LOG.debug("End specific RISC-V codification")
        return long_str

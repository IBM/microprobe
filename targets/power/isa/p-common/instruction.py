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

# Third party modules
from six.moves import zip

# Own modules
from microprobe.code.ins import InstructionOperandValue
from microprobe.target.isa.instruction import GenericInstructionType
from microprobe.target.isa.operand import OperandDescriptor, OperandImmRange
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import getnextf, int_to_twocs

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
__all__ = ["check_load_string_overlap",
           "PowerInstruction",
           ]
LOG = get_logger(__name__)

_14BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    - (2 ** 13),  # Min value
                    (2 ** 13) - 1,  # Max value
                    1,  # StepUImm1v0
                    False,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0  # Add
                    ),
    False,  # Input
    False  # Output
)

_10BITS_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    (2 ** 10) - 1,  # Max value
                    1,  # Step
                    False,  # Address immediate
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
                    31,  # Max value
                    1,  # Step
                    False,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0  # Add
                    ),
    False,  # Input
    False  # Output
)

_1BIT_OPERAND_DESCRIPTOR = OperandDescriptor(
    OperandImmRange("dummy",  # Name
                    "dummy",  # Description
                    0,  # Min value
                    1,  # Max value
                    1,  # Step
                    False,  # Address immediate
                    0,  # Shift
                    [],  # No values
                    0  # Add
                    ),
    False,  # Input
    False  # Output
)


# Functions
def check_load_string_overlap(dummy_instruction,
                              dummy_target_reg,
                              dummy_source_reg,
                              dummy_number_bytes):

    # TODO: remove this
    LOG.warning("Not implemented")
    return

    # target_reg_operand = instruction.operand_by_field(target_reg)
    # source_reg_operand = instruction.operand_by_field(source_reg)

    # orig_dscr_target_operand = target_reg_operand.descriptor
    # orig_dscr_source_operand = source_reg_operand.descriptor

    # try:
    #    number_bytes_operand = instruction.operand_by_field(number_bytes)
    #    orig_dscr_number_bytes_operand = number_bytes_operand.descriptor
    #    input_operand = True
    # except MicroprobeLookupError:
    #    input_operand = False

    # def function_set_target(dummy_value):
    #    raise NotImplementedError(orig_dscr_source_operand)

    # def function_unset_target(dummy_value):
    #    raise NotImplementedError(orig_dscr_target_operand)

    # def function_set_source(dummy_value):
    #    raise NotImplementedError(orig_dscr_number_bytes_operand)

    # def function_unset_source(dummy_value):
    #    pass

    # def function_set_number_bytes(dummy_value):
    #    pass

    # def function_unset_number_bytes(dummy_value):
    #    pass

    # target_reg_operand.register_operand_callbacks(function_set_target,
    #                                             function_unset_target)

    # source_reg_operand.register_operand_callbacks(function_set_source,
    #                                               function_unset_source)
    # if input_operand:
    #    number_bytes_operand.register_operand_callbacks(
    #        function_set_number_bytes,
    #        function_unset_number_bytes)


def check_implicit_ctr(instruction, operand1_name):

    operand = instruction.operand_by_field(operand1_name)
    implicit = instruction._ioperands[:]

    def function_set_operand1(value):
        if value in [0, 1, 8, 9, 10, 11, 16, 17, 18, 19, 24, 25, 26, 27]:
            instruction._ioperands = implicit
        else:
            instruction._ioperands = []

    def function_unset_operand1():
        instruction._ioperands = []

    operand.register_operand_callbacks(
        function_set_operand1, function_unset_operand1
    )


def check_cr(instruction):

    implicit = instruction._ioperands[:]
    desc_dict = {}
    for impl in implicit:
        name = impl.type.values()[0].name
        desc_dict[int(name.replace("CR", ""))] = impl.type

    for operand in instruction.operands():

        if not operand.is_input:
            continue

        def function_update_operands():
            instruction._ioperands = []
            ivalues = []
            ovalues = []
            for operand in instruction.operands():
                if operand.value is None:
                    continue
                if operand.is_input:
                    ivalues.append(operand.value//4)
                if operand.is_output:
                    ovalues.append(operand.value//4)

            iovalues = list(set([val for val in ivalues + ovalues
                                 if val in ivalues and val in ovalues]))
            ivalues = [val for val in ivalues if val not in iovalues]
            ovalues = [val for val in ovalues if val not in iovalues]

            for val in ivalues:
                descr = OperandDescriptor(desc_dict[val], True, False)
                instruction._ioperands.append(descr)

            for val in ovalues:
                descr = OperandDescriptor(desc_dict[val], False, True)
                instruction._ioperands.append(descr)

            for val in iovalues:
                descr = OperandDescriptor(desc_dict[val], True, True)
                instruction._ioperands.append(descr)

        def function_set_operand(val):
            function_update_operands()

        def function_unset_operand():
            function_update_operands()

        operand.register_operand_callbacks(
            function_set_operand, function_unset_operand
        )


# Classes
class PowerInstruction(GenericInstructionType):

    """
    Power Instruction Class
    """

    def binary(self, args, dummy_asm_args=None):

        LOG.debug("Start specific PowerPC codification")

        # Check if fixing is needed
        fix_needed = False
        fix_fields = ['SH0', 'CX', 'AX', 'BX', 'TX', 'SX', 'MB6', 'ME6',
                      'SPR', 'D_14dw', 'D_14sw', 'D_14qw2', 'Dd0',
                      'Dd2', 'dc', 'dm']
        base_fields = ['SH6_5', 'C', 'A', 'Ap', 'B', 'S', 'T', 'TP',
                       'Dd1', 'dx']

        for fix_field in fix_fields:
            if fix_field in [field.name for field in self.format.fields]:
                fix_needed = True
                break

        if not fix_needed:
            long_str = super(PowerInstruction, self).binary(args)

            assert len(long_str) == 32, \
                "Bad PowerPC codification. Length: %d " % len(
                long_str)

            LOG.debug("End specific PowerPC codification")
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

                if field.name == 'SH6_5':
                    sh0_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "A":
                    ax_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "Ap":
                    ax_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "B":
                    bx_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "C":
                    cx_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "T":
                    tx_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name in "TP":
                    tx_value = (value & 0b100000) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value((value & 0b011111) >> 1)
                elif field.name == "S":
                    sx_value = (value & 0x20) >> 5
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "dx":
                    dm_value = (value >> 5) & 0b1
                    dc_value = (value >> 6) & 0b1
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value(value & 0x1F)
                elif field.name == "Dd1":
                    value = int_to_twocs(value, 16)
                    dd0_value = value >> 6
                    dd2_value = value & 0b1
                    newarg = InstructionOperandValue(_5BITS_OPERAND_DESCRIPTOR)
                    newarg.set_value((value >> 1) & 0b11111)
                else:
                    raise NotImplementedError

                newargs.append(newarg)
                LOG.debug("Set field value: %s --> %s", value, newarg.value)

            # Assume variable are previously set
            if field.name in fix_fields:

                newarg = InstructionOperandValue(_1BIT_OPERAND_DESCRIPTOR)

                if field.name == 'SH0':
                    value = sh0_value
                elif field.name == "AX":
                    value = ax_value
                elif field.name == "BX":
                    value = bx_value
                elif field.name == "CX":
                    value = cx_value
                elif field.name == "TX":
                    value = tx_value
                elif field.name == "SX":
                    value = sx_value
                elif field.name == "dm":
                    value = dm_value
                elif field.name == "dc":
                    value = dc_value
                elif field.name in ["MB6", "ME6"]:
                    arg = next_operand_value()
                    newarg = arg.copy()
                    value = int(arg.type.codification(arg.value))
                    value = ((value & 0x1F) << 1) | ((value & 0x20) >> 5)
                elif field.name in ["SPR"]:
                    arg = next_operand_value()
                    newarg = InstructionOperandValue(
                        _10BITS_OPERAND_DESCRIPTOR
                    )
                    value = int(arg.type.codification(arg.value))
                    value = ((value & 0x1F) << 5) | ((value & 0x3E0) >> 5)
                elif field.name in ['D_14dw', 'D_14sw', 'D_14qw2', ]:
                    arg = next_operand_value()
                    # newarg = arg.copy()
                    newarg = InstructionOperandValue(
                        _14BITS_OPERAND_DESCRIPTOR
                    )
                    value = int(arg.type.codification(arg.value))
                    value = value >> 2
                elif field.name == "Dd0":
                    newarg = arg.copy()
                    value = dd0_value
                elif field.name == "Dd2":
                    newarg = arg.copy()
                    value = dd2_value
                else:
                    raise NotImplementedError

                LOG.debug("Set field to value: %s", value)
                newarg.set_value(value)
                newargs.append(newarg)

        LOG.debug("New args: %s", newargs)

        long_str = super(PowerInstruction, self).binary(newargs,
                                                        asm_args=args)

        assert len(long_str) == 32, "Bad PowerPC codification. Length: %d " \
            % len(long_str)

        LOG.debug("End specific PowerPC codification")

        return long_str

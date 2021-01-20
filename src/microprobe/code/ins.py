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
""":mod:`microprobe.code.ins` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import copy
from itertools import product

# Third party modules
import six
from six.moves import range, zip

# Own modules
from microprobe.code.address import Address, InstructionAddress
from microprobe.exceptions import MicroprobeArchitectureDefinitionError, \
    MicroprobeCodeGenerationError, MicroprobeDuplicatedValueError, \
    MicroprobeLookupError, MicroprobeValueError
from microprobe.target.isa.operand import Operand, \
    OperandConstReg, OperandDescriptor
from microprobe.target.isa.register import Register
from microprobe.utils.asm import interpret_asm
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import OrderedDict, \
    Pickable, RejectingDict, RejectingOrderedDict


# Constants
LOG = get_logger(__name__)
__all__ = [
    "Instruction",
    "InstructionMemoryOperandValue",
    "InstructionOperandValue",
    "create_dependency_between_ins",
    "instruction_to_definition",
    "instruction_from_definition",
    "instruction_set_def_properties",
    "instructions_from_asm",
    "MicroprobeInstructionDefinition",
    'instruction_factory',
]

_LABEL_COUNTER = 0


# Functions
def instruction_to_definition(instr):
    """
    Return the definition of an instruction.

    Given an :class:`~.Instruction` object, return the corresponding
    :class:`~.MicroprobeInstructionDefinition` object.

    :param instr: Instruction object
    :type instr: :class:`~.Instruction`
    :rtype: :class:`~.MicroprobeInstructionDefinition`
    """

    label = instr.label
    instr.set_label(None)

    asm = instr.assembly()
    comments = instr.comments
    if instr.disable_asm is True:
        asmfmt = "0x%%0%dX" % (len(instr.binary()) / 4)
        asm = asmfmt % int(instr.binary(), 2)
        comments = [instr.assembly()] + instr.comments

    return MicroprobeInstructionDefinition(instr.architecture_type, [
        operand.value for operand in instr.operands()
    ], label, instr.address, asm,
        instr.decorators, comments)


def instruction_from_definition(definition, fix_relative=True):
    """
    Return the instruction from a definition.

    Given an :class:`~.MicroprobeInstructionDefinition` object, return the
    corresponding :class:`~.Instruction` object.

    :param instr: Instruction definition object
    :type instr: :class:`~.MicroprobeInstructionDefinition`
    :rtype: :class:`~.Instruction`
    """

    ninstr = Instruction()
    instruction_set_def_properties(
        ninstr, definition, fix_relative=fix_relative)
    return ninstr


def instruction_set_def_properties(instr,
                                   definition,
                                   building_block=None,
                                   target=None,
                                   allowed_registers=None,
                                   fix_relative=True,
                                   label_displ=None):
    """
    Set instruction properties from an intruction definition.

    Set instruction properties according to the properties in the instruction
    definition. If *building_block* is provided, its context is used.
    Otherwise, an empty context is used. The *target* is the target platform
    and the *allowed_registers* parameters spicify which register can be
    used (written) by the instruction.

    :param instr: Instruction instance
    :type instr: :class:`~.Instruction`
    :param definition: Instruction definition instance
    :type definition: :class:`~.MicroprobeInstructionDefinition`
    :param building_block: Building block of the instruction
    :type building_block: :class:`~.BuildingBlock`
    :param target: Target instance
    :type target: :class:`~.Target`
    :param allowed_registers: List of allowed registers
    :type allowed_registers: :class:`~.list` of :class:`~.Register`
    """

    global _LABEL_COUNTER
    instruction = definition.instruction_type
    operands = definition.operands
    label = definition.label
    address = definition.address
    comments = definition.comments
    decorators = definition.decorators
    asm = definition.asm

    if allowed_registers is None:
        allowed_registers = []

    if label is not None:
        instr.set_label(label)

    if comments is None:
        comments = []

    if decorators is None:
        decorators = {}

    instr.set_arch_type(instruction)
    LOG.debug("Set instruction type: %s", instruction)

    LOG.debug("Operands, not fixed: %s", operands)
    if len(operands) > 0:

        fixed_operands = []
        LOG.debug("Fixed operands: %s", fixed_operands)

        for idx, operand in enumerate(operands):
            LOG.debug("Fixing operands: %s", operand)

            if (isinstance(operand, six.integer_types) and
                    instr.operands()[idx].type.address_relative and
                    fix_relative):
                LOG.debug("Hardcoded displacement")
                if instr.branch:

                    LOG.debug("Branch label")
                    if label is None:
                        if label_displ is not None:
                            label = "instr_displ_label_%s" % (label_displ)
                            _LABEL_COUNTER = max(_LABEL_COUNTER,
                                                 label_displ + 1)
                        else:
                            label = "instr_displ_label_%s" % (_LABEL_COUNTER)
                            _LABEL_COUNTER += 1

                        instr.set_label(label)

                    iaddress = InstructionAddress(base_address=label,
                                                  displacement=operand)
                    fixed_operands.append(iaddress)
                    continue

            if not isinstance(operand, str):
                fixed_operands.append(operand)
                LOG.debug("Operand not string")
                continue

            displacement = 0

            # Check if there is displacement from a variable
            if building_block is not None:
                for var in building_block.registered_global_vars():
                    if operand.startswith(var.name):
                        if operand.replace(var.name, "") != "":
                            displacement = int(
                                operand.replace(var.name, ""),
                                base=0)
                            operand = var.name
                            break

                possible_vars = [
                    var
                    for var in building_block.registered_global_vars()
                    if var.name == operand
                ]

                LOG.debug("Possible variables: %s", possible_vars)

                if len(possible_vars) == 1:
                    LOG.debug("Operand variable")
                    taddress = Address(base_address=possible_vars[0],
                                       displacement=displacement)
                    fixed_operands.append(taddress)
                    continue

            # Check if there is displacement from a label
            if operand.find('-') > -1:
                displacement = int('-' + operand.split('-')[1], base=0)
                operand = operand.split('-')[0]
            elif operand.find('+') > -1:
                displacement = int('+' + operand.split('+')[1], base=0)
                operand = operand.split('+')[0]

            if instr.operands()[idx].type.address_relative:

                if instr.branch:

                    LOG.debug("Branch label")
                    iaddress = InstructionAddress(base_address=operand,
                                                  displacement=displacement)
                    fixed_operands.append(iaddress)
                    continue

                else:

                    LOG.debug("Branch label")
                    taddress = Address(base_address=operand,
                                       displacement=displacement)
                    fixed_operands.append(taddress)
                    continue

            raise MicroprobeCodeGenerationError(
                "I do not know how to set operand '%s' in instruction "
                "'%s'" % (operand, asm))

        assert len(fixed_operands) == len(operands)

        LOG.debug("Setting operands: %s", fixed_operands)
        instr.set_operands(fixed_operands)

    if address is not None:
        instr.set_address(address.copy())

    for comment in comments:
        instr.add_comment("MPT comment: %s" % comment)

    for decorator_key, decorator_value in decorators.items():

        if decorator_key in ['MA', 'BT', 'EA']:
            if not isinstance(decorator_value, list):
                decorator_value = [decorator_value]
            decorator_value = ["0x%016X" % elem for elem in decorator_value]

        instr.add_comment("Decorator: %s = %s" % (decorator_key,
                                                  decorator_value))
        instr.add_decorator(decorator_key, decorator_value)

    for register_name in allowed_registers:
        if register_name not in list(target.registers.keys()):
            raise MicroprobeCodeGenerationError(
                "Unknown register '%s'. Known registers: %s" %
                (register_name, list(target.registers.keys())))

        if target.registers[register_name] in instr.sets() + instr.uses():
            instr.add_allow_register(target.registers[register_name])

    # TODO : NO NEED TO CHECK ANYTHING JUST REPRODUCING!
    # reserve implicit operands (if they are not already
    # reserved) and add them as allowed
    # for operand_descriptor in instr.implicit_operands:
    #    register = operand_descriptor.type.values()[0]
    #    instr.add_allow_register(register)

    #    if operand_descriptor.is_output and register not \
    #        in building_block.context.reserved_registers \
    #        and register not in target.control_registers:
    #        building_block.context.add_reserved_registers(
    #                                                    [register])

    # context_fix_functions = instr.check_context(
    #                                        building_block.context)
    # for context_fix_function in context_fix_functions:
    #    try:
    #        context_fix_function(target, building_block)
    #    except MicroprobeUncheckableEnvironmentWarning\
    #                                         as warning_check:
    #        building_block.add_warning(str(warning_check))


def instructions_from_asm(asm, target, labels=None, fix_relative=True):
    """

    :param asm:
    :type asm:
    :param target:
    :type target:
    :param labels:
    :type labels:
    """
    asm_defs = interpret_asm(asm, target, labels)
    instrs = [
        instruction_from_definition(asm_def, fix_relative=fix_relative)
        for asm_def in asm_defs
    ]
    return instrs


def instruction_factory(ins_type):
    """Return a instruction of the given instruction type.

    :param ins_type: Instruction type of the new instruction
    :type ins_type: :class:`~.InstructionType`
    :return: A new instruction instance with the type *ins_type*
    :rtype: :class:`~.Instruction`
    """
    instruction = Instruction()
    instruction.set_arch_type(ins_type)
    return instruction


# Classes
class InstructionOperandValue(Pickable):
    """Class to represent an instruction operand value"""

    def __init__(self, operand_descriptor):
        """

        :param operand_descriptor:

        """
        self._operand_descriptor = operand_descriptor
        self._value = None
        self._set_function = None
        self._unset_function = None

    @property
    def value(self):
        """Value of the instruction operand. (type depends on the operand)"""
        return self._value

    @property
    def descriptor(self):
        """Descriptor of the operand (:class:`~.OperandDescriptor`)"""
        return self._operand_descriptor

    def copy(self):
        """Return a copy of the instruction operand value.

        :rtype: :class:`~.InstructionOperandValue`
        """
        newobj = InstructionOperandValue(self._operand_descriptor)
        newobj.set_value(self.value)
        newobj.register_operand_callbacks(self._set_function,
                                          self._unset_function)
        return newobj

    def set_descriptor(self, descriptor):
        """

        :param descriptor:

        """
        self._operand_descriptor = descriptor

    def set_value(self, value, check=True):
        """

        :param value:
        :param check:  (Default value = True)

        """
        if self._value is not None and self._unset_function is not None:
            self._unset_function()

        if check:
            self.type.check(value)

        self._value = value

        if self._set_function is not None and value is not None:
            self._set_function(value)

    def unset_value(self):
        """Unsets the operand value.

        """
        self.set_value(None, check=False)

    def sets(self):
        """Return the list of registers set by the operand.

        :rtype: :class:`~.list` of :class:`~.Register`
        """
        if not self.is_output or self._value is None:
            return []

        return self._operand_descriptor.type.access(self.value)

    @property
    def representation(self):
        """Representation of the operand value for generating assembly."""
        return self._operand_descriptor.type.representation(self.value)

    def uses(self):
        """Return the list of registers used by the operand.

        :rtype: :class:`~.list` of :class:`~.Register`
        """
        if not self.is_input or self._value is None:
            return []

        return self._operand_descriptor.type.access(self.value)

    def __getattr__(self, name):
        """

        :param name:

        """
        try:
            return self._operand_descriptor.__getattribute__(name)
        except AttributeError:
            raise AttributeError("'%s' object has no attribute '%s'" %
                                 (self.__class__.__name__, name))

    def __repr__(self):
        """ """
        return "%s(Type: %s, Value: %s)" % (self.__class__.__name__, self.type,
                                            self.value)

    def register_operand_callbacks(self, set_function, unset_function):
        """

        :param set_function:
        :param unset_function:

        """

        assert self._set_function is None
        assert self._unset_function is None
        self._set_function = set_function
        self._unset_function = unset_function


class InstructionMemoryOperandValue(Pickable):
    """Class to represent an instruction operand value"""

    def __init__(self, memory_operand_descriptor, operand_values,
                 length_values):
        """

        :param memory_operand_descriptor:
        :param operand_values:
        :param length_values:

        """
        self._memory_operand_descriptor = memory_operand_descriptor
        self._operand_values = operand_values
        self._length_values = length_values
        self._address = None
        self._length = None
        self._possible_lengths = None

        self._set_address_function = None
        self._unset_address_function = None
        self._set_length_function = None
        self._unset_length_function = None

        self._possible_lengths_set = None
        self._possible_addresses = None
        self._alignment = None

        self._forbidden_min = None
        self._forbidden_max = None

        if not self.variable_length:
            self._length = self._compute_length()

    def register_mem_operand_callback(self, set_address, set_length,
                                      unset_address, unset_length):
        """

        :param set_address:
        :param set_length:
        :param unset_address:
        :param unset_length:

        """

        assert self._set_address_function is None
        assert self._unset_address_function is None
        assert self._set_length_function is None
        assert self._unset_length_function is None

        self._set_address_function = set_address
        self._unset_address_function = unset_address
        self._set_length_function = set_length
        self._unset_length_function = unset_length

    @property
    def address(self):
        """Address of the memory operand (:class:`~.Address`)."""
        return self._address

    @property
    def descriptor(self):
        """Descriptor of the memory operand (:class:`~.OperandDescriptor`)."""
        return self._memory_operand_descriptor

    @property
    def length(self):
        """Length of the memory operand (::class:`~.int`). """
        return self._length

    @property
    def operands(self):
        """Memory operand values
        (list of :class:`~.InstructionOperandValue`)."""
        return self._operand_values

    @property
    def variable_length(self):
        """Variable length value(:class:`~.bool`)."""

        operand_values = [
            operand
            for operand in self._length_values
            if (isinstance(operand, InstructionOperandValue) or isinstance(
                operand, OperandDescriptor) or isinstance(operand, tuple))
        ]

        if len(operand_values) > 0:
            for operand in operand_values:
                if isinstance(operand, tuple):
                    return True
                elif len(list(operand.type.values())) > 1:
                    return True
                elif not isinstance(list(operand.type.values())[0],
                                    tuple([str] + list(six.integer_types))):
                    return True

        return False

    def _compute_length(self):
        """Compute legnth based on current operand values."""

        length = 0
        for operand in self._length_values:
            if isinstance(operand, six.integer_types):
                length = length + operand
            elif operand == "Unknown":
                LOG.warning("Unknown length (assume 0) for memory operand")
                length = 0
            else:
                LOG.critical("Warning unknown length: %s", str(operand))
                raise NotImplementedError

        return length

    def _compute_possible_lengths(self, context):
        """Compute the possible lengths that can be generated.

        Compute the possible lengths that can be generated from the context
        specified.

        :param context: execution context
        :type context: :class:`~.Context`

        """
        if not self.variable_length:
            self._possible_lengths = [self._length]
            return

        operand_values = [
            operand
            for operand in self._length_values
            if isinstance(operand, InstructionOperandValue)
        ]

        operand_constants = [
            operand
            for operand in self._length_values
            if (not isinstance(operand, InstructionOperandValue) and
                not isinstance(operand, tuple) and not isinstance(
                    operand, OperandDescriptor))
        ]

        operand_register_const = [
            operand
            for operand in self._length_values
            if isinstance(operand, OperandDescriptor)
        ]

        operand_special = [
            operand
            for operand in self._length_values if isinstance(operand, tuple)
        ]

        operand_registers_diff = [
            operand for operand in operand_special if operand[1] != "MASK"
        ]

        operand_masks = [
            operand for operand in operand_special if operand[1] == "MASK"
        ]

        assert ((len(operand_registers_diff) > 0) ^ (len(operand_values) > 0) ^
                (len(operand_masks) > 0) ^ (len(operand_register_const) > 0))

        lengths = OrderedDict()

        LOG.debug("Operand values: %s", operand_values)
        LOG.debug("Operand constants: %s", operand_constants)
        LOG.debug("Operand register constants: %s", operand_register_const)
        LOG.debug("Operand special: %s", operand_special)
        LOG.debug("Operand register diff: %s", operand_registers_diff)
        LOG.debug("Operand masks: %s", operand_masks)

        if len(operand_values) > 0:

            operand_lengths = OrderedDict()
            register_based = False
            negate_idx = []

            for idx, operand in enumerate(operand_values):

                if operand.type.immediate:

                    # Check if the operand is negated
                    preindex = [
                        lidx
                        for lidx, elem in enumerate(self._length_values)
                        if elem == operand
                    ][0]

                    if (preindex > 0 and self._length_values[
                            preindex - 1] == "-"):
                        LOG.debug("Negated Immediate operand")
                        operand_lengths[operand] = [
                            elem * (-1) for elem in operand.type.values()
                        ]
                        negate_idx.append(idx)
                    else:
                        LOG.debug("Immediate operand")
                        operand_lengths[operand] = list(operand.type.values())

                else:

                    assert len(
                        operand_values) == 1, "More than one non immediate "\
                        "operand " "not implemented."
                    register_based = True

            if register_based:

                LOG.debug("Register based")
                for register in operand_values[0].type.values():

                    # if register in context.reserved_registers
                    #    LOG.debug("Skip register: %s", register)
                    #    continue

                    length = context.get_register_value(register)

                    if length is not None:

                        LOG.debug("Fixed register %s to %s", register, length)
                        lengths[(register, length)] = length

                    else:

                        LOG.debug("Register %s not fixed", register)
                        lengths[(register, "reg_range")] = "reg_range"

            else:

                for elem in product(*list(operand_lengths.values())):

                    length = 0
                    for item in elem:
                        length = length + item

                    if 0 in negate_idx:
                        lengths[elem[0] * (-1)] = length
                    else:
                        lengths[elem[0]] = length

        elif len(operand_registers_diff) == 1:

            LOG.debug("Operand register diff")

            if isinstance(operand_registers_diff[0][2],
                          InstructionOperandValue):

                reg2_vals = list(operand_registers_diff[0][2].type.values())

            else:

                raise NotImplementedError

            LOG.debug("Register 2 values: %s", reg2_vals)

            if isinstance(operand_registers_diff[0][1],
                          InstructionOperandValue):

                reg1_vals = list(operand_registers_diff[0][1].type.values())
                allow_reserved = False

            elif operand_registers_diff[0][1] == "REGMAX":

                reg1_vals = [max(reg2_vals)]
                allow_reserved = True

            else:

                raise NotImplementedError

            LOG.debug("Register 1 values: %s", reg1_vals)

            for val1 in reg1_vals:

                if val1 in context.reserved_registers and not allow_reserved:
                    LOG.debug("%s in reserved registers", val1)
                    continue

                for val2 in reg2_vals:

                    if (val2 in context.reserved_registers and
                            not allow_reserved):
                        LOG.debug("%s in reserved registers", val2)
                        continue

                    LOG.debug("Checking combination: %s and %s", val1, val2)

                    ival1 = int(val1.representation)
                    ival2 = int(val2.representation)

                    LOG.debug("Value1: %d", ival1)
                    LOG.debug("Value2: %d", ival2)

                    # TODO: too conservative --> forcing val1 to be >= val2
                    if ival1 < ival2:
                        LOG.debug("Skipping: not allowing val1 < val2")
                        continue

                    if not allow_reserved:

                        skip = False

                        for reserved in context.reserved_registers:
                            if (int(reserved.representation) > ival2 and
                                    int(reserved.representation) < ival1):
                                skip = True
                                break

                        if skip:
                            LOG.debug("Skipping: traversing reserved register")
                            continue

                    diff = ival1 - ival2 + 1

                    LOG.debug("Difference: %s", diff)

                    if diff > 0:
                        if operand_registers_diff[0][1] == "REGMAX":
                            lengths[(val2, None)] = diff
                        else:
                            lengths[(val1, val2)] = diff

        elif len(operand_masks) == 1:

            # if the operand is a mask the lengths are the number in bytes
            # is the # of 1 in the mask

            for elem in operand_masks[0][0].type.values():
                lengths[elem] = bin(elem).count("1")

        elif len(operand_register_const) == 1:

            register = list(operand_register_const[0].type.values())[0]
            length = context.get_register_value(register)

            if length is not None:

                lengths[(register, length)] = length

            else:

                lengths[(register, "reg_range")] = "reg_range"

        else:

            raise NotImplementedError

        LOG.debug("Possible lengths: %s", set(lengths.values()))

        for operand_constant in operand_constants:

            LOG.debug("Processing: %s", operand_constant)
            lengths_to_remove = []
            newlengths = OrderedDict()

            for length in lengths:

                if isinstance(operand_constant, six.integer_types):
                    if isinstance(lengths[length], six.integer_types):
                        lengths[length] += operand_constant
                    else:
                        raise NotImplementedError

                elif operand_constant.startswith("*"):
                    lengths[length] *= int(operand_constant[1:])

                elif operand_constant.startswith("+"):
                    lengths[length] += int(operand_constant[1:])

                elif operand_constant == "-":
                    continue

                elif operand_constant.startswith("-"):
                    lengths[length] -= int(operand_constant[1:])

                elif operand_constant.startswith("CEIL"):
                    ceil_value = int(operand_constant[4:])

                    if lengths[length] != "reg_range":

                        if (lengths[length] % ceil_value) != 0:
                            lengths[length] = (
                                (lengths[length] // ceil_value) + 1) * \
                                ceil_value
                        else:
                            lengths[length] = lengths[length]

                    else:

                        lengths_to_remove.append(length)

                        # TODO: Maximum length is hard-coded to 1024 bytes
                        for elem in range(
                                0,
                                min((2**length[0].type.size) - 1, 1024),
                                ceil_value):
                            newlengths[(length[0], elem)] = elem

                elif operand_constant.startswith("min"):
                    assert isinstance(length, tuple)

                    maxvalue = int(operand_constant.replace("min", ""))

                    if lengths[length] != "reg_range":

                        # value already set
                        if isinstance(lengths[length], Address):

                            # TODO: Assuming that all addresses are always
                            # greater than the max value
                            lengths[length] = maxvalue

                        elif isinstance(lengths[length], six.integer_types):

                            if isinstance(length, six.integer_types):

                                if length > maxvalue:
                                    lengths_to_remove.append(length)

                            elif isinstance(length, tuple):

                                if (isinstance(length[0], Register) and
                                        isinstance(length[1], Register)):

                                    if lengths[length] > maxvalue:
                                        lengths_to_remove.append(length)

                                elif (isinstance(length[0], Register) and
                                      isinstance(length[1],
                                                 six.integer_types)):

                                    if lengths[length] > maxvalue:
                                        # TODO: Assuming that min value is
                                        # the ceiling for lengths operands
                                        lengths[length] = maxvalue

                                else:

                                    LOG.critical(length)
                                    LOG.critical(lengths[length])
                                    raise NotImplementedError

                            else:

                                LOG.critical(length)
                                raise NotImplementedError

                        else:
                            LOG.critical(length)
                            raise NotImplementedError

                    else:

                        lengths_to_remove.append(length)

                        for elem in range(0, maxvalue + 1):

                            newlengths[(length[0], elem)] = elem

                else:
                    LOG.critical(length, lengths)
                    raise NotImplementedError

            LOG.debug("Pass 1: %s", set(lengths.values()))

            if newlengths is not None:

                for length in lengths_to_remove:
                    del lengths[length]

                for key, value in newlengths.items():
                    lengths[key] = value

            LOG.debug("Pass 2: %s", set(lengths.values()))

        LOG.debug("Possible lengths all: %s", set(lengths.values()))
        for key in list(lengths.keys()):
            if lengths[key] <= 0:
                del lengths[key]
        LOG.debug("Possible lengths final: %s", set(lengths.values()))

        assert "reg_range" not in list(lengths.values()), lengths
        assert len(lengths) > 0
        for elem in lengths.values():
            assert isinstance(elem, six.integer_types), elem

        self._possible_lengths = lengths

    def possible_lengths(self, context):
        """

        :param context:

        """

        # if self._possible_lengths_set is not None:
        #    return self._possible_lengths_set

        self._compute_possible_lengths(context)

        if not self.variable_length:
            return self._possible_lengths
        else:
            return list(self._possible_lengths.values())

    def possible_addresses(self, dummy_context):
        """

        :param dummy_context:

        """
        return self._possible_addresses

    def set_possible_addresses(self, addreses, dummy_context):
        """Set the possible addresses for the memory operand.

        :param addreses:
        :param dummy_context:

        """
        assert self._possible_addresses is None
        self._possible_addresses = addreses

    def unset_possible_addresses(self):
        """Unset the possible addresses of the memory operand."""
        self._possible_addresses = None

    def set_alignment(self, alignment):
        """Set the required alignment of the memory operand.

        :param alignment: alignment
        :type alignment: :class:`~.int`
        """
        assert self._alignment is None
        self._alignment = alignment

    def alignment(self):
        """Required alignment of the memory operand (::class:`~.int`)."""
        return self._alignment

    def set_possible_lengths(self, lengths, dummy_context):
        """

        :param lengths:
        :param dummy_context:

        """
        assert self._possible_lengths_set is None
        self._possible_lengths_set = lengths

    def unset_possible_lengths(self):
        """Unset the possible lengths of the memory operand."""
        self._possible_lengths_set = None

    def set_forbidden_address_range(self, min_address, max_address,
                                    dummy_context):
        """

        :param min_address:
        :param max_address:
        :param dummy_context:

        """
        self._forbidden_min = min_address
        self._forbidden_max = max_address

    def set_length(self, length, context):
        """

        :param length:
        :param context:

        """

        LOG.debug("Start set length: %s", length)
        assert isinstance(length, six.integer_types), length

        if self._unset_length_function is not None:
            self._unset_length_function()

        self._compute_possible_lengths(context)

        operand_values = [
            key
            for key in self._possible_lengths
            if self._possible_lengths[key] == length
        ]

        LOG.debug("Operand value required: %s", operand_values)

        # free memory?
        self._possible_lengths = None

        operands = []
        for operand in self._length_values:
            if isinstance(operand, (InstructionOperandValue,
                                    OperandDescriptor)):
                operands.append(operand)
            elif isinstance(operand, tuple):
                if operand[1] == "MASK":
                    operands.append(operand[0])
                elif (isinstance(operand[1], InstructionOperandValue) and
                      isinstance(operand[2], InstructionOperandValue)):
                    operands.append(operand[1])
                    operands.append(operand[2])
                elif (operand[1] == "REGMAX" and
                      isinstance(operand[2], InstructionOperandValue)):
                    # operands.append(max(operand[2].type.values()))
                    operands.append(operand[2])
                else:
                    raise NotImplementedError
            elif isinstance(operand, six.integer_types):
                continue
            elif operand.startswith("*") and operand[1:].isdigit():
                continue
            elif operand.startswith("+") and operand[1:].isdigit():
                continue
            elif operand == "-":
                continue
            elif operand.startswith("-") and operand[1:].isdigit():
                continue
            elif operand.startswith("min") and operand[3:].isdigit():
                continue
            elif operand.startswith("CEIL") and operand[4:].isdigit():
                continue
            else:
                raise NotImplementedError

        if len(operand_values) >= 1:

            # Take the first one values that sets the length (if register
            # dependent, get first the one with value already there)
            operand_values = operand_values[0]

        elif len(operand_values) == 0:
            raise MicroprobeCodeGenerationError("Unable to generate the "
                                                "requested length")

        LOG.debug("Operand to use: %s", operands)

        # TODO: Why this check?
        if isinstance(operand_values, tuple):

            if (isinstance(operand_values[0], Register) and
                    isinstance(operand_values[1], Register)):

                operand_values = [operand_values[0], operand_values[1]]

            else:

                operand_values = [operand_values]

        else:

            operand_values = [operand_values]

        assert len(operands) == len(operand_values)

        for operand, operand_value in zip(operands, operand_values):
            if isinstance(operand, OperandDescriptor):
                # is a register constant
                register = operand_value[0]
                value = operand_value[1]

                if context.get_register_value(register) != value:

                    raise MicroprobeCodeGenerationError(
                        "Unable to generate the requested length. Need the "
                        "register '%s' to be set to '%s' value" %
                        (register, value))

                # Register used for length (conservative approach, reserve it)
                if register not in context.reserved_registers:
                    context.add_reserved_registers([register])

            elif isinstance(operand_value, tuple):

                register = operand_value[0]
                value = operand_value[1]

                operand.set_value(register)

                if (value is not None and
                        context.get_register_value(register) != value):

                    LOG.debug("Context: %s", context.dump())
                    LOG.debug("Register used: %s", register)

                    raise MicroprobeCodeGenerationError(
                        "Unable to generate the requested length. Need a "
                        "register initialized to value: %s" % value)

                # Register used for length (conservative approach, reserve it)
                if register not in context.reserved_registers:
                    context.add_reserved_registers([register])

            else:

                operand.set_value(operand_value)

        self._length = length
        self._check_forbidden_range()

        if self._set_length_function is not None:
            self._set_length_function(length, context)

        LOG.debug("End set length: %s", length)

    def update_address(self, address):
        """

        :param address:
        :param context:

        """
        self._address = address

    def set_address(self, address, context):
        """

        :param address:
        :param context:

        """

        LOG.debug("Start setting address to: %s", address)

        if self._possible_addresses is not None:
            LOG.debug("Check address in possible addresses")
            assert address in self._possible_addresses

        if self._unset_address_function is not None:
            self._unset_address_function()

        base = address.base_address
        address_base = Address(base_address=base, displacement=0)
        index = address.displacement

        base_operand = None
        index_operand_reg = None
        index_operand_imm = None
        relative_operand = None

        # for operand in self.descriptor.type.address_operands.values():
        for idx, operand in enumerate(self.operands):

            LOG.debug("Operand %d: '%s'", idx, operand)

            if operand.descriptor.type.address_base and base_operand is None:
                LOG.debug("Base operand %d: %s", idx, operand)
                base_operand = operand

            if (operand.descriptor.type.address_index and
                    index_operand_reg is None):
                LOG.debug("Index operand %d: %s", idx, operand)
                index_operand_reg = operand

            if (operand.descriptor.type.address_immediate and
                    index_operand_imm is None):
                LOG.debug("Immediate operand %d: %s", idx, operand)
                index_operand_imm = operand

            if (operand.descriptor.type.address_relative and
                    relative_operand is None):
                LOG.debug("Relative operand %d: %s", idx, operand)
                relative_operand = operand

        if relative_operand is not None:

            assert base_operand is None
            assert index_operand_imm is None
            assert index_operand_reg is None

            relative_operand.set_value(address)
            self._address = address

            LOG.debug("Relative operand. Set address directly.")
            return

        if self.descriptor.is_agen and base_operand is None:
            raise MicroprobeCodeGenerationError(
                "I do not know how to generate this address: %s" % address)

        if base_operand is None:
            raise MicroprobeCodeGenerationError(
                "I do not know how to generate "
                "this address: %s (no base operand)" % address
            )

        if not base_operand.descriptor.is_input:
            raise MicroprobeCodeGenerationError(
                "I do not know how to generate "
                "this address: %s (no base operand input)" % address
            )

        fast_path = False
        if context.register_has_value(address):
            if context.registers_get_value(address)[0] in \
                    list(base_operand.type.values()):
                fast_path = True

        if fast_path:

            LOG.debug("Address already in context")

            # Check if the address is already in a register
            # FAST PATH
            register_base = context.registers_get_value(address)[0]
            base_operand.set_value(register_base)

            if index_operand_imm is not None:
                index_operand_imm.set_value(0)

            if index_operand_reg is not None:

                register_zero_list = []
                if context.register_has_value(0):

                    register_zero_list = [
                        reg for reg
                        in context.registers_get_value(0)
                        if reg in list(index_operand_reg.type.values())
                    ]

                if len(register_zero_list) == 0:
                    raise MicroprobeCodeGenerationError(
                        "I do not know how to generate this address: %s. "
                        "One of the following registers should be set to zero:"
                        " %s" % (address,
                                 list(index_operand_reg.type.values())))

                index_operand_reg.set_value(register_zero_list[0])

            generated_address = address.copy()

        else:

            LOG.debug("Address not in context")

            # Get all the addresses in the context that have
            # a base address as 'address_base', if none,
            # raise an exception
            possible_base_regs = []

            for reg, value in context.register_values.items():

                if not isinstance(value, Address):
                    continue

                if reg not in list(base_operand.type.values()):
                    continue

                if Address(base_address=value.base_address) == address_base:
                    possible_base_regs.append((reg, value))
                    LOG.debug("Possible base reg: '%s', Address: '%s'",
                              reg.name, value)

            # ensure that we have at least one
            if len(possible_base_regs) == 0:

                LOG.debug("Unable to generate address")

                raise MicroprobeCodeGenerationError(
                    "I do not know how to generate that address. Base address "
                    "not set. Address: %s Context:\n%s" %
                    (address, context.dump()))

            # get the closest address in the context
            closest_index = index - possible_base_regs[0][1].displacement
            closest_reg = possible_base_regs[0][0]
            closest_address = possible_base_regs[0][1]

            for reg, paddress in possible_base_regs[1:]:
                if index - paddress.displacement > 0 and (abs(
                        index - paddress.displacement) < abs(closest_index)):

                    if ((index_operand_imm is None) and
                            not context.register_has_value(
                        index -
                        paddress.displacement
                    )):
                        continue

                    closest_index = index - paddress.displacement
                    closest_reg = reg
                    closest_address = paddress

            register_base = closest_reg
            base_operand.set_value(register_base)
            generated_address = Address(
                base_address=closest_address.base_address,
                displacement=closest_address.displacement)
            index = closest_index

            LOG.debug("Register base: '%s'", register_base.name)
            LOG.debug("Closest index: '%s (0x%x)'", index, index)

        # TODO: some instructions only have base operands
        # if index_operand_reg is not None or index_operand_imm is not None:
        #    assert address == generated_address

        set_index = False
        if (index_operand_imm is not None and not set_index and
                generated_address != address):

            LOG.debug("The instruction has immediate operand, and the "
                      "generated address still needs some extra displacement")
            assert (index_operand_imm.descriptor.is_input and
                    not index_operand_imm.descriptor.is_output)

            try:
                LOG.debug("Setting immediate displacement")
                index_operand_imm.set_value(index)
                set_index = True
                generated_address += index
            except MicroprobeValueError:
                LOG.debug("Unable to generate the address with the current "
                          "context")
                raise MicroprobeCodeGenerationError(
                    "I do not know how to generate that address. Index "
                    "register not set.")

        if (index_operand_reg is not None and not set_index and
                generated_address != address):

            LOG.debug("The instruction has index register operand, and the "
                      "generated address still needs some extra displacement")
            assert (index_operand_reg.descriptor.is_input and
                    not index_operand_reg.descriptor.is_output)

            if not context.register_has_value(index):
                LOG.debug("Unable to generate the address with the current "
                          "context")
                raise MicroprobeCodeGenerationError(
                    "I do not know how to generate that address. Index "
                    "register not set. Change the generation policy.")

            registers_index = context.registers_get_value(index)
            registers_index = [reg for reg in registers_index
                               if reg in list(index_operand_reg.type.values())]

            if len(registers_index) == 0:
                LOG.debug("Unable to generate the address with the current "
                          "context")
                raise MicroprobeCodeGenerationError(
                    "I do not know how to generate that address. Index "
                    "register not set. Change the generation policy.")

            register_index = registers_index[0]
            index_operand_reg.set_value(register_index)
            set_index = True
            generated_address += index
            LOG.debug("Using register: %s", register_index.name)

        if (index_operand_imm is not None and set_index and
                generated_address == address and
                index_operand_imm.value is None):

            LOG.debug("Setting index immediate operand to zero")
            index_operand_imm.set_value(0)

        if (index_operand_reg is not None and set_index and
                generated_address == address and
                index_operand_reg.value is None):

            LOG.debug("Setting index register operand to zero")
            register_zero = context.registers_get_value(0)[0]
            index_operand_reg.set_value(register_zero)

        if address != generated_address:
            LOG.debug("Unable to generate the address. Raising exception.")
            raise MicroprobeCodeGenerationError(
                "I do not know how to generate that address. %s != %s" %
                (address, generated_address))

        for operand in self.operands:

            if operand in [base_operand, index_operand_imm, index_operand_reg]:
                continue

            if operand.descriptor.type.immediate:
                operand.set_value(0)
            else:
                register_zero = context.registers_get_value(0)[0]
                operand.set_value(register_zero)

        self._address = address
        self._check_forbidden_range()

        if self._set_address_function is not None:
            self._set_address_function(address, context)

        if base_operand.descriptor.is_output:
            # TODO: sometimes the base register is also an output (the
            # generated address is placed there. Implement that case (update
            # context accordingly).
            LOG.warning("Base address register is an output. The memory model"
                        " pass should take that into account")

        LOG.debug("End setting address")

    def update_address_from_operands(self, context=None):
        """

        :param context:
        :type context:
        """
        assert self._address is None

        for operand in self.operands:
            if operand.value is None:
                # Unable to update anything if some operad does not have value
                return

        # Only fixing relative operands.
        if (len(self.operands) == 1 and
                self.operands[0].type.address_relative and
                isinstance(self.operands[0].value, InstructionAddress)):
            self._address = self.operands[0].value

        if context is not None:
            # TODO: fix other types as well
            pass

    def _check_forbidden_range(self):
        """ """

        if self._address is None:
            return

        if self._length is None:
            return

        if self._forbidden_max is None and self._forbidden_min is None:
            return
        elif (self._forbidden_max is not None and
              self._forbidden_min is not None):

            assert self._address > self._forbidden_max or \
                (self._address + self._length) < self._forbidden_min

    def unset_forbidden_address_range(self):
        """Unset the forbiddend address range."""
        self._forbidden_min = None
        self._forbidden_max = None

    def sets(self):
        """Return the list of registers set by the memory operand.

        :rtype: :class:`~.list` of :class:`~.Register`
        """
        if not self.is_store:
            return []

        raise NotImplementedError
        # return self._address

    def uses(self):
        """Return the list of registers used by the memory operand.

        :rtype: :class:`~.list` of :class:`~.Register`
        """
        if not self.is_load:
            return []

        raise NotImplementedError
        # return self._address

    def __getattr__(self, name):
        """

        :param name:

        """
        try:
            return self._memory_operand_descriptor.__getattribute__(name)
        except AttributeError:
            raise AttributeError("'%s' object has no attribute '%s'" %
                                 (self.__class__.__name__, name))

    def __repr__(self):
        """ """
        return "%s(Type: %s, Address: %s)" % (self.__class__.__name__,
                                              str(self.type), self.address)


class Instruction(Pickable):
    """Class to represent an instruction"""

    def __init__(self):
        """ """
        self._address = None
        self._allowed_regs = []
        self._arch_type = None
        self._comments = []
        self._context_callback_check = RejectingDict()
        self._context_callback_fix = RejectingDict()
        self._decorators = RejectingDict()
        self._dependency_distance = 0
        self._generic_type = None
        self._label = None
        self._mem_operands = []
        self._operands = RejectingOrderedDict()

    def set_arch_type(self, instrtype):
        """

        :param instrtype:

        """
        self._arch_type = instrtype
        self._operands = RejectingOrderedDict()
        self._mem_operands = []
        self._allowed_regs = []
        self._address = None
        self._context_callback_check = RejectingDict()
        self._context_callback_fix = RejectingDict()

        # TODO: now all architecture share operand values but this should
        # be decoupled in the future to support different ISA operand setters

        for field, operand_descr in instrtype.operand_descriptors.items():
            self._operands[field] = InstructionOperandValue(operand_descr)

        for mem_operand_descr in instrtype.memory_operand_descriptors:
            operand_values = []
            for field, operand_type in \
                    mem_operand_descr.type.address_operands.items():

                if field in self._operands:
                    operand_value = self._operands[field]
                    assert operand_type == operand_value.type
                    operand_values.append(operand_value)
                else:
                    operand_value = None
                    for ioperand in instrtype.implicit_operands:

                        if len(list(ioperand.type.values())) > 1:
                            continue

                        if list(ioperand.type.values())[0].name == field:
                            operand_value = InstructionOperandValue(ioperand)
                            break

                    if operand_value is None:
                        raise NotImplementedError

                    assert isinstance(operand_value.type, OperandConstReg)

                    # TODO: memory operand is implicit
                    # force it to be address base (is this generic?)
                    # needed for POWERPC branches to CTR or LR

                    operand_value.descriptor.set_type(OperandConstReg(
                        operand_value.type.name, operand_value.type.
                        description, list(operand_value.type.values())[
                            0], True, False, False, False))
                    operand_value.descriptor.set_type(operand_value.type)

                    operand_value.set_value(operand_value.type.values()[0])

                    operand_values.append(operand_value)

            length_values = []
            for field, operand_type in \
                    mem_operand_descr.type.length_operands.items():

                if isinstance(operand_type, Operand) and field.startswith('M'):

                    length_value = self._operands[field]
                    assert operand_type == length_value.type
                    length_values.append((length_value, "MASK"))

                elif isinstance(operand_type, Operand):

                    length_value = self._operands[field]
                    assert operand_type == length_value.type
                    length_values.append(length_value)

                elif str(operand_type).startswith("#"):

                    rfirst = str(operand_type)[1:].split('-')[0]
                    rsecond = str(operand_type)[1:].split('-')[1]

                    if rfirst in self._operands:
                        length_value_a = self._operands[rfirst]
                    elif rfirst == "REGMAX":
                        length_value_a = rfirst
                    else:
                        raise NotImplementedError

                    if rsecond in self._operands:
                        length_value_b = self._operands[rsecond]
                    else:
                        raise NotImplementedError

                    # assert operand_type == length_value.type
                    length_values.append((operand_type, length_value_a,
                                          length_value_b))

                else:

                    length_values.append(operand_type)

            self._mem_operands.append(InstructionMemoryOperandValue(
                mem_operand_descr, operand_values, length_values))

        for value in instrtype.instruction_checks.values():
            function, args = value
            function(self, *args)

    def register_context_callback(self, key, checking_function,
                                  fixing_function):
        """

        :param key:
        :param checking_function:
        :param fixing_function:

        """

        self._context_callback_check[key] = checking_function
        self._context_callback_fix[key] = fixing_function

    @property
    def context_callbacks(self):
        """Returns the list of context callbacks registered."""
        return [
            (key, self._context_callback_check[key],
             self._context_callback_fix[key])
            for key in self._context_callback_check.keys()
        ]

    def check_context(self, context):
        """

        :param context:

        """

        fixing_callbacks = []
        for key, check_context in self._context_callback_check.items():
            requires_fixing = check_context(context)
            if requires_fixing:
                fixing_callbacks.append(self._context_callback_fix[key])
        return fixing_callbacks

    @property
    def architecture_type(self):
        """Instruction architecture type (:class:`~.InstructionType`)."""
        return self._arch_type

    @property
    def decorators(self):
        """Instruction decorators (:class:`~.dict`). """
        return self._decorators

    def memory_operands(self):
        """Instruction memory operands.

        :rtype:  list of `MemoryOperands`
        """
        assert self._arch_type is not None
        return self._mem_operands

    def operands(self):
        """Instruction operands.

        :rtype: list of `Operands`
        """
        assert self._arch_type is not None
        return list(self._operands.values())

    def copy(self):
        """Return a copy of the instruction.

        :rtype: :class:`~.Instruction`
        """
        new_instruction = Instruction()
        new_instruction.set_arch_type(self.architecture_type)
        for callback in self.context_callbacks:
            new_instruction.register_context_callback(*callback)

        new_instruction.set_operands(
            [op.value for op in self.operands()], check=False
        )

        for reg in self.allowed_regs:
            new_instruction.add_allow_register(reg)

        for comment in self.comments:
            new_instruction.add_comment(comment)

        for dec_key, dec_val in self.decorators.items():
            new_instruction.add_decorator(dec_key, dec_val)

        new_instruction.set_label(self.label)
        if self.address is not None:
            new_instruction.set_address(self.address.copy())

        return new_instruction

    def operand_by_field(self, fieldname):
        """

        :param fieldname:

        """
        assert self._arch_type is not None

        try:
            fieldnames = [
                key for key in self._operands.keys()
                if key.startswith(fieldname)
            ]
            fieldname = fieldnames[0]

            if len(fieldnames) > 1:
                raise MicroprobeArchitectureDefinitionError(
                    "Looking for field name with multiple options. "
                    "Check the definition of instruction type "
                    "'%s'" % self._arch_type)

            return self._operands[fieldname]
        except (KeyError, IndexError):
            raise MicroprobeLookupError(
                "'%s' not in %s" %
                (fieldname, list(
                    self._operands.keys())))

    def operand_fields(self):
        """Instruction field names of the operands.

        :rtype: list of  :class:`~.str`
        """
        assert self._arch_type is not None
        return list(self._operands.keys())

    def __str__(self):
        """ """

        if self._arch_type is None:
            return "Generic '%s' instr. Dep. distance: %d" % \
                (self._generic_type, self._dependency_distance)

        return str(self._arch_type)

    def set_operands(self, values, context=None, check=True):
        """

        :param values:

        """
        if len(values) != len(self.operands()):
            raise MicroprobeCodeGenerationError(
                "Invalid number of operands specified for instruction "
                "'%s'. # Accepted operands: %s\n # Provided operands: %s"
                "\n Operands: %s" %
                (self, len(self.operands()), len(values), self.operands()))

        try:
            for operand, value in zip(self.operands(), values):
                if value is not None:
                    operand.set_value(value, check=check)

        except MicroprobeValueError as exc:
            LOG.debug("Valid operands:")
            for operand in self.operands():
                LOG.debug(operand)
            raise exc

        for memoperand in self.memory_operands():
            memoperand.update_address_from_operands(context=context)

    def sets(self):
        """Return the list of registers set by the instruction.

        :rtype: :class:`~.list` of :class:`~.Register`
        """

        sets = []
        for operand in self.operands():
            sets += operand.sets()

        for ioperand in self._arch_type.implicit_operands:
            if ioperand.is_output:
                sets += list(ioperand.type.values())

        return sets

    def uses(self):
        """Return the list of registers used by the instruction.

        :rtype: :class:`~.list` of :class:`~.Register`
        """

        uses = []
        for operand in self.operands():
            uses += operand.uses()

        for ioperand in self._arch_type.implicit_operands:
            if ioperand.is_input:
                uses += list(ioperand.type.values())

        return uses

    def add_allow_register(self, reg):
        """

        :param reg:

        """
        assert reg not in self._allowed_regs, "Already allowed"
        self._allowed_regs.append(reg)

    def add_comment(self, comment):
        """

        :param comment:
        :type comment:
        """
        self._comments.append(comment)

    def add_decorator(self, name, value):
        """

        :param key: decorator name
        :type key:
        :param value: decorator value
        :type value:
        """

        try:
            self._decorators[name] = {}
            self._decorators[name]['value'] = value
        except MicroprobeDuplicatedValueError:
            raise MicroprobeCodeGenerationError(
                "Decorator '%s' already defined for this instruction." % name)

    def rm_decorator(self, name):
        """

        """
        try:
            self._decorators.pop(name)
        except KeyError:
            raise MicroprobeCodeGenerationError(
                "Decorator '%s' not defined for this instruction." % name)

    @property
    def comments(self):
        """List of comments of the instruction (:class:`~.list`). """
        return self._comments

    def allows(self, reg):
        """

        :param reg:

        """
        return reg in self._allowed_regs

    @property
    def allowed_regs(self):
        """List of allowed registers of the instructon. """
        return self._allowed_regs

    def set_label(self, label):
        """

        :param label:

        """

        if label == "":
            raise MicroprobeCodeGenerationError("Do not set the instruction"
                                                " label to an empty string."
                                                "Set it to None if you want"
                                                " to remove it.")

        self._label = label

    @property
    def label(self):
        """Instruction label (:class:`~.str`)."""
        return self._label

    def assembly(self):
        """Assembly representation of the instruction.

        :rtype: :class:`~.str`
        """

        for operand in self.operands():
            if operand.value is None:
                raise MicroprobeCodeGenerationError(
                    "Unable to generate the assembly of an instruction without"
                    " all the operand values specified")

        if self._label is None:
            return self._arch_type.assembly(list(self._operands.values()))

        return self._label + ":" + \
            self._arch_type.assembly(list(self._operands.values()))

    def binary(self):
        """Binary representation of the instruction.

        :rtype: :class:`~.str`
        """

        for operand in self.operands():
            if operand.value is None:
                raise MicroprobeCodeGenerationError(
                    "Unable to generate the binary of an instruction without"
                    " all the operand values specified")

        return self._arch_type.binary(list(self._operands.values()))

    @property
    def address(self):
        """Instruction address (:class:`~.InstructionAddress`)"""
        return self._address

    def set_address(self, address):
        """

        :param address:

        """
        self._address = address

    def unset_address(self):
        """Unset instruction address."""
        self._address = None

    def __repr__(self):
        """ """
        if self._arch_type is not None:
            return "%s(%s)" % (self._arch_type.name, self._operands)
        else:
            return "%s(%s)" % (self.__class__.__name__, "empty")

    def __getattr__(self, name):
        """If attribute not found, check if the architecture type implements it

        :param name:

        """
        try:
            return self._arch_type.__getattribute__(name)
        except AttributeError:
            try:
                return self._arch_type.__getattr__(name)
            except AttributeError:
                raise AttributeError("'%s' object has no attribute '%s'" %
                                     (self.__class__.__name__, name))

    def __getstate__(self):
        """  """

        # We can not pickle/unpickle some functions.
        # Therefore, we miss that call-back control to maintain
        # the instruction variant.  This is not an issue, since we
        # do not expect to modify the operands.
        # TODO: change operand definition to ensure contant values
        # everywhere.

        state = self.__dict__
        state["_context_callback_check"] = RejectingDict()
        state["_context_callback_fix"] = RejectingDict()

        for operand in state['_operands'].values():
            operand._set_function = None
            operand._unset_function = None

        for memoperand in state['_mem_operands']:
            memoperand._set_address_function = None
            memoperand._unset_address_function = None
            memoperand._set_length_function = None
            memoperand._unset_length_function = None

        return state


def create_dependency_between_ins(output_ins, input_ins, context):
    """

    :param output_ins:
    :param input_ins:
    :param context:

    """

    reserved_registers = set(context.reserved_registers)

    output_operands = [
        operand
        for operand in output_ins.operands()
        if operand.is_output and not operand.type.immediate and
        not operand.type.address_relative and not operand.type.address_base and
        not operand.type.address_index
    ]

    input_operands = [
        operand
        for operand in input_ins.operands()
        if operand.is_input and not operand.type.immediate and
        not operand.type.address_relative and not operand.type.address_base and
        not operand.type.address_index
    ]

    # prioritize the operands that are only inputs or only outputs

    output_operands = [operand for operand in output_operands
                       if not operand.is_input] + \
                      [operand for operand in output_operands
                       if operand.is_input]

    input_operands = [operand for operand in input_operands
                      if not operand.is_output] + \
                     [operand for operand in input_operands
                      if operand.is_output]

    dependency_set = False
    for output_operand in output_operands:
        for input_operand in input_operands:
            if output_operand.value is not None:
                valid_values1 = set([output_operand.value])
            else:
                valid_values1 = set(output_operand.type.values())

            if input_operand.value is not None:
                valid_values2 = set([output_operand.value])
            else:
                valid_values2 = set(input_operand.type.values())

            valid_values1 = valid_values1.difference(reserved_registers)
            valid_values2 = valid_values2.difference(reserved_registers)
            valid_values = valid_values1.intersection(valid_values2)

            if len(valid_values) == 0:
                continue

            valid_value = list(valid_values)[0]

            if output_operand.value is None:
                output_operand.set_value(valid_value)

            if input_operand.value is None:
                input_operand.set_value(valid_value)

            assert len(valid_values.intersection(reserved_registers)) == 0

            dependency_set = True
            break

        if dependency_set:
            break

    return dependency_set


class MicroprobeInstructionDefinition(object):

    def __init__(self, instruction_type, operands, label, address, asm,
                 decorators, comments):

        self._type = instruction_type
        self._operands = operands
        self._label = label
        self._address = address
        self._asm = asm
        self._decorators = decorators
        self._comments = comments

    def get_instruction_type(self):
        return self._type

    def get_operands(self):
        return self._operands

    def get_label(self):
        return self._label

    def get_address(self):
        return self._address

    def get_asm(self):
        return self._asm

    def get_decorators(self):
        return self._decorators

    def get_comments(self):
        return self._comments

    def set_instruction_type(self, value):
        self._type = value

    def set_operands(self, value):
        self._operands = value

    def set_label(self, value):
        self._label = value

    def set_address(self, value):
        if isinstance(value, int):
            value = InstructionAddress(base_address="code", displacement=value)
        self._address = value

    def set_asm(self, value):
        self._asm = value

    def set_decorators(self, value):
        self._decorators = value

    def set_comments(self, value):
        self._comments = value

    def copy(self):

        operands = None
        if self._operands is not None:
            operands = self._operands[:]

        address = None
        if self._address is not None:
            address = self._address.copy()

        decorators = None
        if self._decorators is not None:
            decorators = copy.deepcopy(self._decorators)

        comments = None
        if self._comments is not None:
            comments = self._comments[:]

        return MicroprobeInstructionDefinition(self._type, operands,
                                               self._label, address, self._asm,
                                               decorators, comments)

    instruction_type = property(get_instruction_type, set_instruction_type,
                                None, "type's docstring")
    operands = property(get_operands, set_operands, None,
                        "operands's docstring")
    label = property(get_label, set_label, None, "label's docstring")
    address = property(get_address, set_address, None, "address's docstring")
    asm = property(get_asm, set_asm, None, "asm's docstring")
    decorators = property(get_decorators, set_decorators, None,
                          "decorators's docstring")
    comments = property(get_comments, set_comments, None,
                        "comments's docstring")

    def __str__(self):
        return "%s(%s,%s,%s,%s,%s,%s,%s)" % (
            self.__class__.__name__, self.instruction_type, self.operands,
            self.label, self.address, self.asm, self.decorators, self.comments)

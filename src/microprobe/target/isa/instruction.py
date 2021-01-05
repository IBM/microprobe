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
""":mod:`microprobe.target.isa.instruction` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import abc
import os
import random
import sys
from inspect import getmembers, getmodule, isfunction

# Third party modules
import six
from six.moves import range, zip

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.property import PropertyHolder, import_properties
from microprobe.target.isa.operand import MemoryOperand, \
    MemoryOperandDescriptor, OperandConst, \
    OperandConstReg, OperandDescriptor
from microprobe.target.isa.instruction_field import GenericInstructionField
from microprobe.target.isa.instruction_format import GenericInstructionFormat
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import OrderedDict, getnextf
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "instruction.yaml"
)
LOG = get_logger(__name__)
__all__ = ["import_definition",
           "InstructionType",
           "GenericInstructionType",
           "instruction_type_from_bin"]


# Functions
def import_definition(cls, filenames, args):
    """

    :param filenames:
    :param args:

    """

    LOG.debug("Start importing instruction definitions")
    iformats, defined_operands = args

    defined_memory_operands = []
    instructions = {}

    for filename in filenames:
        instruction_data = read_yaml(filename, SCHEMA)

        if instruction_data is None:
            continue

        for elem in instruction_data:
            name = elem["Name"]
            mnemonic = elem["Mnemonic"]
            opcode = elem["Opcode"]
            descr = elem.get("Description", "No description")
            operands = elem.get("Operands", {})
            ioperands = elem.get("ImplicitOperands", {})
            moperands = elem.get("MemoryOperands", {})
            target_checks = elem.get("TargetChecks", {})
            instruction_checks = elem.get("InstructionChecks", {})

            try:
                iformat = iformats[elem["Format"]]
            except KeyError:
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown "
                    "instruction "
                    "format '%s' in "
                    "instruction "
                    "definition "
                    "'%s' found "
                    "in '%s'" % (
                        elem["Format"], name, filename
                    )
                )

            operands = _merge_operands(
                name, filename, operands, iformat, defined_operands
            )

            ioperands = _translate_ioperands(
                name, filename, ioperands, defined_operands
            )

            moperands = _translate_moperands(
                name, filename, operands, ioperands, moperands,
                defined_memory_operands, iformat
            )

            # target_checks = _translate_callbacks(name, filename,
            #                                                target_checks)

            instruction_checks = _translate_checks(
                name, filename, cls, instruction_checks, operands
            )

            instruction = cls(
                name, mnemonic, opcode, descr, iformat, operands, ioperands,
                moperands, instruction_checks, target_checks
            )

            if name in instructions:
                raise MicroprobeArchitectureDefinitionError(
                    "Duplicated "
                    "definition "
                    "of instruction "
                    " '%s' found "
                    "in '%s'" % (
                        name, filename
                    )
                )

            LOG.debug(instruction)
            instructions[name] = instruction

    for filename in filenames:
        import_properties(filename, instructions)

    LOG.debug("End")

    return instructions


def instruction_type_from_bin(binstr, target):
    """

    :param bin:
    :type bin:
    :param target:
    :type target:
    """

    foperand = OperandConst("raw", "raw", int(binstr, 16))
    fields = [GenericInstructionField(
        "raw", "raw", len(binstr) * 4, False, '?', foperand)]
    iformat = GenericInstructionFormat(
        "raw",
        "raw",
        fields,
        "raw: 0x%s" %
        binstr)
    instr_type = GenericInstructionType(
        "raw",
        "raw",
        "0",
        "Unknown raw code",
        iformat,
        {'raw': [foperand, '?']},
        {},
        [],
        {},
        {}
    )

    for prop in target.nop().properties.values():

        if prop.name == "disable_asm":
            prop.set_value(True)

        instr_type.register_property(prop)

    return instr_type


def _translate_checks(name, filename, cls, checks, dummy_operands):
    """

    :param name:
    :param filename:
    :param checks:
    :param dummy_operands:

    """

    translated_checks = []
    module = getmodule(cls)
    module_filename = module.__file__

    defined_ichecks = GENERIC_INSTRUCTION_CHECKS.copy()

    for key, value in dict(getmembers(module, isfunction)).items():
        defined_ichecks[key] = value

    for check in checks.values():

        fname = check[0]
        fargs = check[1:]

        try:
            function = defined_ichecks[fname]
            translated_checks.append((fname, (function, fargs)))
        except KeyError:
            raise MicroprobeArchitectureDefinitionError(
                "Definition of "
                "instruction "
                "'%s' in '%s' "
                "requires the "
                "definition of '%s' "
                "in '%s' module with "
                "operands '%s'." % (
                    name, filename, fname, module_filename, fargs
                )
            )

    return dict(translated_checks)


def _translate_moperands(
    name, filename, operands, ioperands, moperands, defined_memory_operands,
    iformat
):
    """

    :param name:
    :param filename:
    :param operands:
    :param ioperands:
    :param moperands:
    :param defined_memory_operands:
    :param iformat:

    """

    roperands = []
    # defined_memory_operands = []

    for memoperand, value in moperands.items():
        formula, length, rate, io_flags = value

        tformula = []
        sformula = []
        tlength = []

        for field in formula:

            if field == "D?":

                voperands = [
                    key for key in operands.keys() if key.startswith("D")
                ]

                vfield = [
                    tfield.name
                    for tfield in iformat.fields if tfield.name.startswith("D")
                ]

                assert sorted(voperands) == sorted(vfield)

                if len(voperands) == 1:

                    field = voperands[0]
                    sformula.append(field)

                elif len(voperands) > 1:

                    end = voperands[0][-1]
                    voperands2 = [
                        voper for voper in voperands if voper.endswith(end)
                    ]

                    if voperands2 == voperands:
                        for voper in voperands:
                            sformula.append(voper)
                    else:

                        number = set(
                            [
                                elem[-1] for elem in formula if elem != "D?"
                            ]
                        )

                        if len(number) != 1:
                            raise MicroprobeArchitectureDefinitionError(
                                "Bad formula in name '%s' in memory operand"
                                " '%s' of instruction '%s' (%s) in filename "
                                "'%s'" % (
                                    field, memoperand, name, iformat.name,
                                    filename
                                )
                            )
                        number = number.pop()
                        sformula.append("D%s" % number)

            else:
                sformula.append(field)

        for field in sformula:

            if isinstance(field, six.integer_types):
                field = str(field)

            if field.startswith('@'):
                try:
                    field = [
                        elem
                        for elem in operands.keys()
                        if elem[0] == field[1] and elem[-3:] == field[-3:]
                    ][0]
                except IndexError:
                    pass
                    # raise MicroprobeArchitectureDefinitionError(
                    #     "Bad formula in name '%s' in memory operand"
                    #     " '%s' of instruction '%s' (%s) in filename '%s'" %
                    #     (field, memoperand, name, iformat.name, filename)
                    # )

            if field in operands:
                tformula.append((field, operands[field][0]))
            elif field in ioperands:
                tformula.append((field, ioperands[field].type))
            else:
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown field name '%s' in memory operand"
                    " '%s' of instruction '%s' (%s) in filename '%s'" %
                    (field, memoperand, name, iformat.name, filename)
                )

        for idx, field in enumerate(length):
            fname = "no_field_%s" % idx
            if isinstance(field, six.integer_types):
                tlength.append((fname, field))
            elif (
                field.startswith("#") or field.startswith("min") or
                field.startswith("max") or field.startswith("*") or
                field.startswith("CEIL") or field == "Unknown" or
                field.startswith("+") or field.startswith("-")
            ):
                tlength.append((fname, field))
            else:

                if field.endswith("_"):
                    field = field[0:-1]

                pfields = [
                    key for key in operands.keys() if key.startswith(field)
                ]

                if len(pfields) == 1:
                    field = pfields[0]

                try:
                    tlength.append((field, operands[field][0]))
                except KeyError:
                    try:
                        tlength.append((field, ioperands[field]))
                    except Exception:
                        raise MicroprobeArchitectureDefinitionError(
                            "Unknown field name '%s' in length of "
                            "memory operand '%s' of instruction '%s' in"
                            " filename '%s'" % (
                                field, memoperand, name, filename
                            )
                        )

        memory_operand = MemoryOperand(
            OrderedDict(tformula), OrderedDict(tlength)
        )

        is_defined = [
            operand
            for operand in defined_memory_operands if operand == memory_operand
        ]

        if len(is_defined) > 0:
            memory_operand = is_defined[0]
        else:
            defined_memory_operands.append(memory_operand)

        roperands.append(
            MemoryOperandDescriptor(
                memory_operand, io_flags, rate
            )
        )

    return roperands


def _translate_ioperands(name, filename, ioperands, defined_operands):
    """

    :param name:
    :param filename:
    :param ioperands:
    :param defined_operands:

    """
    roperands = {}

    for regname, value in ioperands.items():

        operand_name, io_def = value
        try:
            operand = defined_operands[operand_name]
        except KeyError:
            raise MicroprobeArchitectureDefinitionError(
                "Unknown operand name '%s' in definition "
                "of instruction '%s' in filename '%s'" % (
                    operand_name, name, filename
                )
            )

        try:
            if operand.constant:
                reg = operand.random_value()
            else:
                reg = [
                    value for value in operand.values()
                    if value.name == regname
                ][0]
        except IndexError:
            raise MicroprobeArchitectureDefinitionError(
                "Unknown constant register value '%s' in definition "
                "of instruction '%s' in filename '%s'" % (
                    regname, name, filename
                )
            )

        try:
            operand = defined_operands[reg.name]
        except KeyError:
            operand = OperandConstReg(
                "ConstantReg-%s" % reg.name, "Constant register %s" % reg.name,
                reg, False, False, False, False
            )
            LOG.debug("Operand added: %s", operand)
            defined_operands[reg.name] = operand

        if not operand.constant:
            raise MicroprobeArchitectureDefinitionError(
                "Implicit operand defined but it is not constant in"
                " definition of instruction '%s' in filename '%s'" %
                (name, filename)
            )

        # TODO: This can be improved, we can recycle operand
        # descriptors if operand and I/O are the same
        roperands[regname] = OperandDescriptor(
            operand, "I" in io_def, "O" in io_def
        )

    return roperands


def _merge_operands(name, filename, loperands, iformat, defined_operands):
    """

    :param name:
    :param filename:
    :param loperands:
    :param iformat:
    :param defined_operands:

    """

    # print operands, iformat, defined_operands
    roperands = {}

    # Get default operands from ifields
    for field in iformat.fields:
        roperands[field.name] = [field.default_operand, field.default_io]

    # Overwrite with the specific for the instruction
    fields_processed = []

    for operand_description in loperands.values():
        operand_name, field_name, field_io = operand_description

        if field_name not in roperands:

            field_names = [
                field
                for field in roperands.keys()
                if field.split("_")[0] == field_name
                # if field.startswith(field_name)
            ]

            if len(field_names) == 0:
                LOG.debug("Fields: %s", roperands.keys())
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown instruction field '%s' in instruction definition"
                    " '%s' found in '%s'" % (field_name, name, filename)
                )
            elif len(field_names) > 1:
                raise MicroprobeArchitectureDefinitionError(
                    "Multiple matches for instruction field '%s' in "
                    "instruction definition"
                    " '%s' found in '%s'. Candidates: %s" %
                    (field_name, name, filename, field_names))
            else:
                field_name = field_names[0]

        # Fix names referring to original operands
        if operand_name.startswith("@ORIG@"):
            operand_name = operand_name.replace(
                "@ORIG@", roperands[field_name][0].name
            )

        try:
            operand = defined_operands[operand_name]

        except KeyError:

            # Try for a constant
            constant_value = None

            try:
                constant_value = int(operand_name, 0)
            except ValueError:
                constant_value = None

            if constant_value is not None:
                operand = OperandConst(
                    "Constant-%s" % operand_name,
                    "Constant value %s" % operand_name, constant_value
                )
                defined_operands[operand_name] = operand
                LOG.debug("Operand added: %s", operand)
            else:
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown instruction operand '%s' in "
                    "instruction definition '%s' found in '%s'" %
                    (operand_name, name, filename)
                )

        if field_name in fields_processed:
            raise MicroprobeArchitectureDefinitionError(
                "Field '%s' processed twice. Check definition"
                " instruction '%s' in file '%s'" % (
                    field_name, name, filename
                )
            )

        roperands[field_name] = [operand, field_io]
        fields_processed.append(field_name)

    return roperands


# Generic Instruction checks
def _check_reg_value(instruction, register_name, value, condition):
    """

    :param instruction:
    :param register_name:
    :param value:
    :param condition:

    """

    key = register_name, value, condition
    operand = instruction.operand_by_field(register_name)
    valid_values = list(operand.type.values())

    def checking_function_true(context):
        """

        :param context:

        """

        if context.register_has_value(value):

            registers = [
                register
                for register in context.registers_get_value(value)
                if register in context.reserved_registers
            ]

            for register in operand.type.values():
                if register not in registers:
                    return True

            return False

        return True

    def checking_function_false(context):
        """

        :param context:

        """

        for register in operand.type.values():
            context_value = context.get_register_value(register)

            if context_value is None:
                return True

            if context_value == value:
                return True

        return False

    def fixing_function_false(target, building_block):
        """

        :param target:
        :param building_block:

        """

        assert operand.is_input and not operand.is_output

        registers = [
            reg
            for reg in valid_values
            if reg in building_block.context.reserved_registers and
            building_block.context.get_register_value(reg) != value
        ]

        if len(registers) == 0:

            valid_registers = [
                reg
                for reg in valid_values
                if reg not in building_block.context.reserved_registers
            ]

            assert len(valid_registers) > 0
            register = valid_registers[0]

            random_value = value
            while random_value == value:
                random_value = random.randint(0, (2**(register.type.size - 1)))

            instructions = target.set_register(
                register, random_value, building_block.context
            )

            building_block.context.add_reserved_registers([register])
            building_block.context.set_register_value(register, random_value)
            building_block.add_init(instructions)
            registers = [register]

        new_descriptor_operand = operand.descriptor.copy()

        new_type_operand = new_descriptor_operand.type.copy()
        new_type_operand.set_valid_values(registers)

        new_descriptor_operand.set_type(new_type_operand)
        operand.set_descriptor(new_descriptor_operand)

    def fixing_function_true(target, building_block):
        """

        :param target:
        :param building_block:

        """

        if not building_block.context.register_has_value(value):

            valid_registers = [
                reg
                for reg in valid_values
                if reg not in building_block.context.reserved_registers
            ]

            assert len(valid_registers) > 0
            register = valid_registers[0]

            instructions = target.set_register(
                register, value, building_block.context
            )

            building_block.context.add_reserved_registers([register])
            building_block.context.set_register_value(register, value)
            building_block.add_init(instructions)

        registers = [
            register
            for register in building_block.context.registers_get_value(value)
            if register in building_block.context.reserved_registers
        ]

        new_descriptor_operand = operand.descriptor.copy()

        new_type_operand = new_descriptor_operand.type.copy()
        new_type_operand.set_valid_values(registers)

        new_descriptor_operand.set_type(new_type_operand)
        operand.set_descriptor(new_descriptor_operand)

    if condition is False:

        instruction.register_context_callback(
            key, checking_function_false, fixing_function_false
        )
    else:

        instruction.register_context_callback(
            key, checking_function_true, fixing_function_true
        )


def _check_reg_bit_value(instruction, register_name, bit, value, condition):
    """

    :param instruction:
    :param register_name:
    :param bit:
    :param value:
    :param condition:

    """

    key = register_name, bit, value, condition

    if bit.isdigit():
        bit_min = int(bit)
        bit_max = int(bit) + 1
    elif ":" in bit:
        bit = bit.split(":")
        bit_min = int(bit[0])
        bit_max = int(bit[1]) + 1
    else:
        raise NotImplementedError

    assert bit_min < bit_max

    mask = int("".join(['1'] * (bit_max - bit_min) + ['0'] * bit_min), 2)
    shift = bit_min

    cannary_value = 123456789123456789

    def checking_function(context):
        """

        :param context:

        """

        register_value = context.get_registername_value(register_name)

        if register_value is None:
            return True

        if register_value is cannary_value:
            return False

        bits_value = (register_value & mask) >> shift
        return (bits_value == value) != condition

    def fixing_function(target, building_block):
        """

        :param target:
        :param building_block:

        """

        register = target.registers[register_name]
        instructions = target.set_register_bits(
            register, value, mask, shift, building_block.context
        )

        if register not in building_block.context.reserved_registers:
            building_block.context.add_reserved_registers([register])

        building_block.context.set_register_value(register, cannary_value)
        building_block.add_init(instructions)

    instruction.register_context_callback(
        key, checking_function, fixing_function
    )


def _check_operands(
    instruction, operand1_name, operand2_name, check_type, condition
):
    """

    :param instruction:
    :param operand1_name:
    :param operand2_name:
    :param check_type:
    :param condition:

    """

    operand1 = instruction.operand_by_field(operand1_name)
    operand2 = instruction.operand_by_field(operand2_name)

    orig_descriptor_operand1 = operand1.descriptor
    orig_descriptor_operand2 = operand2.descriptor

    # new_descriptor_operand1 = operand1.descriptor.copy()
    # new_descriptor_operand2 = operand2.descriptor.copy()

    # new_type_operand1 = new_descriptor_operand1.type.copy()
    # new_type_operand2 = new_descriptor_operand2.type.copy()

    if check_type == "less" and condition is False:
        check_type = "greater_equal"

    if check_type == "equal":

        def function_set_operand1(value):
            """

            :param value:

            """

            assert operand1.value == value

            new_descriptor_operand2 = operand2.descriptor.copy()
            new_type_operand2 = new_descriptor_operand2.type.copy()

            operand2.set_descriptor(new_descriptor_operand2)
            new_descriptor_operand2.set_type(new_type_operand2)

            LOG.debug("Ins: %s", instruction)
            LOG.debug("Setting operand 1 to: %s", value)

            previous_values = list(new_type_operand2.values())

            if condition:
                new_type_operand2.set_valid_values([value])
                assert list(new_type_operand2.values()) == [value]
            else:
                new_type_operand2.set_valid_values(
                    [
                        elem
                        for elem in orig_descriptor_operand2.type.values(
                        ) if elem != value
                    ]
                )

            # LOG.debug("Orig operand 2 values: %s",
            #          orig_descriptor_operand2.type.values())
            # LOG.debug("New operand 2 values: %s", new_type_operand2.values())

            LOG.debug(
                "Removed from orig: %s",
                set(orig_descriptor_operand2.type.values()) -
                set(new_type_operand2.values())
            )

            LOG.debug(
                "Removed from previous: %s",
                set(previous_values) - set(new_type_operand2.values())
            )

            assert len(
                set(new_type_operand2.values()) - set(
                    orig_descriptor_operand2.type.values()
                )
            ) == 0

        def function_set_operand2(value):
            """

            :param value:

            """

            assert operand2.value == value

            new_descriptor_operand1 = operand1.descriptor.copy()
            new_type_operand1 = new_descriptor_operand1.type.copy()

            operand1.set_descriptor(new_descriptor_operand1)
            new_descriptor_operand1.set_type(new_type_operand1)

            LOG.debug("Ins: %s", instruction)
            LOG.debug("Setting operand 2 to: %s", value)

            previous_values = list(new_type_operand1.values())

            if condition:
                new_type_operand1.set_valid_values([value])
            else:
                new_type_operand1.set_valid_values(
                    [
                        elem
                        for elem in orig_descriptor_operand1.type.values(
                        ) if elem != value
                    ]
                )

            # LOG.debug("Orig operand 1 values: %s",
            #          orig_descriptor_operand1.type.values())
            # LOG.debug("New operand 1 values: %s", new_type_operand1.values())

            LOG.debug(
                "Removed from orig: %s",
                set(orig_descriptor_operand1.type.values()) -
                set(new_type_operand1.values())
            )

            LOG.debug(
                "Removed from previous: %s",
                set(previous_values) - set(new_type_operand1.values())
            )

            assert len(
                set(new_type_operand1.values()) - set(
                    orig_descriptor_operand1.type.values()
                )
            ) == 0

        def function_unset_operand1():
            """ """
            operand2.set_descriptor(orig_descriptor_operand2)

        def function_unset_operand2():
            """ """
            operand1.set_descriptor(orig_descriptor_operand1)

        operand1.register_operand_callbacks(
            function_set_operand1, function_unset_operand1
        )

        operand2.register_operand_callbacks(
            function_set_operand2, function_unset_operand2
        )
    elif check_type == "less":

        new_base_descriptor_operand1 = operand1.descriptor.copy()
        new_base_type_operand1 = new_base_descriptor_operand1.type.copy()

        new_base_descriptor_operand2 = operand2.descriptor.copy()
        new_base_type_operand2 = new_base_descriptor_operand2.type.copy()

        # first remove the maximum value of operand1, so that it is never used
        # and also remove the minimum value of operand2, so that it is never
        # used
        operand1.set_descriptor(new_base_descriptor_operand1)
        new_base_descriptor_operand1.set_type(new_base_type_operand1)
        new_base_type_operand1.set_valid_values(
            [
                elem
                for elem in orig_descriptor_operand1.type.values()
                if len(
                    [
                        value for value in
                        orig_descriptor_operand2.type.values() if value > elem
                    ]
                ) > 0
            ]
        )

        orig_descriptor_operand1 = operand1.descriptor

        operand2.set_descriptor(new_base_descriptor_operand2)
        new_base_descriptor_operand2.set_type(new_base_type_operand2)
        new_base_type_operand2.set_valid_values(
            [
                elem
                for elem in orig_descriptor_operand2.type.values()
                if len(
                    [
                        value for value in
                        orig_descriptor_operand1.type.values() if value < elem
                    ]
                ) > 0
            ]
        )

        orig_descriptor_operand2 = operand2.descriptor

        # print(operand1_name)
        # print(orig_descriptor_operand1.type.values())

        # print(operand2_name)
        # print(orig_descriptor_operand2.type.values())

        def function_set_operand1(value):
            """

            :param value:

            """

            assert operand1.value == value

            LOG.debug("Ins: %s", instruction)
            LOG.debug("Ins id: %s", id(instruction))

            LOG.debug("Setting operand '%s' to: %s", operand1_name, value)

            new_descriptor_operand2 = operand2.descriptor.copy()
            new_type_operand2 = new_descriptor_operand2.type.copy()

            operand2.set_descriptor(new_descriptor_operand2)
            new_descriptor_operand2.set_type(new_type_operand2)

            previous_values = set(new_type_operand2.values())

            new_type_operand2.set_valid_values(
                [
                    elem
                    for elem in orig_descriptor_operand2.type.values(
                    ) if elem > value
                ]
            )

            new_values = set(new_type_operand2.values())

            LOG.debug(
                "Operand '%s' values: %s", operand2_name, previous_values
            )
            LOG.debug("Operand '%s' new values: %s", operand2_name, new_values)
            LOG.debug("Operand differences: %s", previous_values - new_values)

        def function_set_operand2(value):
            """

            :param value:

            """

            assert operand2.value == value

            LOG.debug("Ins: %s", instruction)
            LOG.debug("Ins id: %s", id(instruction))

            LOG.debug("Setting operand '%s' to: %s", operand2_name, value)

            new_descriptor_operand1 = operand1.descriptor.copy()
            new_type_operand1 = new_descriptor_operand1.type.copy()

            operand1.set_descriptor(new_descriptor_operand1)
            new_descriptor_operand1.set_type(new_type_operand1)

            previous_values = set(new_type_operand1.values())

            new_type_operand1.set_valid_values(
                [
                    elem
                    for elem in orig_descriptor_operand1.type.values(
                    ) if elem < value
                ]
            )

            new_values = set(new_type_operand1.values())

            LOG.debug(
                "Operand '%s' values: %s", operand1_name, previous_values
            )
            LOG.debug("Operand '%s' new values: %s", operand1_name, new_values)
            LOG.debug("Operand differences: %s", previous_values - new_values)

        def function_unset_operand1():
            """ """
            operand2.set_descriptor(orig_descriptor_operand2)

        def function_unset_operand2():
            """ """
            operand1.set_descriptor(orig_descriptor_operand1)

        operand1.register_operand_callbacks(
            function_set_operand1, function_unset_operand1
        )

        operand2.register_operand_callbacks(
            function_set_operand2, function_unset_operand2
        )

    else:

        raise NotImplementedError(
            "Condition '%s' not implemented" % check_type
        )


def _check_memops_overlap(instruction, overlap_type, condition):
    """

    :param instruction:
    :param overlap_type:
    :param condition:

    """

    assert len(instruction.memory_operands()) == 2, "Memory operands overlap" \
                                                    " check requires 2 memory"\
                                                    " operands"
    operand1 = instruction.memory_operands()[0]
    operand2 = instruction.memory_operands()[1]

    def function_unset_operand1():
        """ """
        operand2.unset_possible_addresses()
        operand2.unset_possible_lengths()
        operand2.unset_forbidden_address_range()

    def function_unset_operand2():
        """ """
        operand1.unset_possible_addresses()
        operand1.unset_possible_lengths()
        operand1.unset_forbidden_address_range()

    def function_set_operand1_address(address, context):
        """

        :param address:
        :param context:

        """
        assert operand1.address == address
        if operand1.length is not None:
            function_set_operand1(context)

    def function_set_operand1_length(length, context):
        """

        :param length:
        :param context:

        """
        assert operand1.length == length
        if operand1.address is not None:
            function_set_operand1(context)

    def function_set_operand2_address(address, context):
        """

        :param address:
        :param context:

        """
        assert operand2.address == address
        if operand2.length is not None:
            function_set_operand2(context)

    def function_set_operand2_length(length, context):
        """

        :param length:
        :param context:

        """
        assert operand2.length == length
        if operand2.address is not None:
            function_set_operand2(context)

    if overlap_type == "1_bytes_destructive":

        def function_set_operand1(context):
            """

            :param context:

            """

            possible_address1 = operand1.address + operand1.length - 1
            possible_address2 = operand1.address - operand1.length + 1

            if condition is True:
                operand2.set_possible_addresses(
                    [
                        possible_address1, possible_address2
                    ], context
                )
                operand2.set_possible_lengths([operand1.length], context)
            else:
                operand2.set_forbidden_address_range(
                    possible_address1,
                    possible_address2,
                    context)

        def function_set_operand2(context):
            """

            :param context:

            """

            possible_address1 = operand2.address + operand2.length - 1
            possible_address2 = operand2.address - operand2.length + 1

            if condition is True:
                operand1.set_possible_addresses(
                    [
                        possible_address1, possible_address2
                    ], context
                )
                operand1.set_possible_lengths([operand2.length], context)
            else:
                operand1.set_forbidden_address_range(
                    possible_address1,
                    possible_address2,
                    context)

        operand1.register_mem_operand_callback(
            function_set_operand1_address, function_set_operand1_length,
            function_unset_operand1, function_unset_operand1
        )

        operand2.register_mem_operand_callback(
            function_set_operand2_address, function_set_operand2_length,
            function_unset_operand2, function_unset_operand2
        )

    elif overlap_type == "8_bytes_destructive":

        def function_set_operand1(context):
            """

            :param context:

            """

            possible_address1 = operand1.address + operand1.length - 8
            possible_address2 = operand1.address - operand1.length + 8

            if condition is True:
                operand2.set_possible_addresses(
                    [
                        possible_address1, possible_address2
                    ], context
                )
                operand2.set_possible_lengths([operand1.length], context)
            else:
                raise NotImplementedError

        def function_set_operand2(context):
            """

            :param context:

            """

            possible_address1 = operand2.address + operand2.length - 8
            possible_address2 = operand2.address - operand2.length + 8

            if condition is True:
                operand1.set_possible_addresses(
                    [
                        possible_address1, possible_address2
                    ], context
                )
                operand1.set_possible_lengths([operand2.length], context)
            else:
                raise NotImplementedError

        operand1.register_mem_operand_callback(
            function_set_operand1_address, function_set_operand1_length,
            function_unset_operand1, function_unset_operand1
        )

        operand2.register_mem_operand_callback(
            function_set_operand2_address, function_set_operand2_length,
            function_unset_operand2, function_unset_operand2
        )

    elif overlap_type == "destructive_any" or \
            overlap_type == "destructive_any_or_exact" or \
            overlap_type == "destructive_any_not_exact":

        def function_set_operand1(context):
            """

            :param context:

            """

            min_address = operand1.address
            max_address = operand1.address + operand1.length - 1
            assert max_address >= min_address

            if condition is False:
                operand2.set_forbidden_address_range(
                    min_address, max_address, context
                )
            else:

                alignment = operand2.alignment()
                if alignment is None:
                    alignment = 1

                addresses = [
                    operand1.address +
                    index for index in range(
                        max_address -
                        min_address +
                        1) if (
                        operand1.address +
                        index).displacement %
                    alignment == 0]

                if len(addresses) == 0:
                    raise NotImplementedError

                operand2.set_possible_addresses(addresses, context)

        def function_set_operand2(context):
            """

            :param context:

            """

            min_address = operand2.address
            max_address = operand2.address + operand2.length - 1
            assert max_address >= min_address

            if condition is False:
                operand1.set_forbidden_address_range(
                    min_address, max_address, context
                )
            else:

                alignment = operand2.alignment()
                if alignment is None:
                    alignment = 1

                addresses = [
                    operand2.address +
                    index for index in range(
                        max_address -
                        min_address +
                        1) if (
                        operand2.address +
                        index).displacement %
                    alignment == 0]

                if len(addresses) == 0:
                    raise NotImplementedError

                operand1.set_possible_addresses(addresses, context)

        operand1.register_mem_operand_callback(
            function_set_operand1_address, function_set_operand1_length,
            function_unset_operand1, function_unset_operand1
        )

        operand2.register_mem_operand_callback(
            function_set_operand2_address, function_set_operand2_length,
            function_unset_operand2, function_unset_operand2
        )

    elif overlap_type == "exact":

        def function_set_operand1(context):
            """

            :param context:

            """

            possible_address = operand1.address

            if condition is True:
                operand2.set_possible_addresses([possible_address], context)
                operand2.set_possible_lengths([operand1.length], context)
            else:
                raise NotImplementedError

        def function_set_operand2(context):
            """

            :param context:

            """

            possible_address = operand2.address

            if condition is True:
                operand1.set_possible_addresses([possible_address], context)
                operand1.set_possible_lengths([operand2.length], context)
            else:
                raise NotImplementedError

        operand1.register_mem_operand_callback(
            function_set_operand1_address, function_set_operand1_length,
            function_unset_operand1, function_unset_operand1
        )

        operand2.register_mem_operand_callback(
            function_set_operand2_address, function_set_operand2_length,
            function_unset_operand2, function_unset_operand2
        )

    else:
        # print(overlap_type, condition)
        raise NotImplementedError


def _check_alignment(instruction, operand_idx, alignment):
    """

    :param instruction:
    :param operand_idx:
    :param alignment:

    """

    assert len(instruction.memory_operands()) > operand_idx, \
        "Memory operand alignment check requires %s memory operands" \
        % operand_idx

    operand = instruction.memory_operands()[operand_idx]
    operand.set_alignment(alignment)


GENERIC_INSTRUCTION_CHECKS = {}
for _key, _value in dict(
    getmembers(
        sys.modules[__name__], isfunction
    )
).items():
    if _key.startswith("_check_"):
        GENERIC_INSTRUCTION_CHECKS[_key[1:]] = _value


# Classes
class InstructionType(six.with_metaclass(abc.ABCMeta, PropertyHolder)):
    """Abstract class to represent a machine instruction type."""

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def name(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def mnemonic(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def opcode(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def format(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def operands(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def memory_operand_descriptors(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def operand_descriptors(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def implicit_operands(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def target_checks(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def instruction_checks(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def sets(self, *args):
        """Returns a :class:`~.list` of :class:`~.Register` instances
        set by this :class:`~.InstructionType` when invoked with *args*
        :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.
        :type args: :class:`~.list` of :class:`~.Operand` instances

        """
        raise NotImplementedError

    @abc.abstractmethod
    def uses(self, args):
        """Returns a :class:`~.list` of :class:`~.Register` instances
        used by this :class:`~.InstructionType` when invoked with *args*
        :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.
        :type args: :class:`~.list` of :class:`~.Operand` instances
        :param args:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def assembly(self, args, dissabled_fields=None):
        """Returns the assembly representation of this instruction when
        when invoked with *args* :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.

        """
        raise NotImplementedError

    @abc.abstractmethod
    def binary(self, args, asm_args=None):
        """Return the binary representation of this register when
        when invoked with *args* :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.

        """
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """Return the string representation of this instruction."""
        raise NotImplementedError

    @abc.abstractmethod
    def full_report(self, tabs=0):
        """Return the string representation of this instruction."""
        raise NotImplementedError


class GenericInstructionType(InstructionType):
    """Instruction generic class implementation

    :param iname: Instruction name
    :type iname: :class:`~.str`
    :param idescr: Instruction description
    :type idescr: :class:`~.str`
    :param iformat: Instruction format
    :type iformat: :class:`~.InstructionFormat`

    """

    def __init__(
        self, name, mnemonic, opcode, descr, iformat, operands, ioperands,
        moperands, instruction_checks, target_checks
    ):
        """

        :param name:
        :param mnemonic:
        :param opcode:
        :param descr:
        :param iformat:
        :param operands:
        :param ioperands:
        :param moperands:
        :param instruction_checks:
        :param target_checks:

        """

        super(GenericInstructionType, self).__init__()

        self._name = name
        self._mnemonic = mnemonic
        self._opcode = opcode
        self._descr = descr
        self._format = iformat
        self._operands = OrderedDict(operands)
        self._ioperands = list(ioperands.values())
        self._memoperands = moperands
        self._target_checks = target_checks
        self._instruction_checks = instruction_checks
        self._mask = None

        for key in [field.name for field in iformat.fields]:
            if key not in operands:
                raise MicroprobeArchitectureDefinitionError(
                    "Inconsistent instruction definition. "
                    "Each instruction field should have an operand. "
                    "Instruction: %s", self.name
                )
            else:
                # Sort the operands
                tmp_val = self.operands[key]
                del self.operands[key]
                self.operands[key] = tmp_val

        if list(self.operands.keys()) != [
                field.name for field in iformat.fields]:
            LOG.error("Operands: %s", list(self.operands.keys()))
            LOG.error("Fields: %s", [field.name for field in iformat.fields])
            LOG.error("Instruction format: %s", iformat.name)
            # print(self.operands.keys())
            # print([field.name for field in iformat.fields])
            raise MicroprobeArchitectureDefinitionError(
                "Operands and fields "
                "are not aligned in "
                "'%s'" % self.name
            )

        self._operand_descriptors = OrderedDict()
        for op_descriptor, field in zip(
            list(self.operands.items()), self.format.fields
        ):
            fieldname, op_descriptor = op_descriptor
            operand, io_def = op_descriptor

            if field.name != fieldname:
                raise MicroprobeArchitectureDefinitionError(
                    "Operands and fields are not aligned in '%s" % self.name
                )

            if not field.default_show:
                continue

            # if operand.constant:  # and operand.immediate:
            #     continue

            self._operand_descriptors[field.name] = OperandDescriptor(
                operand, "I" in io_def, "O" in io_def
            )

        opcode_operands = [op for op in operands if op.startswith('opcode')]

        if len(opcode_operands) == 1:
            self.operands[opcode_operands[0]][0] = OperandConst(
                "Opcode", "Instruction opcode", int(self.opcode, 16)
            )
        else:
            # Assume the back-end will take care of multiple operands
            pass

    def _compute_mask(self):

        mask_val_str = "0b"
        mask_str = "0b"
        for op_descriptor, field in zip(
            list(self.operands.items()), self.format.fields
        ):
            dummy_fieldname, op_descriptor = op_descriptor
            format_str = "{0:0%db}" % field.size

            if op_descriptor[0].constant and op_descriptor[
                0
            ].immediate and not field.default_show:

                mask_val_str = mask_val_str + \
                    format_str.format(list(op_descriptor[0].values())[0])
                mask_str = mask_str + "".join(['1'] * field.size)
            elif op_descriptor[0].constant and not op_descriptor[0].immediate:

                mask_val_str = mask_val_str + \
                    format_str.format(
                        int(list(op_descriptor[0].values())[0].representation)
                    )
                mask_str = mask_str + "".join(['1'] * field.size)
            else:

                mask_val_str = mask_val_str + format_str.format(0)
                mask_str = mask_str + "".join(['0'] * field.size)

        assert len(mask_val_str) == self.format.length * 8 + 2, "%s != %s" % (
            len(mask_val_str), self.format.length * 8 + 2
        )
        mask_val = int(mask_val_str, 2)

        assert len(mask_str) == self.format.length * 8 + 2, "%s != %s" % (
            len(mask_str), self.format.length * 8 + 2
        )
        mask = int(mask_str, 2)

        assert mask != 0
        # assert mask_val != 0

        # print("{:032b}".format(mask), "{:032b}".format(mask_val), self.name)

        self._mask = (mask, mask_val)

    @property
    def name(self):
        """ """
        return self._name

    @property
    def mnemonic(self):
        """ """
        return self._mnemonic

    @property
    def description(self):
        """ """
        return self._descr

    @property
    def opcode(self):
        """ """
        return self._opcode

    @property
    def operands(self):
        """ """
        return self._operands

    @property
    def memory_operand_descriptors(self):
        """ """
        return self._memoperands

    @property
    def operand_descriptors(self):
        """ """
        return self._operand_descriptors

    @property
    def implicit_operands(self):
        """ """
        return self._ioperands

    @property
    def format(self):
        """ """
        return self._format

    @property
    def instruction_checks(self):
        """ """
        return self._instruction_checks

    @property
    def target_checks(self):
        """ """
        return self._target_checks

    @property
    def bit_mask(self):
        """ """
        if self._mask is None:
            self._compute_mask()
        return self._mask

    def sets(self, *args):
        """Returns a :class:`~.list` of :class:`~.Register` instances
        set by this :class:`~.InstructionType` when invoked with *args*
        :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.
        :type args: :class:`~.list` of :class:`~.Operand` instances

        """
        raise NotImplementedError

    def uses(self, args):
        """Returns a :class:`~.list` of :class:`~.Register` instances
        used by this :class:`~.InstructionType` when invoked with *args*
        :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.
        :type args: :class:`~.list` of :class:`~.Operand` instances

        """
        raise NotImplementedError

    def assembly(self, args, dissabled_fields=None):
        """Returns the assembly representation of this register when
        when invoked with *args* :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.
        :param dissable_fields: list of fields that will not be translated
                                into assembly
        :param dissabled_fields:  (Default value =None)

        """

        LOG.debug("Begin assembly: %s", self.mnemonic)

        if dissabled_fields is None:
            dissabled_fields = []

        next_operand_value = getnextf(iter(args))
        format_str = self.format.assembly_format

        LOG.debug("Assembly string: %s", format_str)
        assembly_str = format_str.replace("OPC", "@@@")

        for op_descriptor, field in zip(
            list(self.operands.items()), self.format.fields
        ):
            fieldname, op_descriptor = op_descriptor
            operand, dummy = op_descriptor

            LOG.debug("Field: %s", fieldname)

            if field.name != fieldname:
                raise MicroprobeArchitectureDefinitionError(
                    "Operands and fields are not aligned in '%s" % self.name
                )

            if not field.default_show:
                LOG.debug("Skip not shown")
                continue

            if field.name in dissabled_fields:
                LOG.debug("Skip dissabled")
                next_operand_value()
                continue

            if operand.constant:

                LOG.debug("Constant")

                if operand.name == "Zero":  # Operand Zero never shows
                    assembly_str = assembly_str.replace(
                        " %s," % field.name, ""
                    )
                    assembly_str = assembly_str.replace(
                        ", %s" % field.name, ""
                    )
                    assembly_str = assembly_str.replace("%s" % field.name, "")
                    assembly_str = assembly_str.replace("()", "")
                else:
                    assembly_str = assembly_str.replace(
                        field.name, next_operand_value().representation
                    )
                    # operand.representation(operand.values()[0])
            else:

                LOG.debug("No constant value")

                if assembly_str.find("@@@ " + field.name + ",") >= 0:

                    assembly_str = assembly_str.replace(
                        "@@@ " + field.name + ",",
                        "@@@ " + next_operand_value().representation + ",", 1
                    )

                elif assembly_str.find(", " + field.name + ",") >= 0:

                    assembly_str = assembly_str.replace(
                        ", " + field.name + ",",
                        ", " + next_operand_value().representation + ",", 1
                    )

                elif assembly_str.endswith(", " + field.name):

                    assembly_str = assembly_str.replace(
                        ", " + field.name,
                        ", " + next_operand_value().representation, 1
                    )

                elif assembly_str.find("@@@ $" + field.name + ",") >= 0:

                    assembly_str = assembly_str.replace(
                        "@@@ $" + field.name + ",",
                        "@@@ $" + next_operand_value().representation + ",", 1
                    )

                elif assembly_str.find(", $" + field.name + ",") >= 0:

                    assembly_str = assembly_str.replace(
                        ", $" + field.name + ",",
                        ", $" + next_operand_value().representation + ",", 1
                    )

                elif assembly_str.endswith(", $" + field.name):

                    assembly_str = assembly_str.replace(
                        ", $" + field.name,
                        ", $" + next_operand_value().representation, 1
                    )

                elif assembly_str.find("@@@ " + field.name) >= 0:

                    assembly_str = assembly_str.replace(
                        "@@@ " + field.name,
                        "@@@ " + next_operand_value().representation, 1
                    )

                elif assembly_str.find("(" + field.name + ")") >= 0:

                    assembly_str = assembly_str.replace(
                        "(" + field.name + ")",
                        "(" + next_operand_value().representation + ")", 1
                    )

                elif assembly_str.find("(" + field.name + ",") >= 0:

                    assembly_str = assembly_str.replace(
                        "(" + field.name + ",",
                        "(" + next_operand_value().representation + ",", 1
                    )

                elif assembly_str.find(" " + field.name + ")") >= 0:

                    assembly_str = assembly_str.replace(
                        " " + field.name + ")",
                        " " + next_operand_value().representation + ")", 1
                    )

                elif assembly_str.find(" " + field.name + "(") >= 0:

                    assembly_str = assembly_str.replace(
                        " " + field.name + "(",
                        " " + next_operand_value().representation + "(", 1
                    )

                elif assembly_str.find("," + field.name + ")") >= 0:

                    assembly_str = assembly_str.replace(
                        "," + field.name + ")",
                        "," + next_operand_value().representation + ")", 1
                    )

                else:
                    LOG.debug(
                        "%s", list(zip(
                            list(self.operands.items()), self.format.fields
                        ))
                    )
                    LOG.debug("Current assembly: %s", assembly_str)

                    raise MicroprobeArchitectureDefinitionError(
                        "Unable to generate correct assembly for '%s' "
                        "instruction" % self.mnemonic
                    )

            LOG.debug("Current assembly: %s", assembly_str)

        assembly_str = assembly_str.replace("@@@", self.mnemonic)

        LOG.debug("End assembly: %s", assembly_str)

        return assembly_str

    def binary(self, args, asm_args=None):
        """Return the binary representation of this register when
        when invoked with *args* :class:`~.list` of :class:`~.Operand`.

        :param args: Input operands.
        :param asm_args:  (Default value = None)

        """

        next_operand_value = getnextf(iter(args))
        binary_str = ""
        field_length = 0

        if asm_args is None:
            asm_args = args

        LOG.debug("Start codification: %s", self.assembly(asm_args))
        LOG.debug("Args: %s", args)

        for op_descriptor, field in zip(
            list(self.operands.items()), self.format.fields
        ):

            fieldname, op_descriptor = op_descriptor
            operand, dummy = op_descriptor

            LOG.debug("Field: %s", fieldname)
            LOG.debug("Descriptor: %s", op_descriptor)
            LOG.debug("Operand: %s", operand)

            if field.name != fieldname:
                raise MicroprobeArchitectureDefinitionError(
                    "Operands and fields are not aligned in '%s" % self.name
                )

            format_field_str = "{0:0%db}" % field.size
            field_length += field.size

            if operand.constant and not field.default_show:

                LOG.debug("Operand is constant")
                opvalue = operand.codification(list(operand.values())[0])

                LOG.debug("Operand value: %s", list(operand.values())[0])

                # if field.default_show:
                #    LOG.debug("Operand is shown")
                #    dummy_operand = next_operand_value()

            else:

                LOG.debug("Operand is not constant or is shown")
                operand = next_operand_value()
                opvalue = operand.descriptor.type.codification(operand.value)
                LOG.debug("Operand value: %s", operand.value)

            LOG.debug("Operand value to codify: %s", opvalue)
            opvalue = int(opvalue)
            LOG.debug("Operand int value: %d", opvalue)

            if opvalue >= (2**field.size):

                LOG.debug("Field name: %s", fieldname)
                LOG.debug("Format field str: %s", format_field_str)
                LOG.debug("Field size: %d", field.size)
                LOG.debug("Max value codificable: %d", 2**field.size)
                LOG.debug("Operand value: %s", opvalue)
                LOG.debug("Instruction name: %s", self.name)

                raise MicroprobeArchitectureDefinitionError(
                    "Operand value can not be codified within the "
                    "instruction field. Operand: %s Value: %d"
                    % (operand, opvalue)
                )

            if opvalue < 0:

                if abs(opvalue) > (2**(field.size - 1)):

                    LOG.debug("Field name: %s", fieldname)
                    LOG.debug("Format field str: %s", format_field_str)
                    LOG.debug("Field size: %d", field.size)
                    LOG.debug("Max value codificable: %d", 2**field.size)
                    LOG.debug("Operand value: %s", opvalue)
                    LOG.debug("Instruction name: %s", self.name)

                    raise MicroprobeArchitectureDefinitionError(
                        "Operand value can not be codified within the "
                        "instruction field. Operand: %s Value: %d"
                        % (operand, opvalue)
                    )

                opvalue = opvalue + 2**field.size

            field_str = format_field_str.format(opvalue)
            binary_str = binary_str + field_str

            LOG.debug("Current binary: %s", binary_str)

        assert field_length == len(binary_str)

        return binary_str

    def match(self, binary):
        """Return a bolean indicating if the binary provided matches the
        intruction binary mask

        :param binary: Binary instruction codification
        :type binary: :class:`~.int`
        :rtype: :class:`~.bool`
        """
        return (binary & self.bit_mask[0]) == self.bit_mask[1]

    def __str__(self):
        """Return the string representation of this instruction"""
        return "%-8s (%10s)  OPC:0x%4s  Format:%8s  Description: %s" % \
            (self.mnemonic, self.name, self.opcode, self.format.name,
             self.description)

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, self._name)

    def __hash__(self):
        return hash(str(self))

    def _check_cmp(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError(
                "%s != %s" % (
                    other.__class__, self.__class__
                )
            )

    def __eq__(self, other):
        """x.__eq__(y) <==> x==y"""
        self._check_cmp(other)
        return self.name == other.name

    def __ne__(self, other):
        """x.__ne__(y) <==> x!=y"""
        self._check_cmp(other)
        return self.name != other.name

    def __lt__(self, other):
        """x.__lt__(y) <==> x<y"""
        self._check_cmp(other)
        return self.name < other.name

    def __gt__(self, other):
        """x.__gt__(y) <==> x>y"""
        self._check_cmp(other)
        return self.name > other.name

    def __le__(self, other):
        """x.__le__(y) <==> x<=y"""
        self._check_cmp(other)
        return self.name <= other.name

    def __ge__(self, other):
        """x.__ge__(y) <==> x>=y"""
        self._check_cmp(other)
        return self.name >= other.name

    def full_report(self, tabs=0):
        """ """

        shift = ("\t" * (tabs + 1))
        fmt = "%-17s : %-30s\n"
        rstr = str(self)
        rstr += "\n\n"
        rstr += shift + "Definition" + "\n"
        rstr += shift + "----------" + "\n"
        rstr += shift + fmt % ("Name", self.name)
        rstr += shift + fmt % ("Mnemonic", self.mnemonic)
        rstr += shift + fmt % ("Opcode", self.opcode)
        for operand, value in self.operand_descriptors.items():
            rstr += shift + \
                fmt % ("Operand %s" % operand,
                       "%s -- \t Input: %s \t Output: %s" % (value.type,
                                                             value.is_input,
                                                             value.is_output))
        for idx, moperand in enumerate(self.memory_operand_descriptors):
            rstr += shift + fmt % ("Memory Operand %d" % idx,
                                   "\n" + moperand.full_report(tabs=tabs + 1))

        for value in self.implicit_operands:
            rstr += shift + \
                fmt % ("Implicit Operand",
                       "%s -- \t Input: %s \t Output: %s" % (value.type,
                                                             value.is_input,
                                                             value.is_output))

        rstr += shift + \
            fmt % ("Instr. Checks", ",".join(self.instruction_checks))

        rstr += shift + \
            fmt % ("Target Checks", ",".join(self.target_checks))

        rstr += "\n"
        rstr += shift + "Format" + "\n"
        rstr += shift + "------" + "\n"
        rstr += self.format.full_report(tabs=tabs + 1)
        rstr += "\n"
        rstr += shift + "Property List" + "\n"
        rstr += shift + "-------------" + "\n"
        rstr += self.list_properties(tabs=tabs + 1)
        return rstr

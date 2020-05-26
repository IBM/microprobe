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
""":mod:`microprobe.utils.asm` module

This module implements the required features to interpret assembly statements
and translate them into Microprobe internal representation of instruction,
operands, labels and addreses.

The main elements of this module are the following:

- :class:`~.MicroprobeAsmInstructionDefinition` objects to represent
  assembly statements (i.e. instruction definitions)
- :func:`~.interpret_asm` function validates the assembly statements and
  translates them into internal Microprobe represenation of instructions and
  operands.
"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import copy
import itertools
import multiprocessing as mp
import os
import re
import string

# Third party modules
import six
from six.moves import range, zip

# Own modules
import microprobe.code.ins
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address, InstructionAddress
from microprobe.exceptions import MicroprobeAsmError, \
    MicroprobeCodeGenerationError, MicroprobeDuplicatedValueError, \
    MicroprobeValueError
from microprobe.target.isa.operand import InstructionAddressRelativeOperand, \
    OperandConst, OperandImmRange, OperandValueSet
from microprobe.utils.bin import interpret_bin
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Progress, RejectingDict, twocs_to_int, \
    range_to_sequence


# Constants
LOG = get_logger(__name__)
_ASM_CACHE = RejectingDict()
_DECORATOR_CACHE = RejectingDict()
__all__ = [
    "interpret_asm", "MicroprobeAsmInstructionDefinition",
    "instruction_to_asm_definition"
]


# Functions
def interpret_asm(code, target, labels, log=True, show_progress=False,
                  parallel=True, queue=None):
    """
    Return the list of :class:`~.MicroprobeInstructionDefinition` objects
    that results from interpreting the *code* (list of assembly statements).
    The *target* object is used to validate the existence of the instruction
    and operands in the target and the *labels* are needed to validate the
    correctness of the symbolic labels used in the assembly statements.

    :param code: Assembly to interpret
    :type code: :class:`list` of :class:`~.MicroprobeAsmInstructionDefinition`
                or string/s to interpret
    :param target: Target definition
    :type target: :class:`~.Target` object
    :param labels: Labels available
    :type labels: :class:`~.list` of :class:`~.str`
    :return: A list of instructions, operands, labels, etc. resulting from
            interpreting the assembly
    :rtype: :class:`~.list` of :class:`~.MicroprobeInstructionDefinition`
    :raise microprobe.exceptions.MicroprobeAsmError: if something is wrong
        during the interpretation
    """

    LOG.debug("Start interpret_asm")
    instructions_and_params = []

    LOG.debug("Extract defined labels")
    def_labels = labels

    if def_labels is None:
        def_labels = []

    if isinstance(code, str):
        code = [code]

    if len(code) > MICROPROBE_RC["parallel_threshold"] and parallel:
        # Do parallel parsing
        processes = []
        queues = []

        chunksize = max(len(code) // MICROPROBE_RC['cpus'], 1)

        extra_args = {}
        extra_args['log'] = log
        extra_args['show_progress'] = show_progress
        extra_args['parallel'] = False

        for chunk in [code[i:i + chunksize]
                      for i in range(0, len(code), chunksize)]:
            queue = mp.Queue()
            extra_args['queue'] = queue
            proc = mp.Process(target=interpret_asm,
                              args=(chunk, target, def_labels),
                              kwargs=extra_args)
            processes.append(proc)
            queues.append(queue)
            proc.start()
            extra_args['show_progress'] = False

        instructions_and_params = []
        for queue in queues:
            instructions_and_params += queue.get()
            queue.close()
            queue.join_thread()

        for process in processes:
            process.join()
            process.terminate()

        return instructions_and_params

    try:

        if show_progress:
            progress = Progress(len(code), msg="Labels parsed:")

        for instr_def in code:

            if isinstance(instr_def, six.string_types):
                instr_def = _str_to_asmdef(instr_def)

            if instr_def.label in def_labels:
                raise MicroprobeAsmError(
                    "Label '%s' defined twice!" % instr_def.label
                )

            if instr_def.label is not None:
                def_labels.append(instr_def.label.upper())

            if show_progress:
                progress()

        if show_progress:
            progress = Progress(len(code), msg="Instructions parsed:")

        for instr_def in code:

            if isinstance(instr_def, six.string_types):
                instr_def = _str_to_asmdef(instr_def)

            intr_asm = _interpret_instr_def(instr_def, target, def_labels)

            instructions_and_params.append(intr_asm)

            LOG.debug("Instruction: '%s' interpreted", instr_def.assembly)

            if show_progress:
                progress()

    except MicroprobeAsmError as exc:

        if log:

            LOG.critical("Assembly provided:")
            LOG.critical(
                "%20s\t%20s\t%25s\t%s", "-" * 20, "-" * 20, "-" * 25, "-" * 20
            )
            LOG.critical(
                "%20s\t%20s\t%25s\t%s", "label", "address", "instruction",
                "decorators"
            )
            LOG.critical(
                "%20s\t%20s\t%25s\t%s", "-" * 20, "-" * 20, "-" * 25, "-" * 20
            )
            for instr in code:
                if isinstance(instr, six.string_types):
                    instr = _str_to_asmdef(instr)

                address = "--"
                if instr.address is not None:
                    address = "0x%016x" % instr.address

                LOG.critical(
                    "%20s\t%20s\t%25s\t%s", instr.label, address,
                    instr.assembly, instr.decorators
                )
            LOG.critical(
                "%20s\t%20s\t%25s\t%s", "-" * 20, "-" * 20, "-" * 25, "-" * 20
            )

            LOG.critical(
                "If the previous assembly is not correct, "
                "check the format of the assembly file provided"
            )
        raise exc

    LOG.debug("End interpret_asm")

    if queue is not None:
        queue.put(instructions_and_params)

    return instructions_and_params


def instruction_to_asm_definition(instr):

    label = instr.label
    instr.set_label(None)
    return MicroprobeAsmInstructionDefinition(
        instr.assembly(), label, instr.address, None, instr.comments
    )


def _interpret_instr_def(instr_def, target, labels):
    """

    :param instr_def:
    :type instr_def:
    :param target:
    :type target:
    :param labels:
    :type labels:
    """

    LOG.debug("Start interpret_asm: '%s'", instr_def)
    if instr_def.assembly in _ASM_CACHE:

        instruction_type, operands = _ASM_CACHE[instr_def.assembly]
        operands = operands[:]

    elif instr_def.assembly.upper().startswith("0X"):

        binary_def = interpret_bin(
            instr_def.assembly[2:], target, fmt="hex", single=True
        )
        if len(binary_def) > 1:
            raise MicroprobeAsmError("More than one instruction parsed.")
        instruction_type = binary_def[0].instruction_type
        operands = binary_def[0].operands
        _ASM_CACHE[instr_def.assembly] = (instruction_type, operands)

    elif instr_def.assembly.upper().startswith("0B"):

        binary_def = interpret_bin(instr_def.assembly[2:], target, fmt="bin")
        if len(binary_def) > 1:
            raise MicroprobeAsmError("More than one instruction parsed.")
        instruction_type = binary_def[0].instruction_type
        operands = binary_def[0].operands
        _ASM_CACHE[instr_def.assembly] = (instruction_type, operands)

    else:

        asm_mnemonic = _extract_asm_mnemonic(instr_def.assembly)
        LOG.debug("Mnemonic: '%s'", asm_mnemonic)

        asm_operands = _extract_asm_operands(instr_def.assembly)
        LOG.debug("Operands: '%s'", asm_operands)

        # This is a work-around for RISC-V objdump implementation.
        # It does not dump negative numbers and the corresponding
        # absolute value is printed. Also a weird +1 needs to be added

        for idx, asm_operand in enumerate(asm_operands):
            if asm_operand.startswith("0XF") and len(asm_operand) == 18:
                nval = hex(
                    int(twocs_to_int(int(asm_operand, 16), 64)) + 1).upper()

                instr_def = list(instr_def)
                instr_def[0] = instr_def[0].upper().replace(
                    asm_operand, nval)
                instr_def = MicroprobeAsmInstructionDefinition(*instr_def)
                asm_operands[idx] = nval

        # End work-around

        asm_mnemonic, asm_operands = target.normalize_asm(asm_mnemonic,
                                                          asm_operands)

        LOG.debug("Norm. mnemonic: '%s'", asm_mnemonic)
        LOG.debug("Norm. Operands: '%s'", asm_operands)

        instruction_types, asm_operands = _find_instr_with_mnemonic(
            asm_mnemonic, asm_operands, target
        )

        LOG.debug(
            "Types detected: '%s'", [
                type_ins.name for type_ins in instruction_types
            ]
        )

        instruction_type, operands = _extract_operands(
            instr_def.assembly, asm_operands, instruction_types, target, labels
        )

        _ASM_CACHE[instr_def.assembly] = (instruction_type, operands)

    address = _extract_address(instr_def.address)

    if instr_def.decorators in _DECORATOR_CACHE:
        decorators = copy.deepcopy(_DECORATOR_CACHE[instr_def.decorators])
    else:
        decorators = _interpret_decorators(instr_def.decorators)
        _DECORATOR_CACHE[instr_def.decorators] = decorators

    label = None
    if instr_def.label is not None:
        label = instr_def.label.upper()

    LOG.debug("End interpret_asm: '%s'", instr_def)
    return microprobe.code.ins.MicroprobeInstructionDefinition(
        instruction_type, operands, label, address, instr_def.assembly,
        decorators, instr_def.comments
    )


def _extract_address(address):
    """

    :param address:
    :type address:
    """
    if address is not None:
        return InstructionAddress(base_address="code", displacement=address)
    return address


def _extract_asm_mnemonic(asm):
    """

    :param asm:
    :type asm:
    """
    return asm.split()[0].strip().upper()


def _extract_asm_operands(asm):
    """

    :param asm:
    :type asm:
    """
    operands = " ".join(asm.strip().upper().split()[1:])
    return re.findall(r"[.a-zA-Z0-9_+-]+", operands)


def _interpret_decorators(str_decorators):

    decorators = RejectingDict()

    if str_decorators is None:
        return decorators

    for decorator_def in str_decorators.split(" "):
        if decorator_def == '':
            continue

        key = decorator_def.split("=")[0].upper()
        lvalue = (decorator_def + "=").split("=")[1].split(",")

        nvalue = []

        for idx, value in enumerate(lvalue):

            if value == '':
                continue

            if os.path.isfile(value):
                raise NotImplementedError(
                    "Decorator with references to files "
                    "not yet implemented"
                )
            else:
                origvalue = value
                value = value.upper()

            if value == '':
                value = None
            elif value == 'ON':
                value = True
            elif value == 'OFF':
                value = False
            elif value == 'TRUE':
                value = True
            elif value == 'FALSE':
                value = False
            elif value.isdigit():
                value = int(value)
            elif value.startswith("0X"):
                if value.count("-") > 1:
                    value = range_to_sequence(*value.split("-"))
                else:
                    try:
                        value = int(value, 16)
                    except ValueError:
                        value = origvalue
            else:
                value = origvalue

            if isinstance(value, list):
                nvalue.extend(value)
            else:
                nvalue.append(value)

        try:
            if len(lvalue) == 1:
                decorators[key] = nvalue[0]
            else:
                decorators[key] = nvalue

        except MicroprobeDuplicatedValueError:
            raise MicroprobeAsmError(
                "Decorator with key '%s' specified twice for the same "
                "instruction." % key
            )

    return decorators


def _find_instr_with_mnemonic(mnemonic, asm_operands, target):
    """

    :param mnemonic:
    :type mnemonic:
    :param asm_operands:
    :type asm_operands:
    :param target:
    :type target:
    """

    # First, look for default instructions
    base_instructions = [
        instr
        for instr in target.instructions.values()
        if (
            instr.mnemonic == mnemonic or instr.name == mnemonic
        )
    ]

    LOG.debug(
        "Instruction found with same mnemonic: %s",
        [instr.name for instr in base_instructions]
    )

    instructions = [
        instr
        for instr in base_instructions
        if len([op for op in target.new_instruction(instr.name).operands()
                #   if (op.is_input or op.is_output)
                ]) == len(asm_operands)
    ]

    LOG.debug(
        "Instruction found with same operands: %s", [
            instr.name for instr in instructions
        ]
    )

    fixed_asm_operands = asm_operands

    # TODO: Hack for Z amd RISC-V, needs to be
    # TODO: removed from here, it should be in the target backend

    if len(instructions) == 0 and len(base_instructions) > 0:
        # There are instructions but for some reason the number of operands
        # is not correct
        instructions = []
        for instruction in base_instructions:
            # check if it is our fault or user's fault
            fnames = [field.name for field in instruction.format.fields]
            insfmt = instruction.format.assembly_format

            # Z hacks
            if "DH1" in fnames and "DL1" in fnames and "D1" in insfmt:
                asm_operands.append("0x0")
                return _find_instr_with_mnemonic(
                    mnemonic, asm_operands, target
                )

            if "DH2" in fnames and "DL2" in fnames and "D2" in insfmt:
                asm_operands.append("0x0")
                return _find_instr_with_mnemonic(
                    mnemonic, asm_operands, target
                )

            # RISC-V hacks
            if ("s_imm5" in fnames and "s_imm7" in fnames and
                    "s_imm12" in insfmt):
                asm_operands.insert(0, "0x0")
                asm_operands[0], asm_operands[2] = \
                    asm_operands[2], asm_operands[0]
                return _find_instr_with_mnemonic(
                    mnemonic, asm_operands, target
                )

            if ("sb_imm5" in fnames and "sb_imm7" in fnames and
                    "sb_imm12" in insfmt):

                asm_operands.insert(0, "0x0")
                asm_operands[0], asm_operands[3] = \
                    asm_operands[3], asm_operands[0]
                return _find_instr_with_mnemonic(
                    mnemonic, asm_operands, target
                )

    # TODO: Remove from here, it should be in the target backend
    # TODO: Remove from here, it should be in the target backend

    # If no instructions found, check for extended mnemonics
    if len(instructions) == 0 and len(base_instructions) == 0:
        # TODO: Implement
        pass

    if len(instructions) == 0:

        if len(
            [
                instr
                for instr in target.instructions.values(
                ) if instr.mnemonic == mnemonic
            ]
        ) > 0:
            raise MicroprobeAsmError(
                "Unable to interpret asm mnemonic '%s'. Number of operands "
                "is not correct" % mnemonic
            )

        raise MicroprobeAsmError(
            "Unable to interpret_asm mnemonic '%s'. Either the mnemonic is "
            "invalid, the instruction is not supported or this is a not "
            "supported extended mnemonic" % mnemonic
        )

    return instructions, fixed_asm_operands


def _extract_operands(base_asm, asm_operands, intr_types, target, labels):
    """

    :param base_asm:
    :type base_asm:
    :param asm_operands:
    :type asm_operands:
    :param intr_types:
    :type intr_types:
    :param target:
    :type target:
    :param labels:
    :type labels:
    """

    LOG.debug("Start extracting operands")

    operand_dict = {}

    for instr_type in intr_types:

        operands = []
        instruction = target.new_instruction(instr_type.name)
        LOG.debug("Instruction: '%s'", instruction.name)
        LOG.debug("Operands: '%s'", instruction.operands())

        if len(asm_operands) != len(instruction.operands()):
            raise MicroprobeAsmError(
                "Mismatch in number of operands: '%s' !="
                " '%s'. Base asm: '%s'", asm_operands, instruction.operands(),
                base_asm
            )

        sorted_asm_operands = _sort_asm_operands_by_intr_type(
            asm_operands, instruction
        )

        LOG.debug("Sorted asm operands: '%s'", sorted_asm_operands)

        operand_candidates = _generate_operand_candidates(
            sorted_asm_operands, target, instruction, labels
        )

        LOG.debug("Operand candidates: '%s'", operand_candidates)

        operand_candidates = _filter_operands_by_type(
            operand_candidates, instruction
        )

        LOG.debug("Filtered operand candidates: '%s'", operand_candidates)

        for operand_candidate in _find_operand_candidates(
            operand_candidates, instruction
        ):

            LOG.debug("Checking ASM for %s", operand_candidate)
            if _check_assembly_string(
                base_asm, instr_type, target, operand_candidate
            ):
                LOG.debug("ASM OK!")
                operands.append(operand_candidate)

        if len(operands) > 0:
            operand_dict[instr_type] = operands

    if len(list(operand_dict.keys())) == 0:
        raise MicroprobeAsmError(
            "Unable to find operands for assembly: '%s'. If the instruction "
            "contains labels or symbols, make sure they are declared."
            " Otherwise, check the rest of operands" % base_asm.strip()
        )
    elif len(list(operand_dict.keys())) > 1:

        LOG.warning(
            "Operands can be valid for multiple instruction definitions. "
            "Check your architecture definition files and specify a particular"
            " instruction variant. Base assembly: '%s'", base_asm.strip()
        )

        for key in operand_dict:
            LOG.warning("Possible instructions: %s", key)

    instr_type = list(operand_dict.keys())[0]
    operands = operand_dict[instr_type]

    if len(operands) > 1:
        raise MicroprobeAsmError(
            "Multiple operand possibilities for "
            "instruction '%s'. Possibilities: '%s'" % (
                base_asm, operands
            )
        )

    LOG.debug("End extracting operands")

    return instr_type, list(operands[0])


def _sort_asm_operands_by_intr_type(asm_operands, instruction):
    """

    :param asm_operands:
    :type asm_operands:
    :param instruction:
    :type instruction:
    """
    LOG.debug("Start: asm_operands: %s", asm_operands)
    new_operands = []

    asm_fmt = instruction.architecture_type.format.assembly_format + " "
    asm_fmt = asm_fmt.replace("(", " ")
    asm_fmt = asm_fmt.replace(")", " ")
    asm_fmt = asm_fmt.replace(",", " ")

    # TODO: Hack for Z and RISC-V needs to be
    # TODO: removed from here, it should be in the target backend

    fnames = [
        field.name for field in instruction.architecture_type.format.fields
    ]

    # Z hacks
    if "DH1" in fnames and "DL1" in fnames and " D1 " in asm_fmt:
        asm_fmt = asm_fmt.replace(" D1 ", " DL1 ")
        asm_fmt += " DH1 "

    if "DH2" in fnames and "DL2" in fnames and " D2 " in asm_fmt:
        asm_fmt = asm_fmt.replace(" D2 ", " DL2 ")
        asm_fmt += " DH2 "

    # RISC-V hacks
    if ("s_imm5" in fnames and "s_imm7" in fnames and
            "s_imm12" in asm_fmt):
        asm_fmt = asm_fmt.replace(" s_imm12 ", " s_imm5 ")
        asm_fmt = asm_fmt.replace("OPC ", "OPC s_imm7 ")

    if ("sb_imm5" in fnames and "sb_imm7" in fnames and
            "sb_imm12" in asm_fmt):
        asm_fmt = asm_fmt.replace(" sb_imm12 ", " sb_imm5 ")
        asm_fmt = asm_fmt.replace("OPC ", "OPC sb_imm7 ")

    # TODO: removed from here, it should be in the target backend
    # TODO: removed from here, it should be in the target backend

    fields = [
        [field.name, asm_fmt.find(" %s " % field.name)]
        for field in instruction.architecture_type.format.fields
        if " %s " % field.name in asm_fmt
    ]

    sorted_fields = sorted(fields, key=lambda x: x[1])

    for asm_operand, sorted_field in zip(asm_operands, sorted_fields):
        sorted_field.append(asm_operand)

    for field in fields:

        field_name = field[0]
        new_operands.append(
            [
                elem[2] for elem in sorted_fields if elem[0] == field_name
            ][0]
        )

    if len(asm_operands) != len(new_operands):
        new_operands = []
        for asm_operand in asm_operands:
            # if asm_operand not in new_operands:
            new_operands.append(asm_operand)

    LOG.debug("Asm operands: %s", asm_operands)
    LOG.debug("New operands: %s", new_operands)
    if len(asm_operands) != len(new_operands):
        raise MicroprobeAsmError("Unable to interpret assembly operands")

    return new_operands


def _filter_operands_by_type_pos(operands, instruction):
    """

    :param operands:
    :type operands:
    :param instruction:
    :type instruction:
    """
    LOG.debug("Start")
    new_operands = []

    for operand, operand_values in zip(instruction.operands(), operands):
        valid_values = []
        for operand_val in operand_values:
            try:
                operand.type.check(operand_val)
                valid_values.append(operand_val)
            except MicroprobeValueError:
                continue

        new_operands.append(valid_values)

    LOG.debug("New operands: %s", new_operands)
    LOG.debug("End")

    return new_operands


def _check_assembly_string(base_asm, instr_type, target, operands):
    """

    :param base_asm:
    :type base_asm:
    :param instr_type:
    :type instr_type:
    :param target:
    :type target:
    :param operands:
    :type operands:
    """

    LOG.debug("Start checking assembly string: %s", base_asm)

    operands = list(operands)

    for idx, operand in enumerate(operands):
        if isinstance(operand, six.string_types):
            operands[idx] = Address(base_address=operand)

    instruction = target.new_instruction(instr_type.name)

    try:
        instruction.set_operands(operands)
    except MicroprobeValueError:
        LOG.debug("End checking assembly string: Operands not valid")
        return False
    except MicroprobeCodeGenerationError:
        LOG.debug(
            "End checking assembly string: Operands not valid for "
            "callback"
        )
        return False

    nasm = _normalize_asm(instruction.assembly())
    base_asm = _normalize_asm(base_asm)
    base_asm = base_asm.replace(instr_type.name, instr_type.mnemonic)

    LOG.debug("'%s' == '%s' ?", nasm, base_asm)
    if nasm == base_asm:
        LOG.debug("End checking assembly string: Valid")
        return True

    LOG.debug("End checking assembly string: Not valid")
    return False


def _find_operand_candidates(candidates, instruction):
    """

    :param candidates:
    :type candidates:
    :param instruction:
    :type instruction:
    """

    LOG.debug("Start")
    # flat_candidates = [candidate
    #                    for candidate_pos in candidates
    #                    for candidate in candidate_pos]

    validated_combinations = []

    if len(candidates) != len(instruction.operands()):
        LOG.debug("No operand candidates, different number of operands")
        yield

    # for candidate_combination in itertools.permutations(flat_candidates,
    #                                                     len(candidates)):

    for candidate_combination in itertools.product(*candidates):

        LOG.debug("Combination: %s", candidate_combination)

        if str(candidate_combination) in validated_combinations:
            LOG.debug("Already validated")
            continue

        validated_combinations.append(str(candidate_combination))

        if _validate_operands(candidate_combination, instruction):
            LOG.debug("Combination valid: %s", candidate_combination)
            yield candidate_combination

        LOG.debug("Combination not valid: %s", candidate_combination)


def _validate_operands(operand_values, instruction):
    """

    :param operand_values:
    :type operand_values:
    :param instruction:
    :type instruction:
    """

    LOG.debug("Start validate operands")

    for operand_value, operand in zip(operand_values, instruction.operands()):

        LOG.debug("Validating: '%s' <-> '%s'", operand_value, operand)

        if isinstance(operand_value, six.string_types):

            LOG.debug("Value is a string")
            if not isinstance(operand.type, InstructionAddressRelativeOperand):
                LOG.debug("Invalid: A string in a non-relative operand")
                return False

        else:

            LOG.debug("Value is not a string")
            if (
                isinstance(operand.type, InstructionAddressRelativeOperand) and
                not isinstance(operand_value, six.integer_types)
            ):
                LOG.debug("Invalid: A not int in a relative operand")
                return False

            try:

                if (
                    isinstance(
                        operand.type, (
                            OperandImmRange, OperandConst, OperandValueSet
                        )
                    ) and isinstance(
                        operand_value, int
                    )
                ):
                    LOG.debug("Checking int value: %s", operand_value)
                    operand.type.check(operand_value)

                elif (
                    not isinstance(
                        operand.type, (
                            OperandImmRange, OperandConst, OperandValueSet
                        )
                    ) and not isinstance(operand_value, six.integer_types)
                ):

                    LOG.debug("Checking not int value: %s", operand_value)
                    operand.type.check(operand_value)

                elif (
                    isinstance(
                        operand.type, (InstructionAddressRelativeOperand)
                    ) and isinstance(operand_value, six.integer_types)
                ):

                    LOG.debug("Checking relative int value: %s", operand_value)
                    operand.type.check(operand_value)

                else:
                    return False

            except MicroprobeValueError as exc:
                LOG.debug(exc)
                return False

    return True


def _generate_operand_candidates(operands, target, instruction, labels):
    """

    :param operands:
    :type operands:
    :param target:
    :type target:
    :param instruction:
    :type instruction:
    :param labels:
    :type labels:
    """

    LOG.debug("Start: operands=%s", operands)
    candidates = []

    for operand in operands:
        options = []

        LOG.debug("Processing operand: %s", operand)

        operand_value = _numeric_format(operand)
        if operand_value is not None:

            LOG.debug("Operand looks like a numeric value '%d'", operand_value)

            options.append(operand_value)
            options += _generate_immediate_variations(
                operand_value, instruction
            )
            if operand.isdigit():
                options += _generate_possible_registers(operand, target)

        else:

            LOG.debug("Operand looks like a label or register value.")

            islabel = False
            for label in labels:
                if operand.startswith(label):
                    islabel = True
                    break

            if islabel:
                options.append(operand)
            else:
                options += _generate_possible_registers(operand, target)

        if len(options) == 0:
            raise MicroprobeAsmError(
                "Unable to generate operand candidates "
                "for operand '%s'" % operand
            )

        if len(options) > 0:
            LOG.debug("New candidate: %s", options)
            candidates.append(options)

    LOG.debug("End")
    return candidates


def _generate_immediate_variations(immediate, instr):
    """

    :param immediate:
    :type immediate:
    :param instr:
    :type instr:
    """

    variations = []
    for operand in [oper for oper in instr.operands() if oper.type.immediate]:
        new_val = _numeric_format(operand.type.representation(immediate))
        if new_val != immediate:
            diff = new_val - immediate
            variation = immediate - diff

            if (
                _numeric_format(
                    operand.type.representation(variation)
                ) == immediate and variation not in variations
            ):
                variations.append(variation)

    return variations


def _generate_possible_registers(operand, target):
    """

    :param operand:
    :type operand:
    :param target:
    :type target:
    """

    LOG.debug("Looking possible registers for operand: '%s'", operand)

    reg_repr = [reg for reg in target.registers.values()
                if reg.representation.upper() == operand.upper()]

    if len(reg_repr) > 0:
        registers = reg_repr
    elif len(re.findall("[0-9]+", operand)) != 1:
        registers = []
    elif operand[0].isdigit() and not operand.isdigit():
        registers = []
    elif operand[0] == '-' and operand[1:].isdigit():
        registers = []
    else:

        norm_operand = re.sub("[^0-9]", "", operand)

        registers = [
            register
            for register in target.registers.values()
            if register.representation == norm_operand
        ]

    LOG.debug("Registers for operand: '%s' are: '%s'", operand, registers)

    return registers


def _filter_operands_by_type(candidates, instruction):
    """

    :param candidates:
    :type candidates:
    :param instruction:
    :type instruction:
    """

    operand_types = _get_operand_types(instruction)

    new_candidates = []
    for candidate in candidates:

        operand_candidates = []
        for operand_option in candidate:

            LOG.debug("Operand option: %s", operand_option)

            if (
                isinstance(operand_option, six.string_types) and 'label' in [
                    oper for oper in operand_types
                    if isinstance(oper, six.string_types)
                ]
            ):
                operand_candidates.append(operand_option)
            elif (
                isinstance(operand_option, six.string_types) and
                    'label' not in [
                    oper for oper in operand_types
                    if isinstance(oper, six.string_types)
                ]
            ):
                raise MicroprobeAsmError(
                    "Unable to find operand candidates when interpreting "
                    "instruction '%s'. Check the assembly provided " %
                    instruction.name
                )
            elif isinstance(operand_option, six.integer_types):
                # and
                # 'value' in [oper for oper in operand_types
                #            if isinstance(oper, str)]):
                operand_candidates.append(operand_option)
            elif operand_option.type in \
                    [list(oper.values())[0].type
                     for oper in operand_types if
                     not isinstance(oper,
                                    tuple([str] + list(six.integer_types))) and
                     not isinstance(list(oper.values())[0],
                                    six.integer_types)]:
                operand_candidates.append(operand_option)
            else:

                LOG.debug(operand_option.type.name)
                LOG.debug(
                    [
                        list(oper.values())[0].type.name
                        for oper in operand_types
                        if not isinstance(oper,
                                          tuple([str] +
                                                list(six.integer_types)))
                        and not isinstance(
                            list(oper.values())[0], six.integer_types
                        )
                    ]
                )

                LOG.debug([oper for oper in operand_types])

                LOG.debug("Removing: %s", operand_option)

        if len(operand_candidates) == 0:

            raise MicroprobeAsmError(
                "Unable to find operand candidates when interpreting "
                "instruction '%s'. Check the assembly provided " %
                instruction.name
            )

        assert len(operand_candidates) <= len(candidate)

        new_candidates.append(operand_candidates)

    return new_candidates


def _get_operand_types(instruction):
    """

    :param instruction:
    :type instruction:
    """

    LOG.debug("Start")

    types = []
    label = False
    value = False

    for operand in instruction.operands():

        LOG.debug("Operand: %s", operand)
        LOG.debug("Operand type: %s", operand.type)

        if operand.type not in types:
            if isinstance(operand.type, InstructionAddressRelativeOperand):
                label = True
                value = True
            elif isinstance(operand.type, (OperandConst, OperandImmRange)):
                value = True
            else:
                types.append(operand.type)

        LOG.debug("Current types: %s", types)

    if label:
        types.append('label')

    if value:
        types.append('value')

    LOG.debug("Final types: %s", types)
    LOG.debug("End")

    return types


def _normalize_asm(asm):
    """

    :param asm:
    :type asm:
    """

    LOG.debug("Start asm normalizing: '%s'", asm)
    nasm = asm.upper()
    nasm = nasm.strip()

    nasm = re.sub(r'\( +', r'(', nasm)
    nasm = re.sub(r' +\)', r')', nasm)
    nasm = re.sub(r' +\(', r'(', nasm)
    nasm = re.sub(r'\) +', r')', nasm)
    nasm = re.sub(r',', r', ', nasm)
    nasm = re.sub(r' +', r' ', nasm)

    nasm = re.sub(r" [^0-9-]+([0-9]+),", r" \1,", nasm)
    nasm = re.sub(r" [^0-9-]+([0-9]+)$", r" \1", nasm)
    nasm = re.sub(r"\([^0-9-]+([0-9]+),", r"(\1,", nasm)
    nasm = re.sub(r"\([^0-9-]+([0-9]+)\)", r"(\1)", nasm)
    nasm = re.sub(r" [^0-9-]+([0-9]+)\)", r" \1)", nasm)

    for hexnum in re.findall("0X[0-9ABCDEF]+", nasm):
        nasm = nasm.replace(hexnum, str(int(hexnum, 16)), 1)

    for octnum in re.findall("0O[0-7]+", nasm):
        nasm = nasm.replace(octnum, str(int(octnum, 8)), 1)

    for binnum in re.findall("0B[01]+", nasm):
        nasm = nasm.replace(binnum, str(int(binnum, 2)), 1)

    # Replace the leading zeros
    nasm = re.sub(r" [0]+([0-9]+),", r" \1,", nasm)
    nasm = re.sub(r" [0]+([0-9]+)$", r" \1", nasm)
    nasm = re.sub(r" [0]+([0-9]+)\(", r" \1(", nasm)
    nasm = re.sub(r" [0]+([0-9]+)\)", r" \1)", nasm)
    nasm = re.sub(r" -[0]+([0-9]+),", r" -\1,", nasm)
    nasm = re.sub(r" -[0]+([0-9]+)$", r" -\1", nasm)
    nasm = re.sub(r" -[0]+([0-9]+)\(", r" -\1(", nasm)
    nasm = re.sub(r" -[0]+([0-9]+)\)", r" -\1)", nasm)

    LOG.debug("End asm normalizing: '%s'", nasm)

    return nasm


def _numeric_format(operand):
    """

    :param operand:
    :type operand:
    """

    operand = operand.upper()

    negative = False
    if operand.startswith('-'):
        operand = operand[1:]
        negative = True

    if (
        operand.startswith('0X') and all(
            c in set(string.hexdigits) for c in operand[2:]
        )
    ):
        value = int(operand, 16)
    elif (
        operand.startswith('0O') and all(
            c in set(string.octdigits) for c in operand[2:]
        )
    ):
        value = int(operand, 8)
    elif (
        operand.startswith('0B') and all(c in set("01") for c in operand[2:])
    ):
        value = int(operand, 2)
    elif operand.isdigit():
        value = int(operand, 10)
    else:
        return None

    if negative:
        value = value * (-1)

    return value


def _str_to_asmdef(asm_string):
    """

    :param asm_string:
    :type asm_string:
    """

    # TODO: Add address SUPPORT

    comment = (asm_string + ";").split(";")[1].strip()
    asm_string = asm_string.split(";")[0].strip()

    # This is a work-around for RISC-V objdump implementation.
    # It generates comments with '#' character
    if "#" in asm_string:
        asm_string = asm_string.split("#")[0].strip()

    label = None
    address = None

    asmfull = asm_string
    if asm_string.find(":") > 0:
        # Has label/Address
        asmfull = asm_string.split(":")[1]
        address_label = asm_string.split(":")[0].strip()

        for elem in address_label.split(" "):

            if (
                (
                    elem.startswith("0x") or
                    re.search(r"^[0-9a-fA-F]+$", elem) is not None
                ) and address is None
            ):
                address = int(elem, 16)
            elif (
                elem[0] == '<' and elem[-1] == '>' and label is None and
                len(elem) > 2
            ):
                label = elem[1:-1]
            else:
                raise MicroprobeAsmError(
                    "Unable to interpret '%s'" % asm_string
                )

    asm = asmfull.split("@")[0].strip()

    decorator = (asmfull + '@').split("@")[1].strip()
    if decorator == '':
        decorator = None

    if label == '':
        label = None

    if address == '':
        address = None

    return MicroprobeAsmInstructionDefinition(
        asm, label, address, decorator, comment
    )


# Classes
class MicroprobeAsmInstructionDefinition(object):

    def __init__(self, assembly, label, address, decorators, comments):
        self.assembly = assembly
        self.label = label
        self.address = address
        self.decorators = decorators
        self.comments = comments

    def __iter__(self):
        yield self.assembly
        yield self.label
        yield self.address
        yield self.decorators
        yield self.comments

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

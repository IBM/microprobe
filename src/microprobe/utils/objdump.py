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
""":mod:`microprobe.utils.obdump` module

This module implements the required features to interpret objdump assembly
dumps and translate them into Microprobe internal represenation of instruction,
operands, labels and addreses, which can be translated to other formats (e.g.
MPT) afterwards.

The main elements of this module are the following:

- :func:`~.interpret_objdump` function parses the objdump output and
  translates it into internal Microprobe represenation of instructions and
  operands, etc.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import re

# Third party modules
from six.moves import zip

# Own modules
from microprobe.code.address import Address
from microprobe.code.ins import MicroprobeInstructionDefinition
from microprobe.exceptions import MicroprobeAsmError, \
    MicroprobeBinaryError, MicroprobeObjdumpError
from microprobe.utils.asm import interpret_asm
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Progress
from microprobe.utils.mpt import MicroprobeTestVariableDefinition


# Constants
LOG = get_logger(__name__)
__all__ = ["interpret_objdump"]


# Functions
def interpret_objdump(
    objdump_output,
    target,
    strict=False,
    sections=None,
    start_address=-1,
    end_address=float('+inf')
):
    """
    Returns a :class:`~.MicroprobeTestDefinition` object
    that results from interpreting the objdump output.
    The *target* object is used to validate the existence of the instruction
    and operands.

    :param objdump_output: Assembly to interpret
    :type objdump_output: Objdump textual output
    :param target: Target definition
    :type target: :class:`~.Target` object
    :param strict: If set, fail if an opcode can not be interpreted.
                  (Default: False)
    :type strict: :class:`~.bool`
    :param sections: List of section names to parse
    :type sections: :class:`~.list` of :class:`~.str`
    :param start_address: Start address to interpret
    :type start_address: ::class:`~.int`
    :param end_address: End address to interpret
    :type end_address: ::class:`~.int`
    :return: An object representing the microprobe test
    :rtype: :class:`~.list` of :class:`~.MicroprobeTestDefinition`
    :raise microprobe.exceptions.MicroprobeObjdumpError: if something is wrong
        during the interpretation of the objdump
    """

    if isinstance(objdump_output, str):
        objdump_output = objdump_output.replace('\r', '\n')
        objdump_output = objdump_output.split('\n')

    filtered_objdump_output = _objdump_cleanup(
        objdump_output, sections, start_address, end_address
    )

    code_labels = _find_code_labels(filtered_objdump_output)
    var_labels = _find_var_labels(filtered_objdump_output, code_labels)

    labels = code_labels + var_labels
    label_pattern = _generate_label_pattern(labels)

    binary_format = _binary_reformat(filtered_objdump_output)
    asm_format = _asm_reformat(filtered_objdump_output)

    assert len(binary_format) == len(asm_format)

    instr_defs = []
    current_labels = var_labels[:]

    progress = Progress(len(binary_format), msg="Lines parsed:")

    for binary, asm in zip(binary_format, asm_format):

        instr_def = None
        if not label_pattern.search(asm):
            try:
                instr_def = interpret_asm(binary, target, current_labels)
            except MicroprobeBinaryError:
                if strict:
                    raise MicroprobeObjdumpError(
                        "Unable to interpret binary '%s' (asm:' %s')" %
                        (binary, asm)
                    )
                else:
                    LOG.warning("Skiping binary '%s' (asm:' %s')", binary, asm)
                instr_def = None
        else:
            try:
                instr_def = interpret_asm(
                    asm, target, current_labels,
                    log=False
                )
            except MicroprobeAsmError:
                instr_def = interpret_asm(binary, target, current_labels)

        if instr_def is not None:
            fixed_instr_def = _fix_instr_definition(instr_def[0], asm, target)
            instr_defs.append(fixed_instr_def)

            if fixed_instr_def.label is not None:
                current_labels.append(fixed_instr_def.label)

        progress()

    variable_defs = []
    required_defs = []
    for var_label in var_labels:
        var_def = _interpret_variable(var_label, objdump_output)
        if var_def is not None:
            variable_defs.append(var_def)
        else:
            LOG.warning(
                "Variable label: '%s' referenced but not found "
                "in the dump"
            )
            required_defs.append(_default_variable(var_label))

    return variable_defs, required_defs, instr_defs


def _asm_reformat(input_str):

    output = []
    symbol_line = ""
    for line in input_str:
        match = re.search("^[0-9a-fA-F]+ <(.*.)>:$", line)
        if match is not None:
            symbol_line = line
        else:
            mline = symbol_line + " " + " ".join(line.split('\t')[1:])
            symbol_line = ""
            output.append(mline.strip())

    return output


def _binary_reformat(input_str):

    output = []
    symbol_line = ""
    for line in input_str:
        match = re.search("^[0-9a-fA-F]+ <(.*.)>:$", line)
        if match is not None:
            symbol_line = line
        else:
            mline = symbol_line + " 0x" + line.split('\t')[0].replace(" ", "")
            symbol_line = ""
            output.append(mline.strip())

    return output


def _default_variable(var_name):
    return MicroprobeTestVariableDefinition(
        var_name, "char", 1, None, None, None
    )


def _find_code_labels(input_text):
    labels = []

    for line in input_text:
        match = re.search("^[0-9a-fA-F]+ <(.*.)>:$", line)
        if match is not None:
            label = _sanitize_label(match.group(1))
            if label not in labels:
                labels.append(label)

    return labels


def _find_var_labels(input_text, code_labels):

    labels = []

    for line in input_text:
        match = re.search("^.*<(.*.)>.*$", line)
        if match is not None:
            label = _sanitize_label(match.group(1))
            if label not in labels and label not in code_labels:
                labels.append(label)

    return labels


def _fix_instr_definition(instr_def, asm, target):

    labelmatch = re.search("^.*<(.*.)>.*$", asm)
    label = None
    if labelmatch is not None:
        label = labelmatch.group(1)

    instruction = target.new_instruction(instr_def.instruction_type.name)
    operands = list(instr_def.operands)

    for idx, operand in enumerate(instruction.operands()):

        if operand.type.address_relative and label is not None:
            operands[idx] = Address(base_address=label.upper())

        operand.set_value(operands[idx])

    instr_def = MicroprobeInstructionDefinition(
        instr_def.instruction_type, operands, instr_def.label,
        instr_def.address, instruction.assembly(), instr_def.decorators,
        instr_def.comments
    )

    return instr_def


def _generate_label_pattern(labels):

    regex = []
    for label in labels:
        regex.append("^.*<%s[+-]*[0-9a-fA-F]*.*>.*$" % label)

    regex_str = "|".join(regex)

    pattern = re.compile(regex_str)
    return pattern


def _interpret_variable(var_name, input_str):

    input_str = _objdump_cleanup(input_str, ['ALL'])
    init_value = []

    address = None
    dump = False

    for line in input_str:

        if line.endswith(" <%s>:" % var_name):
            dump = True
            address = int(line.split(' ')[0], 16)
            continue
        elif dump and line.endswith(':'):
            break
        elif not dump:
            continue

        init_value.extend(
            int(elem, 16) for elem in line.split('\t')[0].strip().split(' ')
        )

    if dump is False:
        return None

    len_init_value = len(init_value)

    if init_value[1:] == init_value[:-1]:
        init_value = [init_value[0]]

    if init_value == [0]:
        init_value = None

    return MicroprobeTestVariableDefinition(
        var_name, "char", len_init_value, address, None, init_value
    )


def _objdump_cleanup(
    input_text,
    sections, start_address=0,
    end_address=float('+inf')
):

    if sections is None:
        sections = ['.text']

    all_sections = "ALL" in sections

    # Remove uneded output
    output_text = []
    current_section = ""

    for line in input_text:

        if (
            line.strip() == "" or line.find("file format elf") > -1 or
            line.find("file format aix") > -1 or line.find("...") > -1
        ):
            continue

        if line.startswith("Disassembly of section"):
            current_section = line.split(" ")[3][:-1]
            continue

        if (current_section in sections) or all_sections:
            output_text.append(line.replace('@', '_'))

    # Remove uneded addresses
    def _is_hex(mstr):
        return re.search(r"^[0-9a-fA-F]+$", mstr.strip()) is not None

    input_text = output_text[:]
    output_text = []
    for line in input_text:

        line = line.strip()

        tabbed = line.split("\t")
        if tabbed[0][-1] == ':' and len(tabbed) == 1:

            if (
                int(
                    tabbed[0].split(' ')[0], 16
                ) >= start_address and int(
                    tabbed[0].split(' ')[0], 16
                ) <= end_address
            ):

                output_text.append(line)

        elif len(tabbed) in [3, 4] and _is_hex(tabbed[0][:-1]):

            if (
                int(
                    tabbed[0][:-1], 16
                ) >= start_address and int(
                    tabbed[0][:-1], 16
                ) <= end_address
            ):

                output_text.append("\t".join(tabbed[1:]))

        else:
            raise MicroprobeObjdumpError(
                "Unable to parse line '%s' from input file." % line
            )

    if not output_text:
        raise MicroprobeObjdumpError(
            "Empty input. Check if the address ranges and/or the section names"
            " provided exist in the input"
        )

    return output_text


def _sanitize_label(mstr):

    # mstr = mstr.split('@')[0]

    match = re.search("(^.*)[+-]0x.*$", mstr)
    if match is not None:
        mstr = match.group(1)

    return mstr

# Classes

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
""":mod:`microprobe.utils.bin` definition module

This module implements the required features to interpret instructions in
binary codification and translate them into Microprobe internal represenation
of instruction, operands, labels and addreses.

The main elements of this module are the following:

- :class:`~.MicroprobeBinInstructionStream` objects to represent a binary
  stream of codified instructions
- :func:`~.interpret_bin` function validates the binary codification and
  translates them into internal Microprobe represenation of instructions and
  operands.
"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import itertools
import math
import string
import re

# Third party modules
import six
from six.moves import range, zip

# Own modules
import microprobe.code.ins
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobeBinaryError, \
    MicroprobeCodeGenerationError, MicroprobeValueError
from microprobe.target.isa.instruction import instruction_type_from_bin
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Progress, \
    RejectingDict, int_to_twocs, twocs_to_int


# Constants
LOG = get_logger(__name__)
_BIN_CACHE = RejectingDict()
_CODE_CACHE = RejectingDict()
_DATA_CACHE = RejectingDict()
_DATA_CACHE_LENGTHS = []
_DATA_CACHE_ENABLED = True
_CODE_CACHE_ENABLED = True
_BIN_CACHE_ENABLED = True

__all__ = ["interpret_bin",
           "MicroprobeBinInstructionStream", ]


# Functions
def interpret_bin(
        code, target, fmt="hex", safe=None,
        single=False, little_endian=None, word_length=None
        ):
    """
    Return the list of :class:`~.MicroprobeInstructionDefinition` objects
    that results from interpreting the *code* (a binary stream).
    The *target* object is used to validate the existence of the instruction
    and operands in the target.

    :param code: String to interpret
    :type code: :class:`~.str` object
    :param target: Target definition
    :type target: :class:`~.Target` object
    :return: A list of instructions, operands, labels, etc. resulting from
            interpreting the assembly
    :rtype: :class:`~.list` of :class:`~.MicroprobeInstructionDefinition`
    :raise microprobe.exceptions.MicroprobeBinaryError: if something is wrong
        during the interpretation
    """

    if safe is None:
        safe = MICROPROBE_RC['safe_bin']

    if single:
        little_endian = False
        if fmt == "hex":
            word_length = int(math.ceil(len(code)/2))
        elif fmt == "bin":
            word_length = int(math.ceil(len(code)/8))
        else:
            raise MicroprobeBinaryError("Unknown format '%s'" % fmt)

    key = "%s-%s-%s-%s" % (code, target.name, fmt, safe)

    if key in _CODE_CACHE and _CODE_CACHE_ENABLED:
        code = [instrdef.copy() for instrdef in _CODE_CACHE[key]]
    elif safe:
        code = _interpret_bin_code_safe(
            code, target, single, fmt=fmt, little_endian=little_endian,
            word_length=word_length
        )
        if _CODE_CACHE_ENABLED:
            _CODE_CACHE[key] = code[:]
    else:
        code = _interpret_bin_code(
            code, target, single, fmt=fmt, little_endian=little_endian,
            word_length=word_length
        )
        if _CODE_CACHE_ENABLED:
            _CODE_CACHE[key] = code[:]

    return code


def _interpret_bin_code(
        code, target, single, fmt="hex", little_endian=True, word_length=None
        ):

    instructions_and_params = []

    binstream = MicroprobeBinInstructionStream(
        code, target, fmt=fmt, little_endian=little_endian,
        word_length=word_length
    )

    while not binstream.empty():
        bins, instr_type, operands = binstream.decode_next()
        instr_def = microprobe.code.ins.MicroprobeInstructionDefinition(
            instr_type, operands, None, None, bins, None, None
        )
        instructions_and_params.append(instr_def)

    return instructions_and_params


def _interpret_bin_code_safe(
        code, target, single, fmt="hex", little_endian=None, word_length=None
        ):

    instructions_and_params = []

    binstream = MicroprobeBinInstructionStream(
        code, target, fmt=fmt,
        _data_cache=True,
        little_endian=little_endian,
        word_length=word_length
    )

    min_skip_length = min(
        [ins.format.length for ins in target.instructions.values()]) * 2
    fmt = "0x%%0%dx" % (min_skip_length)

    while not binstream.empty():
        try:
            bins, instr_type, operands = binstream.decode_next()
            instr_def = microprobe.code.ins.MicroprobeInstructionDefinition(
                instr_type, operands, None, None, bins, None, None
            )
            instructions_and_params.append(instr_def)
        except MicroprobeBinaryError:
            if single:
                skip = binstream.skip_all()
            else:
                skip = binstream.skip(characters=min_skip_length)

            instr_type = instruction_type_from_bin(skip, target)
            instr_def = microprobe.code.ins.MicroprobeInstructionDefinition(
                instr_type, (), None, None, skip, None, None
            )
            instructions_and_params.append(instr_def)

            if _BIN_CACHE_ENABLED:
                key = (fmt % int(skip, 16)).lower()
                _BIN_CACHE[key] = (
                    fmt %
                    int(skip, 16), instr_type, ())

    return instructions_and_params


def _compute_target_lengths(target):
    """

    :param target:
    :type target:
    """
    instr_formats = set(
        (
            instr.format for instr in target.instructions.values()
        )
    )
    lengths = set((instr_format.length for instr_format in instr_formats))
    LOG.debug("Possible lengths: %s", lengths)
    return lengths


def _interpret_bin_instr(instr_type, bin_instr):
    """

    :param target:
    :type target:
    """
    LOG.debug("Interpret bin instr: %s, %s", instr_type, hex(bin_instr))

    operand_values = []
    processed_bits = 0
    for op_descriptor, field in zip(
        list(instr_type.operands.items()), instr_type.format.fields
    ):
        dummy_fieldname, op_descriptor = op_descriptor
        operand, dummy_io_def = op_descriptor

        processed_bits += field.size

        LOG.debug("Process field: %s, size: %d", field, field.size)
        LOG.debug("Process operand: %s", operand)
        LOG.debug("Processed bits: %d", processed_bits)

        if not field.default_show:
            LOG.debug("Skip, not shown")
            continue

        field_value = (
            bin_instr >> (
                (
                    (instr_type.format.length * 8) - processed_bits
                )
            )
        ) & (
            (0b1 << field.size) - 1
        )

        LOG.debug("All: 0x%x", bin_instr)
        LOG.debug(
            "Shift bits: %d", (instr_type.format.length * 8) - processed_bits
        )
        LOG.debug(
            "Shifted value: 0x%x", (
                bin_instr >> (
                    (
                        (instr_type.format.length * 8) - processed_bits
                    )
                )
            )
        )
        LOG.debug("Field size: %d", field.size)
        LOG.debug("Mask used: 0x%x", (0b1 << field.size) - 1)
        LOG.debug("Field value: %s", hex(field_value))
        LOG.debug("Field value: %s", bin(field_value))

        found = False
        if (operand.immediate or
                operand.address_relative or operand.address_absolute):

            LOG.debug("Immediate/Relative operand")
            oper_size_pairs = [(field_value, field.size, 0)]

            if operand.shift > 0:

                LOG.debug("Operand shifted by: %s", operand.shift)
                pair = (
                    field_value << operand.shift, field.size + operand.shift,
                    operand.shift
                )
                oper_size_pairs.append(pair)

            if hasattr(operand, "step"):

                LOG.debug("Operand has a step of: %s", operand.step)
                for idx in [0, 1, 2]:

                    if (int(math.log(operand.step, 2)) - idx) < 0:
                        continue

                    pair = (
                        field_value << (
                            int(math.log(operand.step, 2)) - idx
                        ), field.size + int(math.log(operand.step, 2)) - idx,
                        (int(math.log(operand.step, 2)) - idx)
                    )
                    oper_size_pairs.append(pair)

                if operand.shift > 0:

                    LOG.debug(
                        "Operand shifted/stepped: %s %s", operand.shift,
                        operand.step
                    )
                    pair = (
                        field_value << (
                            (
                                int(math.log(operand.step, 2)) - 1
                            ) + operand.shift
                        ), field.size + int(math.log(operand.step, 2)) - 1 +
                        operand.shift, (
                            (
                                int(math.log(operand.step, 2)) - 1
                            ) + operand.shift
                        )
                    )
                    oper_size_pairs.append(pair)

            if operand.address_relative or operand.address_absolute or (
                not operand.address_relative and operand.min < 0
            ):
                LOG.debug("C2 codification")
                new_pairs = []
                for oper, size, shift in oper_size_pairs:
                    new_pairs.append((twocs_to_int(oper, size), size, shift))
                oper_size_pairs += new_pairs

            #
            # Handle special codifications
            # TODO: This should be moved to the architecture
            # back-ends
            #
            # MB field on POWERPC
            special_condition = False
            if field.name in ["MB6", "ME6"]:
                LOG.debug("Special condition field 1")
                special_condition = True
                pair = (
                    (
                        (field_value >> 1) & 0b11111
                    ) | (
                        (field_value & 0b1) << 5
                    ), field.size, operand.shift
                )
                oper_size_pairs.append(pair)

            if field.name in ["SH6_5"]:
                LOG.debug("Special condition field 2")
                special_condition = True
                pair = (field_value + 32, 6, operand.shift)
                oper_size_pairs.append(pair)

            if field.name in ["Dd0", "Dd2"]:
                special_condition = True
                pair = (0, field.size, operand.shift)
                oper_size_pairs.append(pair)

            if field.name in ['Dd1']:
                special_condition = True

                dd2_value = bin_instr & 0b1
                dd0_value = (bin_instr >> 6) & (0b1111111111)

                value = (field_value << 1)
                value = value | dd2_value
                value = value | (dd0_value << 6)
                value = twocs_to_int(value, 16)
                pair = (value, 16, operand.shift)
                oper_size_pairs.append(pair)

            if field.name in ["dc", "dm"]:
                special_condition = True
                pair = (0, field.size, operand.shift)
                oper_size_pairs.append(pair)

            if field.name in ['dx']:
                special_condition = True

                dc_value = (bin_instr >> 6) & 0b1
                dm_value = (bin_instr >> 2) & 0b1

                value = field_value
                value = value | (dm_value << 5)
                value = value | (dc_value << 6)
                # value = twocs_to_int(value, 16)
                pair = (value, 7, operand.shift)
                oper_size_pairs.append(pair)

            # Z Fixes
            if field.name in ["DH1", "DH2"]:
                LOG.debug("Special condition field 3")
                special_condition = True
                pair = (0, field.size, operand.shift)
                oper_size_pairs.append(pair)

            if field.name in ["DL1", "DL2"]:
                LOG.debug("Special condition field 4")
                special_condition = True

                next_field_value = (
                    bin_instr >> (
                        (
                            (instr_type.format.length * 8) -
                            (processed_bits + 8)
                        )
                    )
                ) & (
                    (0b1 << 8) - 1
                )

                pair = (
                    field_value | (next_field_value << field.size),
                    field.size + 8, operand.shift
                )
                oper_size_pairs.append(pair)
                pair = (twocs_to_int(pair[0], pair[1]), pair[1], pair[2])
                oper_size_pairs.append(pair)

            # RISC-V fixes

            # List of immediate fixes which need to be performed
            riscv_fixes = {
                'sb_imm7': ('sb_imm5', 13, True, '12|10:5;#13;4:1|11'),
                's_imm7': ('s_imm5', 12, True, '11:5;#13;4:0'),
                'uj_imm20': (None, 21, True, '20|10:1|11|19:12'),
                'cw_imm3': ('c_imm2', 7, False, '#3;5:3;#3;2|6'),
                'cd_imm3': ('c_imm2', 8, False, '#3;5:3;#3;7|6'),
                'cb_imm5': ('c_imm3', 9, True, '#3;8|4:3;#3;7:6|2:1|5'),
                'cw_imm5': ('c_imm1', 8, False, '#3;5;#5;4:2|7:6'),
                'cd_imm5': ('c_imm1', 9, False, '#3;5;#5;4:3|8:6'),
                'ci_imm5': ('c_imm1', 6, True, '#3;5;#5;4:0'),
                'cu_imm5': ('c_imm1', 20, False, '#3;5;#5;4:0', 5),
                'cs_imm5': ('c_imm1', 10, True, '#3;9;#5;4|6|8:7|5'),
                'cls_imm5': ('c_imm1', 6, False, '#3;5;#5;4:0'),
                'cw_imm6': (None, 8, False, '#3;5:2|7:6'),
                'cd_imm6': (None, 9, False, '#3;5:3|8:6'),
                'c_imm11': (None, 12, True, '#3;11|4|9:8|10|6|7|3:1|5'),
                'cs_imm8': (None, 10, False, '#3;5:4|9:6|2|3')
            }
            zero_fields = [fix[0] for _, (_, fix) in
                           enumerate(riscv_fixes.items())]

            def _parse_riscv_fix_field(fix):
                value = 0
                src_pos = (instr_type.format.length * 8) - 1

                segments = fix[3].split(';')
                for segment in segments:
                    if segment.startswith('#'):
                        src_pos -= int(segment[1:])
                    else:
                        tokens = segment.split('|')
                        for token in tokens:
                            if ':' in token:
                                start, end = map(int, token.split(':'))
                                for dst_pos in range(start, end - 1, -1):
                                    bit = (bin_instr >> src_pos) & 1
                                    value |= (bit << dst_pos)
                                    src_pos -= 1
                            else:
                                bit = (bin_instr >> src_pos) & 1
                                dst_pos = int(token)
                                value |= (bit << dst_pos)
                                src_pos -= 1

                if fix[2]:
                    value = twocs_to_int(value, fix[1])

                if len(fix) == 5 and (value >> fix[4]) > 0:
                    value = (1 << fix[1]) + twocs_to_int(value, fix[4]+1)

                return value

            # Fields which will contain the actual value
            if field.name in riscv_fixes:
                special_condition = True
                fix = riscv_fixes[field.name]
                value = _parse_riscv_fix_field(fix)
                pair = (value, fix[1], operand.shift)
                oper_size_pairs.append(pair)

            # Fields which will contain a 0
            if field.name in zero_fields:
                special_condition = True
                pair = (0, field.size, operand.shift)
                oper_size_pairs.append(pair)

            oper_size_pairs = list(set(oper_size_pairs))
            LOG.debug("Possible operand values: %s", oper_size_pairs)

            valid_values = []
            for operand_value, size, shift in oper_size_pairs:

                # Regular no shift
                valid = (
                    int(operand.codification(operand_value)) == field_value
                )

                # C2 no shift
                valid = valid or (
                    int_to_twocs(operand_value, size + shift) == field_value
                )

                # Regular shifted
                valid = valid or (
                    (
                        int(operand.codification(operand_value)) >> shift
                    ) == field_value
                )

                # C2 shifted
                valid = valid or (
                    (
                        int_to_twocs(operand_value, size + shift) >> shift
                    ) == field_value
                )

                # C2 shifted 2
                valid = valid or (
                    (
                        int_to_twocs(operand_value >> shift, size - shift)
                    ) == field_value
                )

                valid = valid or special_condition

                if valid:

                    LOG.debug("Codification matches")

                    try:

                        LOG.debug("Checking: %s", operand_value)
                        LOG.debug("Operand: %s", operand)
                        LOG.debug("Instruction type: %s", instr_type)
                        operand.check(operand_value)
                        valid_values.append(operand_value)
                        found = True
                        LOG.debug("Codification matches and valid value!")

                    except MicroprobeValueError as exc:
                        LOG.debug(exc)
                        LOG.debug("Codification matches but not valid value")

            operand_values.append(set(valid_values))

        else:

            LOG.debug("Non immediate operand")

            registers = []

            for value in operand.values():

                LOG.debug("Testing value: %s", value)
                if operand.codification(value) == "N/A":
                    continue

                int_val = int(operand.codification(value))
                valid = int_val == field_value

                if int_val > (2**field.size) - 1:

                    mask = (2**field.size) - 1
                    valid = valid or (int_val & mask) == field_value
                    valid = valid or ((int_val >> 1) & mask) == field_value

                # Handle POWERPC specific codification
                if (value.type.name).startswith("SPR"):
                    valid = (
                        ((int_val >> 5) & 0b11111) | (
                            (int_val & 0b11111) << 5
                        )
                    ) == field_value

                if field.name in ['TP']:
                    tmp_value = field_value << 0b1
                    tx_value = ((bin_instr >> 21) & 0b1) * 32
                    tmp_value = tx_value + tmp_value
                    if operand.codification(value) == str(tmp_value):
                        valid = True

                # Handle RISCV specific codification
                if field.name in ['crs1', 'crs2', 'crd',
                                  'fcrs1', 'fcrs2', 'fcrd']:
                    valid = (int_val & 0b1000
                             and (int_val & 0b111) == field_value)

                if valid:
                    try:
                        operand.check(value)
                        registers.append(value)
                        LOG.debug("Adding value: %s", value)
                    except MicroprobeValueError:
                        LOG.debug("Codification matches but not valid value")

            registers = list(set(registers))
            if len(registers) > 0:
                found = True
                operand_values.append(registers)

        if not found:
            return None

    LOG.debug("Operand values: %s", operand_values)
    return operand_values


def _swap_bytes(original, little_endian=False):
    result = ""

    if not little_endian:
        return original

    # Pad with 0s on the left until having an even number of digits
    if(len(original) % 2 != 0):
        original = "0" + original

    while(len(original) > 0):
        original, result = original[:-2], result + original[-2:]

    return result


def _normalize_code(
        code, fmt="hex", endianess_missmatch=False, word_length=None
        ):
    """

    :param code:
    :type code:
    :param iformat:
    :type iformat:
    """

    skip_character = " \n"
    skip_regex = '|'.join([c for c in skip_character])

    if fmt == "hex":
        digit_list = string.hexdigits + skip_character
    elif fmt == "bin":
        digit_list = "01" + skip_character
    else:
        raise MicroprobeBinaryError(
            "Unknown format '%s'" % fmt
        )

    if not isinstance(code, six.string_types):
        raise MicroprobeBinaryError(
            "Invalid input provided. Code is not a string"
        )

    for character in code:
        if not isinstance(character, six.string_types):
            raise MicroprobeBinaryError(
                "Invalid input provided. Not character provided"
            )
        if character not in digit_list:
            raise MicroprobeBinaryError(
                "Invalid input provided. Not hexadecimal number provided"
            )

    code = "".join([char for char in code if char not in skip_character])

    if endianess_missmatch:
        LOG.debug("Fixing missmatch between input data and target's endianess")
        assert word_length is not None
        n = word_length * 2
        words = [(code[i:i+n]) for i in range(0, len(code), n)]
        code = ""
        for word in words:
            code += _swap_bytes(word, True)

    if fmt == "hex":
        return code
    elif fmt == "bin":
        return "".join(
            [
                hex(int(code[elem:elem + 4], 2))[
                    2:
                ] for elem in range(0, len(code), 4)
            ]
        )


# Classes
class MicroprobeBinInstructionStream(object):
    """

    """

    def __init__(
            self, code, target, fmt="hex",
            _data_cache=False, little_endian=None, word_length=None
            ):
        """

        :param code:
        :type code:
        :param target:
        :type target:
        """

        self._little_endian = target.little_endian

        if little_endian is not None:
            self._stream_little_endian = little_endian
        else:
            self._stream_little_endian = target.little_endian

        endianess_missmatch = self._little_endian != self._stream_little_endian

        self._code = _normalize_code(
            code,
            fmt=fmt,
            endianess_missmatch=endianess_missmatch,
            word_length=word_length
        )
        self._fmt = fmt
        self._target = target

        self._index = 0
        self._data_cache = _data_cache
        self._lenghts = list(sorted(_compute_target_lengths(target)))
        self._progress = Progress(len(self._code), msg="Bytes parsed:")

    def empty(self):
        """

        """
        return self._index >= len(self._code)

    @property
    def lengths(self):
        return self._lenghts

    def skip(self, characters=2):
        self._index += characters
        self._progress(increment=characters)
        assert self._index % 2 == 0
        return self._code[self._index - characters:self._index]

    def skip_all(self):
        pindex = self._index
        self._index += len(self._code)
        self._progress(increment=len(self._code)-pindex)
        assert self._index % 2 == 0
        return self._code[pindex:self._index]

    def decode_next(self):
        """

        """
        if self.empty():
            raise MicroprobeBinaryError("Binary stream finished")

        LOG.debug("Index %s : value: %s",
                  self._index, self._code[self._index:self._index + 16])

        bin_str = None

        if self._data_cache and _DATA_CACHE_ENABLED:
            for length in sorted(_DATA_CACHE_LENGTHS, reverse=True):
                bin_str = self._code[self._index:(self._index + length)]
                if bin_str in _DATA_CACHE:
                    self._index += length
                    self._progress(increment=length)
                    return bin_str, None, None

        matches = []
        max_size = max(self._lenghts) * 2
        for length in self._lenghts:

            if self._index == 0 and len(self._code) < (length * 2):
                LOG.debug("Short bin string without leading zeros")
            elif self._index + length * 2 > len(self._code):
                LOG.debug("Skipping length %s ...", length)
                continue

            bin_str = self._code[self._index:self._index + max_size]
            bin_str = bin_str[0:length * 2]

            if self._little_endian:
                bin_str = _swap_bytes(bin_str, self._little_endian)

            bin_int = int(bin_str, 16)

            fmt = "0x%%0%dx" % (length * 2)
            bin_str = fmt % bin_int

            if bin_str in _BIN_CACHE and _BIN_CACHE_ENABLED:
                add = _BIN_CACHE[bin_str][1].format.length * 2
                self._index += add
                self._progress(increment=add)
                return _BIN_CACHE[bin_str]

            LOG.debug("Looking for length: %d", length)

            matches += [
                (instr_type, bin_int)
                for instr_type in self._target.instructions.values()
                if instr_type.format.length == length and instr_type.match(
                    bin_int
                )
            ]

            LOG.debug("Current matches: %s", matches)

        if len(matches) == 0:
            raise MicroprobeBinaryError(
                "Unable to interpret the binary provided: %s" % bin_str
            )

        if len(set([match[0].format.length for match in matches])) > 1:
            raise MicroprobeBinaryError(
                "Multiple instructions with multiple lengths found"
            )

        possible_match_operands = []
        for instr_type, bin_int in matches:
            operands = _interpret_bin_instr(instr_type, bin_int)

            if operands is not None:

                for elem in itertools.product(*operands):
                    possible_match_operands.append((bin_int, instr_type, elem))

        if len(possible_match_operands) == 0:
            raise MicroprobeBinaryError(
                "No variants found when processing: %s" %
                [hex(elem2) for dummy, elem2 in matches]
            )

        for bin_int, instr_type, operand_values in possible_match_operands:

            instruction = microprobe.code.ins.Instruction()
            instruction.set_arch_type(instr_type)

            LOG.debug(
                "Check match: %s : Values: %s",
                instr_type.name,
                operand_values)

            try:

                for operand, value in zip(
                    instruction.operands(), operand_values
                ):
                    operand.set_value(value)

                codification = int(instruction.binary(), 2)

                if bin_int == codification:

                    LOG.debug("Match found")

                    add = instr_type.format.length * 2
                    self._index += add
                    fmt = "0x%%0%dx" % (add)
                    self._progress(increment=add)

                    assert self._index % 2 == 0
                    assert int(
                        fmt %
                        bin_int, 16) == bin_int, (hex(bin_int),
                                                  fmt)

                    if _BIN_CACHE_ENABLED:
                        key = (fmt % bin_int).lower()
                        _BIN_CACHE[key] = (fmt % bin_int,
                                           instr_type,
                                           operand_values)

                    return (fmt % bin_int, instr_type, operand_values)

            except MicroprobeValueError:
                LOG.debug("Skip match")
                continue
            except MicroprobeCodeGenerationError:
                LOG.debug("Skip match")
                continue

        raise MicroprobeBinaryError("No candidates found for %s", hex(bin_int))

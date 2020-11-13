#!/usr/bin/env python
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
File: mp_dma2objdump

This script processes a dma file and dumps the corresponding objdump.
"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import os
import sys

# Third party modules
from six.moves import range
import six

# Own modules
from microprobe.code.address import Address
from microprobe.code.ins import instruction_from_definition
from microprobe.exceptions import MicroprobeDMAFormatError
from microprobe.target import import_definition
from microprobe.utils.bin import interpret_bin
from microprobe.utils.cmdline import CLI, \
    existing_file, int_type, print_warning
from microprobe.utils.misc import Progress, RejectingDict


# Functions
def dump_objdump(target, arguments):
    """

    :param target:
    :type target:
    :param arguments:
    :type arguments:
    """

    ifile = open(arguments['input_dma_file'], 'r')
    dataw = arguments['width_bytes']
    inputlines = ifile.readlines()
    ifile.close()

    progress = Progress(len(inputlines), msg="Lines parsed:")
    lines_dict = {}
    for idx, line in enumerate(inputlines):
        splitline = line.upper().split(" ")

        if len(splitline) != 3:
            raise MicroprobeDMAFormatError(
                "Unable to parse line %d: %s" % (idx, line)
            )

        if (splitline[0] != "D" or len(splitline[1]) != 16 or
                len(splitline[1]) != 16):
            raise MicroprobeDMAFormatError(
                "Unable to parse line %d: %s" % (idx, line)
            )

        key = int(splitline[1], base=16)
        if key in lines_dict:
            print_warning(
                "Address (%s) in line %d overwrites previous entry" %
                (splitline[1], idx)
            )

        lines_dict[key] = splitline[2][:-1]
        progress()

    current_key = None
    progress = Progress(len(list(lines_dict.keys())),
                        msg="Detecting segments:")

    for key in sorted(lines_dict):

        progress()

        if current_key is None:
            current_key = key
            continue

        current_address = current_key + (len(lines_dict[current_key]) // 2)

        if current_address == key:
            lines_dict[current_key] += lines_dict[key]
            lines_dict.pop(key)
        else:
            current_key = key

    instrs = []
    progress = Progress(len(list(lines_dict.keys())),
                        msg="Interpreting segments:")

    for key in sorted(lines_dict):
        progress()
        current_instrs = interpret_bin(
            lines_dict[key],
            target,
            safe=not arguments['strict'])
        current_instrs[0].address = Address(base_address='code',
                                            displacement=key)
        instrs += current_instrs

    maxlen = max([ins.format.length
                  for ins in target.instructions.values()] + [dataw]) * 2
    maxlen += maxlen // 2

    counter = 0
    label_dict = RejectingDict()
    instr_dict = RejectingDict()
    range_num = 1

    progress = Progress(len(instrs), msg="Computing labels:")
    for instr_def in instrs:
        progress()

        if instr_def.address is not None:
            counter = instr_def.address.displacement

        if instr_def.instruction_type is None:

            for idx in range(0, len(instr_def.asm), dataw * 2):

                label = None
                if instr_def.address is not None and idx == 0:
                    label = ".range_%x" % range_num
                    label_dict[counter] = label
                    range_num += 1
                elif counter in label_dict:
                    label = label_dict[counter]

                idx2 = min(idx + (dataw * 2), len(instr_def.asm))

                masm = instr_def.asm[idx:idx2].lower()
                binary = " ".join([str(masm)[i:i + 2]
                                   for i in range(0, len(masm), 2)]).lower()
                instr_dict[counter] = [binary, "0x" + masm, label, None, None]

                counter += (idx2 - idx) // 2

            continue

        instr = instruction_from_definition(instr_def,
                                            fix_relative=False)
        asm = instr.assembly().lower()

        relative = None
        absolute = None
        if instr.branch:

            for memoperand in instr.memory_operands():

                if not memoperand.descriptor.is_branch_target:
                    continue

                for operand in memoperand.operands:
                    if operand.type.address_relative:
                        relative = operand.value

                    if operand.type.address_absolute:
                        absolute = operand.value

        masm = instr_def.asm
        if instr_def.asm.startswith("0x"):
            masm = instr_def.asm[2:]

        if len(masm) % 2 != 0:
            masm = "0" + masm

        binary = " ".join([str(masm)[i:i + 2] for i in range(0, len(masm), 2)])

        assert len(binary.split(" ")) % 2 == 0

        label = None
        if instr_def.address is not None:
            if counter not in label_dict:
                label = ".range_%x" % range_num
                label_dict[counter] = label
                range_num += 1
            else:
                label = label_dict[counter]
        elif counter in label_dict:
            label = label_dict[counter]

        rtarget = None
        atarget = None
        if relative is not None or absolute is not None:

            if relative is not None:
                assert absolute is None

                if isinstance(relative, six.integer_types):
                    target_addr = counter + relative
                    rtarget = relative

                elif isinstance(relative, Address):
                    target_addr = counter + relative.displacement
                    rtarget = relative.displacement
                else:
                    raise NotImplementedError

            if absolute is not None:
                assert relative is None

                if isinstance(absolute, six.integer_types):
                    target_addr = absolute
                    atarget = absolute
                elif isinstance(absolute, Address):
                    target_addr = absolute.displacement
                    atarget = absolute.displacement
                else:
                    raise NotImplementedError

            if target_addr not in label_dict:
                label_dict[target_addr] = "branch_%x" % target_addr

            if target_addr in instr_dict:
                instr_dict[target_addr][2] = label_dict[target_addr]

        instr_dict[counter] = [binary, asm, label, rtarget, atarget]
        counter = counter + (len(masm) // 2)

    for target_addr in label_dict:
        if target_addr not in instr_dict:
            continue

        if instr_dict[target_addr][2] != label_dict[target_addr]:
            assert instr_dict[target_addr][2] is None
            instr_dict[target_addr][2] = label_dict[target_addr]

    print("")
    print(
        "%s:\tfile format raw %s" % (
            os.path.basename(
                arguments['input_dma_file']
            ), target.isa.name
        )
    )
    print("")
    print("")
    print("Disassembly of section .code:")
    print("")

    str_format = "%8s:\t%-" + str(maxlen) + "s\t%s"
    for counter in sorted(instr_dict.keys()):

        binary, asm, label, rtarget, atarget = instr_dict[counter]

        if label is not None:
            print("%016x <%s>:" % (counter, label))

        cformat = str_format
        if rtarget is not None:
            cformat = str_format + "\t <%s>" % (label_dict[counter + rtarget])
        elif atarget is not None:
            cformat = str_format + "\t <%s>" % (label_dict[atarget])

        print(cformat % (hex(counter)[2:], binary, asm))


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe DMA to Objdump tool",
        default_config_file="mp_dma2objdump.cfg",
        force_required=['target']
    )

    groupname = "DMA to Objdump arguments"

    cmdline.add_group(
        groupname, "Command arguments related to DMA to Objdump tool"
    )

    cmdline.add_option(
        "input-dma-file",
        "i",
        None,
        "DMA file to process",
        group=groupname,
        opt_type=existing_file,
        required=True
    )

    cmdline.add_option(
        "width-bytes",
        "w",
        8,
        "Maximum data width in bytes",
        group=groupname,
        opt_type=int_type(0, 32),
    )

    cmdline.add_flag(
        "strict",
        "s",
        "Do not allow unrecognized binary",
        group=groupname,
    )

    cmdline.main(args, _main)


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    target = import_definition(arguments['target'])

    if 'strict' not in arguments:
        arguments['strict'] = False

    dump_objdump(target, arguments)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

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
File: mp_bin2objdump

This script processes a bin file and dumps the corresponding objdump.
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
from microprobe.target import import_definition
from microprobe.utils.bin import interpret_bin
from microprobe.utils.cmdline import CLI, existing_file, \
    int_type, print_error, print_warning
from microprobe.utils.misc import RejectingOrderedDict, which
from microprobe.utils.run import run_cmd_output


# Constants


# Functions
def dump_objdump(target, arguments):
    """

    :param target:
    :type target:
    :param arguments:
    :type arguments:
    """

    cmd = "'%s' -Ax -tx1 -v '%s'" % (
        arguments['od_bin'], arguments['input_bin_file'])
    text_string = run_cmd_output(cmd)
    bintext = []
    for line in text_string.split('\n'):
        if line == "":
            continue
        bintext.append("".join(line.split(' ')[1:]))

    instrs = interpret_bin(
        "".join(bintext), target,
        safe=not arguments['strict']
    )

    print("")
    print(
        "%s:\tfile format raw %s" % (
            os.path.basename(
                arguments['input_bin_file']
            ), target.isa.name
        )
    )
    print("")
    print("")
    print("Disassembly of section .raw:")
    print("")

    maxlen = max(len(instr.asm[2:]) for instr in instrs)
    if maxlen % 2 != 0:
        maxlen = maxlen + 1
    maxlen += maxlen // 2

    counter = arguments['start_address']

    label_dict = RejectingOrderedDict()
    instr_dict = RejectingOrderedDict()

    for instr_def in instrs:
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

        masm = instr_def.asm[2:]
        if len(masm) % 2 != 0:
            masm = "0" + masm

        binary = " ".join([str(masm)[i:i + 2] for i in range(0, len(masm), 2)])

        label = None
        if counter == 0:
            label = ".raw"
            label_dict[counter] = label
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
        counter = counter + len(masm) // 2

    str_format = "%8s:\t%-" + str(maxlen) + "s\t%s"
    addresses = []
    for counter, values in instr_dict.items():

        binary, asm, label, rtarget, atarget = values

        if label is not None:
            print("%016x <%s>:" % (counter, label))

        cformat = str_format
        if rtarget is not None:
            cformat = str_format + "\t <%s>" % (label_dict[counter + rtarget])
        elif atarget is not None:
            cformat = str_format + "\t <%s>" % (label_dict[atarget])

        print(cformat % (hex(counter)[2:], binary, asm))
        addresses.append(counter)

    error = False
    for key in label_dict.keys():
        if key not in addresses:
            print_warning("Target address '%s' not in the objdump" % hex(key))
            error = True

    if error and arguments['strict']:
        print_error("Check target addresses of relative branches")
        exit(-1)


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe Binary to Objdump tool",
        default_config_file="mp_bin2objdump.cfg",
        force_required=['target']
    )

    groupname = "Binary to Objdump arguments"

    cmdline.add_group(
        groupname, "Command arguments related to Binary to Objdump tool"
    )

    cmdline.add_option(
        "input-bin-file",
        "i",
        None,
        "Binary file to process",
        group=groupname,
        opt_type=existing_file,
        required=True
    )

    cmdline.add_option(
        "od-bin",
        "ob",
        which("od"),
        "'od' dump utility. Default: %s" % which("od"),
        group=groupname,
        opt_type=existing_file
    )

    cmdline.add_option(
        "start-address",
        "X",
        0x0,
        "Start address. Default: 0x0",
        group=groupname,
        opt_type=int_type(0, float("+inf"))
    )

    cmdline.add_flag(
        "strict",
        "S",
        "Check relative branches correctness and all instructions valid.",
        group=groupname
    )

    cmdline.main(args, _main)


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    target = import_definition(arguments['target'])

    if arguments['od_bin'] is None:
        print_error(
            "Unable to find a 'od' utility. Edit your $PATH or use"
            " the --od-bin parameter"
        )
        exit(-1)

    if "strict" not in arguments:
        arguments["strict"] = False

    dump_objdump(target, arguments)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

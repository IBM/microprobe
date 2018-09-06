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
File: mp_coblst2mpt

This script processes an cobol lst output and generates the corresponding
mpt file.
"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import gzip
import re
import struct
import sys

# Third party modules
from six.moves import range

# Own modules
from microprobe.code.address import Address
from microprobe.code.ins import instruction_to_definition
from microprobe.target import import_definition
from microprobe.utils.asm import MicroprobeAsmInstructionDefinition, \
    interpret_asm
from microprobe.utils.cmdline import CLI, existing_file, int_type, \
    new_file_ext, print_error, print_info, print_warning
from microprobe.utils.mpt import MicroprobeTestVariableDefinition, \
    mpt_configuration_factory, mpt_parser_factory, \
    variable_to_test_definition
from microprobe.utils.objdump import interpret_objdump


# Constants


# Functions
def dump_mpt(input_file_fd, target, arguments):
    """

    :param input_file_fd:
    :type input_file_fd:
    :param target:
    :type target:
    :param arguments:
    :type arguments:
    """

    try:
        contents = input_file_fd.read()
    except KeyboardInterrupt:
        print_info("No input data provided. Exiting...")
        exit(1)

    print_info("Parsing input file...")

    skip = True
    data_mode = False

    reg_comment = re.compile("^  [0-9][0-9][0-9][0-9][0-9][0-9]: ")
    reg_label = re.compile(":.*EQU     \\*")
    reg_data = re.compile(" +DC +X'")
    reg_entry = re.compile(" +DS +")

    instruction_definitions = []
    data_definitions = []

    clabel = None
    hlabel = None
    paddress = None
    for line in contents.split("\n"):
        if " PROC " in line:
            skip = False

        if skip:
            continue

        if line.startswith("1PP "):
            continue

        if line.replace(" ", "") == "":
            continue

        if " CONSTANT AREA " in line:
            data_mode = True
            continue

        if "***" in line:
            continue

        if data_mode is True and "|" not in line:
            break

        if line.startswith("0"):
            line = line.replace("0", " ", 1)

        sline = [elem for elem in line.split("|")[0].split(" ") if elem != ""]

        if data_mode:
            if line.startswith("0 0"):
                line = line.replace("0 0", "  0", 1)

            address = int(sline[0], 16)

            if len(data_definitions) > 0 and \
                    (address == data_definitions[-1][0] +
                     len(data_definitions[-1][1]) // 2):
                data_definitions[-1][1] += "".join(sline[2:])
            else:
                data_definitions.append(
                    [address, "".join(sline[2:]), "constant_area"])

            continue

        if reg_comment.search(line):
            continue

        if reg_label.search(line):
            clabel = hlabel + "_" + sline[2].replace(":", "")
            continue

        if sline[2] == "PROC":
            hlabel = sline[3]
            continue

        if sline[2] == "RET":
            continue

        if reg_entry.search(line):
            continue

        if reg_data.search(line):
            address = int(sline[0], 16)
            if len(data_definitions) > 0 and \
                    (address == data_definitions[-1][0] +
                     len(data_definitions[-1][1]) // 2):
                data_definitions[-1][1] += "".join(sline[1:3])
                data_definitions[-1][2] += "".join(sline[4:])
            else:
                data_definitions.append(
                    [address, "".join(sline[1:3]), " ".join(sline[4:])])
            continue

        idx = 1
        value = ""
        while len(sline[idx]) == 4:
            value += sline[idx]
            idx += 1

        address = int(sline[0], 16)
        if address - (len(value) // 2) == paddress:
            address = None

        comment = " ".join(sline[idx + 1:])
        asm = "0x%s" % value
        asm_def = MicroprobeAsmInstructionDefinition(
            asm, clabel, address, None, comment)

        instruction_definitions.append(asm_def)
        clabel = None
        paddress = int(sline[0], 16)

    instr_defs = interpret_asm(
        instruction_definitions, target,
        [],
        show_progress=True
    )

    var_defs = []
    for idx, data in enumerate(data_definitions):
        address = data[0]
        var_name = "data_%010d" % idx
        len_init_value = len(data[1]) // 2
        init_value = [int(data[1][2 * idx:2 * (idx + 1)], 16)
                      for idx in range(0, len_init_value)]

        var_defs.append(
            MicroprobeTestVariableDefinition(
                var_name, "char", len_init_value, address, None, init_value
            )
        )

    print_info("Input file parsed")

    print_info(
        "%d instructions processed from the input file" % len(instr_defs)
    )

    if var_defs != []:
        print_info(
            "Variables referenced and detected in the dump: %s" %
            ','.join([var.name for var in var_defs])
        )

    print_info("Generating the MPT contents...")

    mpt_config = mpt_configuration_factory()

    if 'default_code_address' in arguments:
        mpt_config.set_default_code_address(arguments['default_code_address'])
    else:
        mpt_config.set_default_code_address(instr_defs[0].address.displacement)

    if 'default_data_address' in arguments:
        mpt_config.set_default_data_address(arguments['default_data_address'])
    else:
        mpt_config.set_default_data_address(0)

    for var in var_defs:
        mpt_config.register_variable_definition(var)

    mpt_config.register_instruction_definitions(instr_defs)

    print_info("Dumping MPT to '%s'" % arguments['output_mpt_file'])
    mpt_parser = mpt_parser_factory()
    mpt_parser.dump_mpt_config(mpt_config, arguments['output_mpt_file'])


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe COBOL lst to MPT tool",
        default_config_file="mp_coblst2mpt.cfg",
        force_required=['target']
    )

    groupname = "COBOL lst to MPT arguments"

    cmdline.add_group(
        groupname, "Command arguments related to COBOL lst to MPT tool"
    )

    cmdline.add_option(
        "input-coblst-file",
        "i",
        None,
        "COBOL lst file to process, if not provided, the input is read from"
        " standard input",
        group=groupname,
        opt_type=existing_file,
        required=False
    )

    cmdline.add_option(
        "output-mpt-file",
        "O",
        None,
        "Output file name",
        group=groupname,
        opt_type=new_file_ext(".mpt"),
        required=True
    )

    cmdline.add_flag(
        "strict",
        "S",
        "Be strict when parsing objdump input, if not set, silently skip "
        "unparsed elements",
        group=groupname
    )

    cmdline.add_option(
        "from-address",
        "f",
        0x0,
        "If set, start interpreting from this address",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "to-address",
        "t",
        float('+inf'),
        "If set, end interpreting at this address",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "default-code-address",
        "X",
        None,
        "Default code address",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "default-data-address",
        "D",
        None,
        "Default data address",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    print_info("Processing input arguments...")
    cmdline.main(args, _main)


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    print_info("Arguments processed!")

    print_info("Importing target definition...")
    target = import_definition(arguments['target'])

    if "input_coblst_file" in arguments:
        print_info("Input file provided")

        file_fd = open(arguments["input_coblst_file"], 'rb')
        if struct.unpack("cc", file_fd.read(2)) == ('\x1f', '\x8b'):
            print_info("Compressed GZIP file detected")
            file_fd.close()
            file_fd = gzip.open(arguments["input_coblst_file"])
        else:
            file_fd.close()
            file_fd = open(arguments["input_coblst_file"])

    else:
        print_info("No input file provided, reading from standard input... ")
        file_fd = sys.stdin

    dump_mpt(file_fd, target, arguments)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

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
File: mp_obdump2mpt

This script processes an objdump output and generates the corresponding
mpt file.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import gzip
import struct
import sys

# Third party modules
import six

# Own modules
from microprobe.code.address import Address
from microprobe.code.ins import instruction_to_definition
from microprobe.target import import_definition
from microprobe.utils.cmdline import CLI, existing_file, int_type, \
    new_file_ext, print_error, print_info, print_warning
from microprobe.utils.misc import open_generic_fd
from microprobe.utils.mpt import mpt_configuration_factory, \
    mpt_parser_factory, variable_to_test_definition
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
        if six.PY3 and not isinstance(contents, str):
            contents = contents.decode()
    except KeyboardInterrupt:
        print_info("No input data provided. Exiting...")
        exit(1)

    print_info("Parsing input file...")

    print_info("Sections to parse: %s" % arguments['sections'])

    var_defs, req_defs, instr_defs = \
        interpret_objdump(contents, target,
                          strict=arguments.get('strict', False),
                          sections=arguments['sections'],
                          start_address=arguments['from_address'],
                          end_address=arguments['to_address'])

    print_info("Input file parsed")

    print_info(
        "%d instructions processed from the input file" % len(instr_defs)
    )

    if var_defs != []:
        print_info(
            "Variables referenced and detected in the dump: %s" %
            ','.join([var.name for var in var_defs])
        )

    if req_defs != []:
        print_warning(
            "Variables referenced and *NOT* detected in the dump: %s" %
            ','.join([var.name for var in req_defs])
        )
        print_warning(
            "You might need to edit the generated MPT to fix the"
            " declaration of such variables"
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

    if arguments.get('elf_abi', False):

        kwargs = {}
        if "stack_name" in arguments:
            kwargs["stack_name"] = arguments["stack_name"]
        if "stack_address" in arguments:
            kwargs["stack_address"] = Address(
                base_address="code",
                displacement=arguments["stack_address"]
            )

        variables, instructions = target.elf_abi(
            arguments["stack_size"], arguments.get(
                "start_symbol", None
            ), **kwargs
        )

        for variable in variables:
            req_defs.append(variable_to_test_definition(variable))

        address = instr_defs[0].address
        for instr in reversed(instructions):
            instr_defs = [instruction_to_definition(instr)] + instr_defs
            address -= instr.architecture_type.format.length

        if address.displacement < 0:
            print_error(
                "Default code address is below zero after"
                " adding the initialization code."
            )
            print_error(
                "Check/modify the objdump provided or do not use"
                " the elf_abi flag."
            )
            exit(-1)

        mpt_config.set_default_code_address(address.displacement)

    instr = None
    if "end_branch_to_itself" in arguments:
        instr = target.branch_to_itself()
    elif arguments.get('elf_abi', False):
        instr = target.nop()

    if instr is not None:
        instr.set_label("ELF_ABI_EXIT")
        instr_defs.append(instruction_to_definition(instr))

    for var in var_defs + req_defs:
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
        "Microprobe Objdump to MPT tool",
        default_config_file="mp_objdump2mpt.cfg",
        force_required=['target']
    )

    groupname = "Objdump to MPT arguments"

    cmdline.add_group(
        groupname, "Command arguments related to Objdump to MPT tool"
    )

    cmdline.add_option(
        "input-objdump-file",
        "i",
        None,
        "Objdump file to process, if not provided, the input is read from"
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
        "sections",
        "s", ['.text'],
        "Space separated CODE section names to interpret. "
        "(default: '.text' section)",
        group=groupname,
        nargs='+',
        required=False
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

    cmdline.add_flag(
        "elf-abi",
        None,
        "Ensure ELF Application Binary Interface (e.g. define stack, stack"
        " pointer, etc.)",
        group=groupname
    )

    cmdline.add_option(
        "stack-size",
        None,
        4096,
        "Stack size in bytes (Default: 4096)",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "stack-name",
        None,
        None,
        "Stack name (Default: microprobe_stack)",
        group=groupname,
        opt_type=str,
        required=False
    )

    cmdline.add_option(
        "stack-address",
        None,
        None,
        "Stack address (Default: allocated in the data area)",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "start-symbol",
        None,
        None,
        "Symbol to call after initializing the stack. If not specified, "
        "no call is performed",
        group=groupname,
        opt_type=str,
        required=False
    )

    cmdline.add_flag(
        "end-branch-to-itself",
        None,
        "A branch to itself instruction will be added at the end of the test",
        group=groupname
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

    if "input_objdump_file" in arguments:
        print_info("Input file provided")
        file_fd = open_generic_fd(arguments["input_objdump_file"], 'r')
    else:
        print_info("No input file provided, reading from standard input... ")
        file_fd = sys.stdin

    dump_mpt(file_fd, target, arguments)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

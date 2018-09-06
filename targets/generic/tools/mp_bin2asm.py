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
File: mp_bin2asm

This script processes a bin file and dumps the corresponding assembly.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import sys

# Own modules
from microprobe.code.ins import instruction_from_definition
from microprobe.target import import_definition
from microprobe.utils.bin import interpret_bin
from microprobe.utils.cmdline import CLI, \
    existing_file, print_error, print_info
from microprobe.utils.misc import which
from microprobe.utils.run import run_cmd_output


# Constants


# Functions
def dump_bin(target, arguments):
    """

    :param target:
    :type target:
    :param arguments:
    :type arguments:
    """

    print_info("Parsing input file...")

    cmd = "od -Ax -tx1 -v '%s'" % arguments['input_bin_file']
    text_string = run_cmd_output(cmd)
    bintext = []
    for line in text_string.split('\n'):
        if line == "":
            continue
        bintext.append("".join(line.split(' ')[1:]))

    instrs = interpret_bin("".join(bintext), target)
    for instr in instrs:
        print(instruction_from_definition(instr).assembly())


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe Binary to Assembly tool",
        default_config_file="mp_bin2asm.cfg",
        force_required=['target']
    )

    groupname = "Binary to Assembly arguments"

    cmdline.add_group(
        groupname, "Command arguments related to Binary to Assembly tool"
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

    if arguments['od_bin'] is None:
        print_error(
            "Unable to find a 'od' utility. Edit your $PATH or use"
            " the --od-bin parameter"
        )
        exit(-1)

    dump_bin(target, arguments)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

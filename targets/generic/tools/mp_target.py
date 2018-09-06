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
File: mp_target

This script shows the requested information from a given target.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import sys

# Own modules
from microprobe.target import import_definition
from microprobe.utils.cmdline import CLI, parse_instruction_list, print_info


# Constants


# Functions
def print_target_info(target, info):
    """
    Prints the information *info* requested from the *target*. If the *info*
    is None, all the information is printed.

    :param target: Target definition object
    :type target: :class:`Target`
    :param info: Information requested
    :type info: :class:`str`
    """
    if info is None:
        print(target.full_report())


def print_instruction_info(instruction, info):
    """
    Prints the information *info* requested from the *target*. If the *info*
    is None, all the information is printed.

    :param instruction: Instruction defintion object
    :type instruction: :class:`Instruction`
    :param info: Information requested
    :type info: :class:`str`
    """
    if info is None:
        print(instruction.full_report())


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe Target definition query tool",
        default_config_file="mp_target.cfg",
        force_required=['target']
    )

    groupname = "Instruction"
    cmdline.add_group(
        groupname, "Command arguments related to instruction information"
    )

    cmdline.add_option(
        "instructions",
        "ins",
        None,
        "Comma separated list of instructions to obtain information",
        group=groupname,
        opt_type=str,
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

    if 'instructions' not in arguments:
        print_info("Dumping target %s" % target.name)
        print_target_info(target, None)
    else:

        arguments['instructions'] = parse_instruction_list(
            target, arguments['instructions']
        )

        for instruction in arguments['instructions']:
            print_instruction_info(instruction, None)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

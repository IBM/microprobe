#!/usr/bin/env python
# Copyright 2011-2021 IBM Corporation
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
File: mp_mpt2trace

This script implements the tool that converts mpt files Qtraces.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import sys

# Own modules
import microprobe
import microprobe.code
import microprobe.passes.address
import microprobe.passes.branch
import microprobe.passes.ilp
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.memory
import microprobe.passes.register
import microprobe.passes.structure
import microprobe.passes.symbol
import microprobe.passes.variable
import microprobe.utils.cmdline
from microprobe.exceptions import MicroprobeException, \
    MicroprobeMPTFormatError, MicroprobeValueError
from microprobe.target import import_definition
from microprobe.utils.asm import interpret_asm
from microprobe.utils.cmdline import csv_with_integer, \
    csv_with_ranges, file_with, int_type, new_file_ext, \
    print_error, print_info, print_warning, string_with_chars
from microprobe.utils.logger import get_logger

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
LOG = get_logger(__name__)
_DEFAULT_MAX_INS = 100000


# Functions
def generate(test_definition, outputfile, target, **kwargs):
    """
    Microbenchmark generation policy

    :param test_definition: Test definition object
    :type test_definition: :class:`MicroprobeTestDefinition`
    :param outputfile: Outputfile name
    :type outputfile: :class:`str`
    :param target: Target definition object
    :type target: :class:`Target`
    """

    variables = test_definition.variables
    print_info("Interpreting assembly...")
    sequence = interpret_asm(
        test_definition.code, target, [var.name for var in variables]
    )

    if len(sequence) < 1:
        raise MicroprobeMPTFormatError(
            "No instructions found in the 'instructions' entry of the MPT"
            " file. Check the input file."
        )

    max_ins = test_definition.instruction_count
    if kwargs["max_trace_size"] != _DEFAULT_MAX_INS or max_ins is None:
        max_ins = kwargs["max_trace_size"]

    # registers = test_definition.registers
    # raw = test_definition.raw

    # if test_definition.default_data_address is None:
    #    print_error("Default data address is needed")
    #    exit(-1)

    # if test_definition.default_code_address is None:
    #    print_error("Default code address is needed")
    #    exit(-1)

    wrapper_name = "QTrace"

    print_info("Creating benchmark synthesizer...")

    try:
        cwrapper = microprobe.code.get_wrapper(wrapper_name)
    except MicroprobeValueError as exc:
        raise MicroprobeException(
            "Wrapper '%s' not available. Check if you have the wrappers "
            "of the target installed or set up an appropriate "
            "MICROPROBEWRAPPERS environment variable. Original error was: %s" %
            (wrapper_name, str(exc))
        )

    wrapper_kwargs = {}
    wrapper_kwargs["init_code_address"] = test_definition.default_code_address
    wrapper_kwargs["init_data_address"] = test_definition.default_data_address
    wrapper = cwrapper(**wrapper_kwargs)

    start_addr = [
        reg.value for reg in test_definition.registers
        if reg.name == "PC"
    ]

    if start_addr:
        start_addr = start_addr[0]
    else:
        start_addr = None

    synth = microprobe.code.TraceSynthesizer(
        target, wrapper, show_trace=kwargs.get(
            "show_trace", False), maxins=max_ins, start_addr=start_addr
    )

    # if len(registers) >= 0:
    #    synth.add_pass(
    #        microprobe.passes.initialization.InitializeRegistersPass(
    #            registers, skip_unknown=True, warn_unknown=True
    #        )
    #    )

    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(len(sequence))
    )

    synth.add_pass(
        microprobe.passes.instruction.ReproduceSequencePass(sequence)
    )

    synth.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass()
    )

    synth.add_pass(
        microprobe.passes.branch.NormalizeBranchTargetsPass()
    )

    synth.add_pass(
        microprobe.passes.memory.InitializeMemoryDecorator(
            default=kwargs.get("default_memory_access_pattern", None)
        )
    )

    synth.add_pass(
        microprobe.passes.branch.InitializeBranchDecorator(
            default=kwargs.get("default_branch_pattern", None),
            indirect=kwargs.get("default_branch_indirect_target_pattern", None)
        )
    )

    synth.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass()
    )

    print_info("Synthesizing...")
    bench = synth.synthesize()

    # Save the microbenchmark
    synth.save(outputfile, bench=bench)
    return


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = microprobe.utils.cmdline.CLI(
        "MicroprobeTest (mpt) to TRACE tool",
        mpt_options=True,
        default_config_file="mp_mpt2trace.cfg",
        force_required=['target']
    )

    groupname = "MPT to trace arguments"
    cmdline.add_group(
        groupname,
        "Command arguments related to MPT to trace tool")

    cmdline.add_option(
        "trace-output-file",
        "O",
        None,
        "C output file name",
        group=groupname,
        opt_type=new_file_ext([".qt", ".qt.gz", ".qt.bz2"]),
        required=True
    )

    groupname = "Trace generation options"
    cmdline.add_group(groupname,
                      "Command arguments related to trace generation options")

    cmdline.add_option(
        "default-memory-access-pattern", None, None,
        "Memory access pattern for memory references that are not modeled by"
        "Microprobe or not modeled using 'MP' decorator in MPT file. "
        "Format: comma separated list of addresses or address ranges. If a "
        "file path is provided, the file is readed to gather the list of "
        "addresses.  The format of the file should be one address or range "
        "per line. Address range format is : <start>-<end>-<strid>. E.g. "
        "0x100-0x200-0x010 will generate 0x100,0x110,0x120...0x1F0,0x200 "
        "pattern.",
        group=groupname,
        opt_type=file_with(csv_with_ranges(0, 0xFFFFFFFFFFFFFFFF)),
    )

    cmdline.add_option(
        "default-branch-pattern", None, None,
        "Branch pattern for branches that are not modeled by"
        "Microprobe or not modeled using 'BP' decorator in MPT file. "
        "Format: string with T or N, for taken and not taken branches, "
        " respectively. If a file path is provided, the file is readed to "
        "gather the branch pattern. The format of the file should be one "
        "string providing the branch pattern (T and N characters).",
        group=groupname,
        opt_type=file_with(string_with_chars('TN')),
    )

    cmdline.add_option(
        "default-branch-indirect-target-pattern", None, None,
        "Branch target pattern for branches that are not modeled by"
        "Microprobe or not modeled using 'BT' decorator in MPT file. "
        "Format: comma separated list of target addresses. If a file "
        "path is provided, the file is readed to gather the list of addresses."
        " The format of the file should be one address per line.",
        group=groupname,
        opt_type=file_with(csv_with_integer),
    )

    cmdline.add_option(
        "max-trace-size", None, _DEFAULT_MAX_INS,
        "Maximum trace size in intructions. Default: %d" % _DEFAULT_MAX_INS,
        group=groupname,
        opt_type=int_type(0, 999999999999),
    )

    cmdline.add_flag(
        "show-trace",
        None,
        "Show trace while being generated",
        group=groupname,
    )

    cmdline.add_flag(
        "safe-bin", None, "Ignore unrecognized binary codifications (do not"
        "fail). Useful when MPTs are generated by dumping directly code "
        "pages, which contain padding zeros and other non-code stuff)",
        groupname
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

    if 'safe-bin' in arguments:
        microprobe.MICROPROBE_RC['safe_bin'] = True

    target = import_definition(arguments.pop('target'))
    test_definition = arguments.pop('mpt_definition')
    outputfile = arguments.pop('trace_output_file')

    print_info("Start generating '%s'" % outputfile)
    generate(test_definition, outputfile, target, **arguments)
    print_info("'%s' generated!" % outputfile)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

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
File: mp_mpt2c

This script implements the tool that converts mpt files C code.
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
from microprobe.utils.cmdline import new_file_ext, print_info, print_warning
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)


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

    registers = test_definition.registers
    raw = test_definition.raw

    for instruction_def in sequence:
        if instruction_def.address is not None:
            print_warning(
                "Instruction address not needed in '%s'" % instruction_def.asm
            )

    if test_definition.default_data_address is not None:
        print_warning("Default data address not needed")

    if test_definition.default_code_address is not None:
        print_warning("Default code address not needed")

    wrapper_name = "CWrapper"
    if kwargs.get("endless", False):
        print_warning("Using endless C wrapper")
        wrapper_name = "CInfGen"

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
    wrapper = cwrapper(**wrapper_kwargs)

    synth = microprobe.code.Synthesizer(target, wrapper, extra_raw=raw)

    if len(registers) >= 0:
        print_info("Add register initialization pass")
        synth.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                registers, skip_unknown=True, warn_unknown=True
            )
        )

    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(len(sequence))
    )
    synth.add_pass(microprobe.passes.variable.DeclareVariablesPass(variables))
    synth.add_pass(
        microprobe.passes.instruction.ReproduceSequencePass(sequence)
    )

    if kwargs.get("fix_memory_registers", False):
        kwargs["fix_memory_references"] = True

    if kwargs.get("fix_memory_references", False):
        synth.add_pass(
            microprobe.passes.memory.FixMemoryReferencesPass(
                reset_registers=kwargs.get("fix_memory_registers", False)
            )
        )

    if kwargs.get("fix_memory_registers", False):
        print_info("Fix memory registers: On")
        synth.add_pass(microprobe.passes.register.NoHazardsAllocationPass())

    if kwargs.get("fix_branch_next", False):
        print_info("Force branch to next: On")
        synth.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass())
        synth.add_pass(microprobe.passes.branch.BranchNextPass(
            force=True))

    if kwargs.get("fix_indirect_branches", False):
        print_info("Fix indirect branches: On")
        synth.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass())
        synth.add_pass(microprobe.passes.branch.FixIndirectBranchPass())

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
        "MicroprobeTest (mpt) to C tool",
        mpt_options=True,
        default_config_file="mp_mpt2c.cfg",
        force_required=['target']
    )

    groupname = "MPT to C arguments"
    cmdline.add_group(groupname, "Command arguments related to MPT to C tool")

    cmdline.add_option(
        "c-output-file",
        "O",
        None,
        "C output file name",
        group=groupname,
        opt_type=new_file_ext(".c"),
        required=True
    )

    groupname = "Fixing options"
    cmdline.add_group(groupname, "Command arguments related to fixing options")
    cmdline.add_flag(
        "fix-indirect-branches", None, "Fix branches without known target",
        groupname
    )
    cmdline.add_flag(
        "fix-branch-next", None, "Force target of branches to be the next "
        "sequential instruction",
        groupname
    )
    cmdline.add_flag(
        "fix-memory-references", None,
        "Ensure that registers used by instructions accessing "
        "storage are initialized to valid locations", groupname
    )
    cmdline.add_flag(
        "fix-memory-registers", None,
        "Fix non-storage instructions touching registers used for"
        " storage address computations (implies "
        "--fix-memory-referenes flag)", groupname
    )

    cmdline.add_flag(
        "endless", None, "Wrap the code generated within an endless loop",
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
    target = import_definition(arguments.pop('target'))
    test_definition = arguments.pop('mpt_definition')
    outputfile = arguments.pop('c_output_file')

    print_info("Start generating '%s'" % outputfile)
    generate(test_definition, outputfile, target, **arguments)
    print_info("'%s' generated!" % outputfile)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

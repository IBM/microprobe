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
power_v206_power7_ppc64_linux_gcc_profile.py

Example module to show how to generate a benchmark for each instruction
of the ISA
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import multiprocessing as mp
import os
import sys
import traceback

# Third party modules
from six.moves import map, range

# Own modules
import microprobe.code.ins
import microprobe.passes.address
import microprobe.passes.branch
import microprobe.passes.decimal
import microprobe.passes.float
import microprobe.passes.ilp
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.memory
import microprobe.passes.register
import microprobe.passes.structure
import microprobe.utils.cmdline
from microprobe.exceptions import MicroprobeException
from microprobe.target import import_definition
from microprobe.utils.cmdline import existing_dir, \
    int_type, print_error, print_info, print_warning
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
LOG = get_logger(__name__)  # Get the generic logging interface


# Functions
def main_setup():
    """
    Set up the command line interface (CLI) with the arguments required by
    this command line tool.
    """

    args = sys.argv[1:]

    # Create the CLI interface object
    cmdline = microprobe.utils.cmdline.CLI("ISA power v206 profile example",
                                           config_options=False,
                                           target_options=False,
                                           debug_options=False)

    # Add the different parameters for this particular tool
    cmdline.add_option(
        "instruction",
        "i",
        None,
        "Instruction names to generate. Default: All instructions",
        required=False,
        nargs="+",
        metavar="INSTRUCTION_NAME")

    cmdline.add_option(
        "output_prefix",
        None,
        "POWER_V206_PROFILE",
        "Output prefix of the generated files. Default: POWER_V206_PROFILE",
        opt_type=str,
        required=False,
        metavar="PREFIX")

    cmdline.add_option(
        "output_path",
        "O",
        "./",
        "Output path. Default: current path",
        opt_type=existing_dir,
        metavar="PATH")

    cmdline.add_option(
        "parallel",
        "p",
        mp.cpu_count(),
        "Number of parallel jobs. Default: number of CPUs available (%s)" %
        mp.cpu_count(),
        opt_type=int,
        choices=list(range(
            1,
            mp.cpu_count() +
            1)),
        metavar="NUM_JOBS")

    cmdline.add_option(
        "size",
        "S",
        64,
        "Benchmark size (number of instructions in the endless loop). "
        "Default: 64 instructions",
        opt_type=int_type(1, 2**20),
        metavar="BENCHMARK_SIZE")

    cmdline.add_option(
        "dependency_distance",
        "D",
        1000,
        "Average dependency distance between the instructions. "
        "Default: 1000 (no dependencies)",
        opt_type=int_type(1, 1000),
        metavar="DEPENDECY_DISTANCE")

    # Start the main
    print_info("Processing input arguments...")
    cmdline.main(args, _main)


def _main(arguments):
    """
    Main program. Called after the arguments from the CLI interface have
    been processed.
    """

    print_info("Arguments processed!")

    print_info("Importing target definition "
               "'power_v206-power7-ppc64_linux_gcc'...")
    target = import_definition("power_v206-power7-ppc64_linux_gcc")

    # Get the arguments
    instructions = arguments.get("instruction", None)
    prefix = arguments["output_prefix"]
    output_path = arguments["output_path"]
    parallel_jobs = arguments["parallel"]
    size = arguments["size"]
    distance = arguments["dependency_distance"]

    # Process the arguments
    if instructions is not None:

        # If the user has provided some instructions, make sure they
        # exists and then we call the generation function

        instructions = _validate_instructions(instructions, target)

        if len(instructions) == 0:
            print_error("No valid instructions defined.")
            exit(-1)

        # Set more verbose level
        # set_log_level(10)
        #
        list(map(_generate_benchmark,
                 [(instruction,
                   prefix,
                   output_path,
                   target, size, distance) for instruction in instructions]))

    else:

        # If the user has not provided any instruction, go for all of them
        # and then call he generation function

        instructions = _generate_instructions(target, output_path, prefix)

        # Since several benchmark will be generated, reduce verbose level
        # and call the generation function in parallel

        # set_log_level(30)

        if parallel_jobs > 1:
            pool = mp.Pool(processes=parallel_jobs)
            pool.map(_generate_benchmark,
                     [(instruction,
                       prefix,
                       output_path,
                       target,
                       size,
                       distance) for instruction in instructions],
                     1)
        else:
            list(map(_generate_benchmark,
                     [(instruction,
                       prefix,
                       output_path,
                       target,
                       size,
                       distance) for instruction in instructions]))


def _validate_instructions(instructions, target):
    """
    Validate the provided instruction for a given target
    """

    nins = []
    for instruction in instructions:

        if instruction not in list(target.isa.instructions.keys()):
            print_warning(
                "'%s' not defined in the ISA. Skipping..." %
                instruction)
            continue
        nins.append(instruction)
    return nins


def _generate_instructions(target, path, prefix):
    """
    Generate the list of instruction to be generated for a given target
    """

    instructions = []
    for name, instr in target.instructions.items():

        if instr.privileged or instr.hypervisor:
            # Skip priv/hyper instructions
            continue

        if instr.branch and not instr.branch_relative:
            # Skip branch absolute due to relocation problems
            continue

        if instr.category in ['LMA', 'LMV', 'DS', 'EC']:
            # Skip some instruction categories
            continue

        if name in ['LSWI_V0', 'LSWX_V0', 'LMW_V0', 'STSWX_V0',
                    'LD_V1', 'LWZ_V1', 'STW_V1']:
            # Some instructions are not completely supported yet
            # String-related instructions and load multiple

            continue

        # Skip if the files already exists

        fname = "%s/%s_%s.c" % (path, prefix, name)
        ffname = "%s/%s_%s.c.fail" % (path, prefix, name)

        if os.path.isfile(fname):
            print_warning("Skip %s. '%s' already generated" % (name, fname))
            continue

        if os.path.isfile(ffname):
            print_warning("Skip %s. '%s' already generated (failed)"
                          % (name, ffname))
            continue

        instructions.append(name)

    return instructions


def _generate_benchmark(args):
    """
    Actual benchmark generation policy. This is the function that defines
    how the microbenchmark are going to be generated
    """

    instr_name, prefix, output_path, target, size, distance = args

    try:

        # Name of the output file
        fname = "%s/%s_%s" % (output_path, prefix, instr_name)

        # Name of the fail output file (generated in case of exception)
        ffname = "%s.c.fail" % (fname)

        print_info("Generating %s ..." % (fname))

        instruction = microprobe.code.ins.Instruction()
        instruction.set_arch_type(target.instructions[instr_name])
        sequence = [target.instructions[instr_name]]

        # Get the wrapper object. The wrapper object is in charge of
        # translating the internal representation of the microbenchmark
        # to the final output format.
        #
        # In this case, we obtain the 'CInfGen' wrapper, which embeds
        # the generated code within an infinite loop using C plus
        # in-line assembly statements.
        cwrapper = microprobe.code.get_wrapper("CInfGen")

        # Create the synthesizer object, which is in charge of driving the
        # generation of the microbenchmark, given a set of passes
        # (a.k.a. transformations) to apply to the an empty internal
        # representation of the microbenchmark
        synth = microprobe.code.Synthesizer(target, cwrapper(),
                                            value=0b01010101)

        # Add the transformation passes

        #######################################################################
        # Pass 1: Init integer registers to a given value                     #
        #######################################################################
        synth.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                value=_init_value()))
        floating = False
        vector = False

        for operand in instruction.operands():
            if operand.type.immediate:
                continue

            if operand.type.float:
                floating = True

            if operand.type.vector:
                vector = True

        if vector and floating:
            ###################################################################
            # Pass 1.A: if instruction uses vector floats, init vector        #
            #           registers to float values                             #
            ###################################################################
            synth.add_pass(
                microprobe.passes.initialization.InitializeRegistersPass(
                    v_value=(
                        1.000000000000001,
                        64)))
        elif vector:
            ###################################################################
            # Pass 1.B: if instruction uses vector but not floats, init       #
            #           vector registers to integer value                     #
            ###################################################################
            synth.add_pass(
                microprobe.passes.initialization.InitializeRegistersPass(
                    v_value=(
                        _init_value(),
                        64)))
        elif floating:
            ###################################################################
            # Pass 1.C: if instruction uses floats, init float                #
            #           registers to float values                             #
            ###################################################################
            synth.add_pass(
                microprobe.passes.initialization.InitializeRegistersPass(
                    fp_value=1.000000000000001))

        #######################################################################
        # Pass 2: Add a building block of size 'size'                         #
        #######################################################################
        synth.add_pass(
            microprobe.passes.structure.SimpleBuildingBlockPass(size))

        #######################################################################
        # Pass 3: Fill the building block with the instruction sequence       #
        #######################################################################
        synth.add_pass(
            microprobe.passes.instruction.SetInstructionTypeBySequencePass(
                sequence
            )
        )

        #######################################################################
        # Pass 4: Compute addresses of instructions (this pass is needed to   #
        #         update the internal representation information so that in   #
        #         case addresses are required, they are up to date).          #
        #######################################################################
        synth.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass())

        #######################################################################
        # Pass 5: Set target of branches to be the next instruction in the    #
        #         instruction stream                                          #
        #######################################################################
        synth.add_pass(microprobe.passes.branch.BranchNextPass())

        #######################################################################
        # Pass 6: Set memory-related operands to access 16 storage locations  #
        #         in a round-robin fashion in stride 256 bytes.               #
        #         The pattern would be: 0, 256, 512, .... 3840, 0, 256, ...   #
        #######################################################################
        synth.add_pass(
            microprobe.passes.memory.SingleMemoryStreamPass(
                16,
                256))

        #######################################################################
        # Pass 7.A: Initialize the storage locations accessed by floating     #
        #           point instructions to have a valid floating point value   #
        #######################################################################
        synth.add_pass(microprobe.passes.float.InitializeMemoryFloatPass(
            value=1.000000000000001)
        )

        #######################################################################
        # Pass 7.B: Initialize the storage locations accessed by decimal      #
        #           instructions to have a valid decimal value                #
        #######################################################################
        synth.add_pass(
            microprobe.passes.decimal.InitializeMemoryDecimalPass(
                value=1))

        #######################################################################
        # Pass 8: Set the remaining instructions operands (if not set)        #
        #         (Required to set remaining immediate operands)              #
        #######################################################################
        synth.add_pass(
            microprobe.passes.register.DefaultRegisterAllocationPass(
                dd=distance))

        # Synthesize the microbenchmark.The synthesize applies the set of
        # transformation passes added before and returns object representing
        # the microbenchmark
        bench = synth.synthesize()

        # Save the microbenchmark to the file 'fname'
        synth.save(fname, bench=bench)

        print_info("%s generated!" % (fname))

        # Remove fail file if exists
        if os.path.isfile(ffname):
            os.remove(ffname)

    except MicroprobeException:

        # In case of exception during the generation of the microbenchmark,
        # print the error, write the fail file and exit
        print_error(traceback.format_exc())
        open(ffname, 'a').close()
        exit(-1)


def _init_value():
    """ Return a init value """
    return 0b0101010101010101010101010101010101010101010101010101010101010101


# Main
if __name__ == '__main__':
    # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main_setup')):
        main_setup()
        exit(0)

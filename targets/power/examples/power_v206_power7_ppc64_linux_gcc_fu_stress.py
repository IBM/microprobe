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
power_v206_power7_ppc64_linux_gcc_fu_stress.py

Example module to show how to generate a benchmark stressing a particular
functional unit of the microarchitecture at different rate using the
average latency of instructions as well as the average dependency distance
between the instructions
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os
import sys
import traceback

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
from microprobe.exceptions import MicroprobeException, \
    MicroprobeTargetDefinitionError
from microprobe.target import import_definition
from microprobe.utils.cmdline import dict_key, existing_dir, \
    float_type, int_type, print_error, print_info
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

    # Get the target definition
    try:
        target = import_definition("power_v206-power7-ppc64_linux_gcc")
    except MicroprobeTargetDefinitionError as exc:
        print_error("Unable to import target definition")
        print_error("Exception message: %s" % str(exc))
        exit(-1)

    func_units = {}
    valid_units = [elem.name for elem in target.elements.values()]

    for instr in target.isa.instructions.values():
        if instr.execution_units == "None":
            LOG.debug("Execution units for: '%s' not defined", instr.name)
            continue

        for unit in instr.execution_units:
            if unit not in valid_units:
                continue

            if unit not in func_units:
                func_units[unit] = [elem for elem in target.elements.values()
                                    if elem.name == unit][0]

    # Create the CLI interface object
    cmdline = microprobe.utils.cmdline.CLI("ISA power v206 profile example",
                                           config_options=False,
                                           target_options=False,
                                           debug_options=False)

    # Add the different parameters for this particular tool
    cmdline.add_option(
        "functional_unit",
        "f",
        [func_units['ALU']],
        "Functional units to stress. Default: ALU",
        required=False,
        nargs="+",
        choices=func_units,
        opt_type=dict_key(func_units),
        metavar="FUNCTIONAL_UNIT_NAME")

    cmdline.add_option(
        "output_prefix",
        None,
        "POWER_V206_FU_STRESS",
        "Output prefix of the generated files. Default: POWER_V206_FU_STRESS",
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

    cmdline.add_option(
        "average_latency",
        "L",
        2,
        "Average latency of the selected instructins. "
        "Default: 2 cycles",
        opt_type=float_type(1, 1000),
        metavar="AVERAGE_LATENCY")

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
    functional_units = arguments["functional_unit"]
    prefix = arguments["output_prefix"]
    output_path = arguments["output_path"]
    size = arguments["size"]
    latency = arguments["average_latency"]
    distance = arguments["dependency_distance"]

    if functional_units is None:
        functional_units = ["ALL"]

    _generate_benchmark(target,
                        "%s/%s_" % (output_path, prefix),
                        (functional_units, size, latency, distance))


def _generate_benchmark(target, output_prefix, args):
    """
    Actual benchmark generation policy. This is the function that defines
    how the microbenchmark are going to be generated
    """

    functional_units, size, latency, distance = args

    try:

        # Name of the output file
        func_unit_names = [unit.name for unit in functional_units]
        fname = "%s%s" % (output_prefix, "_".join(func_unit_names))
        fname = "%s_LAT_%s" % (fname, latency)
        fname = "%s_DEP_%s" % (fname, distance)

        # Name of the fail output file (generated in case of exception)
        ffname = "%s.c.fail" % (fname)

        print_info("Generating %s ..." % (fname))

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

        #######################################################################
        # Pass 2: Add a building block of size 'size'                         #
        #######################################################################
        synth.add_pass(
            microprobe.passes.structure.SimpleBuildingBlockPass(size)
        )

        #######################################################################
        # Pass 3: Fill the building block with the instruction sequence       #
        #######################################################################
        synth.add_pass(
            microprobe.passes.instruction.SetInstructionTypeByElementPass(
                target,
                functional_units,
                {}))

        #######################################################################
        # Pass 4: Compute addresses of instructions (this pass is needed to   #
        #         update the internal representation information so that in   #
        #         case addresses are required, they are up to date).          #
        #######################################################################
        synth.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass()
        )

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

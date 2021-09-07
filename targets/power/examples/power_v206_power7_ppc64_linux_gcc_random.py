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
power_v206_power7_ppc64_linux_gcc_memory.py

Example python script to show how to generate random microbenchmarks.
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import multiprocessing as mp
import os
import random
import sys

# Third party modules
from six.moves import map, range

# Own modules
import microprobe.code
import microprobe.passes.address
import microprobe.passes.branch
import microprobe.passes.ilp
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.memory
import microprobe.passes.register
import microprobe.passes.structure
from microprobe.exceptions import MicroprobeError, \
    MicroprobeTargetDefinitionError
from microprobe.model.memory import EndlessLoopDataMemoryModel
from microprobe.target import import_definition
from microprobe.utils.cmdline import print_error, print_info

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Benchmark size
BENCHMARK_SIZE = 8 * 1024

# Get the target definition
try:
    TARGET = import_definition("power_v206-power7-ppc64_linux_gcc")
except MicroprobeTargetDefinitionError as exc:
    print_error("Unable to import target definition")
    print_error("Exception message: %s" % str(exc))
    exit(-1)

BASE_ELEMENT = [element for element in TARGET.elements.values()
                if element.name == 'L1D'][0]
CACHE_HIERARCHY = TARGET.cache_hierarchy.get_data_hierarchy_from_element(
    BASE_ELEMENT)

PARALLEL = True


def main():
    """ Main program. """
    if PARALLEL:
        pool = mp.Pool(processes=mp.cpu_count())
        pool.map(generate, list(range(0, 100)), 1)
    else:
        list(map(generate, list(range(0, 100))))


def generate(name):
    """ Benchmark generation policy. """

    if os.path.isfile("%s/random-%s.c" % (DIRECTORY, name)):
        print_info("Skip %d" % name)
        return

    print_info("Generating %d..." % name)

    # Generate a random memory model (used afterwards)
    model = []
    total = 100
    for mcomp in CACHE_HIERARCHY[0:-1]:
        weight = random.randint(0, total)
        model.append(weight)
        print_info("%s: %d%%" % (mcomp, weight))
        total = total - weight

    # Fix remaining
    level = random.randint(0, len(CACHE_HIERARCHY[0:-1]) - 1)
    model[level] += total

    # Last level always zero
    model.append(0)

    # Sanity check
    psum = 0
    for elem in model:
        psum += elem
    assert psum == 100

    modelobj = EndlessLoopDataMemoryModel("random-%s", CACHE_HIERARCHY, model)

    # Get the loop wrapper. In this case we take the 'CInfPpc', which
    # generates an infinite loop in C using PowerPC embedded assembly.
    cwrapper = microprobe.code.get_wrapper("CInfPpc")

    # Define function to return random numbers (used afterwards)
    def rnd():
        """Return a random value. """
        return random.randrange(0, (1 << 64) - 1)

    # Create the benchmark synthesizer
    synth = microprobe.code.Synthesizer(TARGET, cwrapper())

    ##########################################################################
    # Add the passes we want to apply to synthesize benchmarks               #
    ##########################################################################

    # --> Init registers to random values
    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=rnd))

    # --> Add a single basic block of size size
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE))

    # --> Fill the basic block with instructions picked randomly from the list
    #     provided

    instructions = []
    for instr in TARGET.instructions.values():

        if instr.privileged:  # Skip privileged
            continue
        if instr.hypervisor:  # Skip hypervisor
            continue
        if instr.trap:  # Skip traps
            continue
        if instr.syscall:  # Skip syscall
            continue
        if "String" in instr.description:  # Skip unsupported string instr.
            continue
        if "Multiple" in instr.description:  # Skip unsupported mult. ld/sts
            continue
        if instr.category in [
                'LMA',
                'LMV',
                'DS',
                'EC',
                'WT']:  # Skip unsupported categories
            continue
        if instr.access_storage_with_update:  # Not supported by mem. model
            continue
        if instr.branch and not instr.branch_relative:  # Skip branches
            continue
        if "Reserve Indexed" in instr.description:  # Skip (illegal intr.)
            continue
        if "Conitional Indexed" in instr.description:  # Skip (illegal intr.)
            continue
        if instr.name in ['LD_V1', 'LWZ_V1', 'STW_V1', ]:
            continue

        instructions.append(instr)

    synth.add_pass(
        microprobe.passes.instruction.SetRandomInstructionTypePass(
            instructions
        )
    )

    # --> Set the memory operations parameters to fulfill the given model
    synth.add_pass(microprobe.passes.memory.GenericMemoryModelPass(modelobj))

    # --> Set target of branches to next instruction (first compute addresses)
    synth.add_pass(microprobe.passes.address.UpdateInstructionAddressesPass())
    synth.add_pass(microprobe.passes.branch.BranchNextPass())

    # --> Set the dependency distance and the default allocation. Dependency
    #     distance is randomly picked
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=random.randint(1, 20)
        )
    )

    # Generate the benchmark (applies the passes)
    # Since it is a randomly generated code, the generation might fail
    # (e.g. not enough access to fulfill the requested memory model, etc.)
    # Because of that, we handle the exception accordingly.
    try:
        print_info("Synthesizing %d..." % name)
        bench = synth.synthesize()
        print_info("Synthesized %d!" % name)
        # Save the benchmark
        synth.save("%s/random-%s" % (DIRECTORY, name), bench=bench)
    except MicroprobeError:
        print_info("Synthesizing error in '%s'. This is Ok." % name)

    return True


if __name__ == '__main__':
    # run main if executed from the command line
    # and the main method exists

    if len(sys.argv) != 2:
        print_info("Usage:")
        print_info("%s output_dir" % (sys.argv[0]))
        exit(-1)

    DIRECTORY = sys.argv[1]

    if not os.path.isdir(DIRECTORY):
        print_error("Output directory '%s' does not exists" % (DIRECTORY))
        exit(-1)

    if callable(locals().get('main')):
        main()

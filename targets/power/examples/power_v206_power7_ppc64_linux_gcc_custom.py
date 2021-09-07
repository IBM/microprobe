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
power_v206_power7_ppc64_linux_gcc_custom.py

Example python script to show how to generate random microbenchmarks.
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os
import sys

# Own modules
import microprobe.code
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.memory
import microprobe.passes.register
import microprobe.passes.structure
from microprobe.exceptions import MicroprobeTargetDefinitionError
from microprobe.model.memory import EndlessLoopDataMemoryModel
from microprobe.target import import_definition
from microprobe.utils.cmdline import print_error, print_info
from microprobe.utils.misc import RNDINT

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

if len(sys.argv) != 2:
    print_info("Usage:")
    print_info("%s output_dir" % (sys.argv[0]))
    exit(-1)

DIRECTORY = sys.argv[1]

if not os.path.isdir(DIRECTORY):
    print_info("Output DIRECTORY '%s' does not exists" % (DIRECTORY))
    exit(-1)

# Get the target definition
try:
    TARGET = import_definition("power_v206-power7-ppc64_linux_gcc")
except MicroprobeTargetDefinitionError as exc:
    print_error("Unable to import target definition")
    print_error("Exception message: %s" % str(exc))
    exit(-1)


###############################################################################
# Example 1: loop with instructions accessing storage , hitting the first     #
#            level of cache and with dependency distance of 3                 #
###############################################################################
def example_1():
    """ Example 1 """
    name = "L1-LOADS"

    base_element = [element for element in TARGET.elements.values()
                    if element.name == 'L1D'][0]
    cache_hierarchy = TARGET.cache_hierarchy.get_data_hierarchy_from_element(
        base_element)

    model = [0] * len(cache_hierarchy)
    model[0] = 100

    mmodel = EndlessLoopDataMemoryModel("random-%s", cache_hierarchy, model)

    profile = {}
    for instr_name in sorted(TARGET.instructions.keys()):
        instr = TARGET.instructions[instr_name]
        if not instr.access_storage:
            continue
        if instr.privileged:  # Skip privileged
            continue
        if instr.hypervisor:  # Skip hypervisor
            continue
        if "String" in instr.description:  # Skip unsupported string instr.
            continue
        if "ultiple" in instr.description:  # Skip unsupported mult. ld/sts
            continue
        if instr.category in [
                'DS',
                'LMA',
                'LMV',
                'EC']:  # Skip unsupported categories
            continue
        if instr.access_storage_with_update:  # Not supported
            continue

        if instr.name in ['LD_V1', 'LWZ_V1', 'STW_V1', ]:
            continue

        if (any([moper.is_load
                 for moper in instr.memory_operand_descriptors]) and
            all(
                [not moper.is_store
                 for moper in instr.memory_operand_descriptors])):
            profile[instr] = 1

    cwrapper = microprobe.code.get_wrapper("CInfPpc")
    synth = microprobe.code.Synthesizer(TARGET, cwrapper())

    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=RNDINT))
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE))
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeByProfilePass(profile)
    )
    synth.add_pass(microprobe.passes.memory.GenericMemoryModelPass(mmodel))
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=3))

    print_info("Generating %s..." % name)
    bench = synth.synthesize()
    print_info("%s Generated!" % name)
    synth.save("%s/%s" % (DIRECTORY, name), bench=bench)  # Save the benchmark


###############################################################################
# Example 2: loop with instructions using the MUL unit and with dependency    #
#            distance of 4                                                    #
###############################################################################
def example_2():
    """ Example 2 """
    name = "FXU-MUL"

    cwrapper = microprobe.code.get_wrapper("CInfPpc")
    synth = microprobe.code.Synthesizer(TARGET, cwrapper())

    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=RNDINT))
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE))
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeByElementPass(
            TARGET,
            [TARGET.elements['MUL_FXU0_Core0_SCM_Processor']],
            {}))
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=4))

    print_info("Generating %s..." % name)
    bench = synth.synthesize()
    print_info("%s Generated!" % name)
    synth.save("%s/%s" % (DIRECTORY, name), bench=bench)  # Save the benchmark


###############################################################################
# Example 3: loop with instructions using the ALU unit and with dependency    #
#            distance of 1                                                    #
###############################################################################
def example_3():
    """ Example 3 """
    name = "FXU-ALU"

    cwrapper = microprobe.code.get_wrapper("CInfPpc")
    synth = microprobe.code.Synthesizer(TARGET, cwrapper())

    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=RNDINT))
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE))
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeByElementPass(
            TARGET,
            [TARGET.elements['ALU_FXU0_Core0_SCM_Processor']],
            {}))
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=1))

    print_info("Generating %s..." % name)
    bench = synth.synthesize()
    print_info("%s Generated!" % name)
    synth.save("%s/%s" % (DIRECTORY, name), bench=bench)  # Save the benchmark


###############################################################################
# Example 4: loop with FMUL* instructions with different weights and with     #
#            dependency distance 10                                           #
###############################################################################
def example_4():
    """ Example 4 """
    name = "VSU-FMUL"

    profile = {}
    profile[TARGET.instructions['FMUL_V0']] = 4
    profile[TARGET.instructions['FMULS_V0']] = 3
    profile[TARGET.instructions['FMULx_V0']] = 2
    profile[TARGET.instructions['FMULSx_V0']] = 1

    cwrapper = microprobe.code.get_wrapper("CInfPpc")
    synth = microprobe.code.Synthesizer(TARGET, cwrapper())

    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=RNDINT))
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE))
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeByProfilePass(profile))
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=10))

    print_info("Generating %s..." % name)
    bench = synth.synthesize()
    print_info("%s Generated!" % name)
    synth.save("%s/%s" % (DIRECTORY, name), bench=bench)  # Save the benchmark


###############################################################################
# Example 5: loop with FADD* instructions with different weights and with     #
#            dependency distance 1                                            #
###############################################################################
def example_5():
    """ Example 5 """
    name = "VSU-FADD"

    profile = {}
    profile[TARGET.instructions['FADD_V0']] = 100
    profile[TARGET.instructions['FADDx_V0']] = 1
    profile[TARGET.instructions['FADDS_V0']] = 10
    profile[TARGET.instructions['FADDSx_V0']] = 1

    cwrapper = microprobe.code.get_wrapper("CInfPpc")
    synth = microprobe.code.Synthesizer(TARGET, cwrapper())

    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=RNDINT))
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE))
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeByProfilePass(profile))
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=1))

    print_info("Generating %s..." % name)
    bench = synth.synthesize()
    print_info("%s Generated!" % name)
    synth.save("%s/%s" % (DIRECTORY, name), bench=bench)  # Save the benchmark


###############################################################################
# Call the examples                                                           #
###############################################################################
example_1()
example_2()
example_3()
example_4()
example_5()
exit(0)

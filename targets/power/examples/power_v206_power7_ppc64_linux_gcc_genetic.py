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
power_v206_power7_ppc64_linux_gcc_genetic.py

Example python script to show how to generate a set of microbenchmark
stressing a particular unit but at different IPC ratio using a genetic
search algorithm to play with two knobs: average latency and dependency
distance.

An IPC evaluation and scoring script is required. For instance:

.. code:: bash

   #!/bin/bash
   # ARGS: $1 is the target IPC
   #       $2 is the name of the generate benchnark
   target_ipc=$1
   source_bench=$2

   # Compile the benchmark
   gcc -O0 -mcpu=power7 -mtune=power7 -std=c99 $source_bench.c -o $source_bench

   # Evaluate the ipc
   ipc=< your preferred commands to evaluate the IPC >

   # Compute the score (the closer to the target IPC the
   score=(1/($ipc-$target_ipc))^2 | bc -l

   echo $score

Use the script above as a template for your own GA-based search.
"""

# Futures
from __future__ import absolute_import, division

# Built-in modules
import datetime
import os
import sys
import time as runtime

# Third party modules
from six.moves import range

# Own modules
import microprobe.code
import microprobe.driver.genetic
import microprobe.passes.ilp
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.register
import microprobe.passes.structure
from microprobe.exceptions import MicroprobeTargetDefinitionError
from microprobe.target import import_definition
from microprobe.utils.cmdline import print_error, print_info, print_warning
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
BENCHMARK_SIZE = 20

# Get the target definition
try:
    TARGET = import_definition("power_v206-power7-ppc64_linux_gcc")
except MicroprobeTargetDefinitionError as exc:
    print_error("Unable to import target definition")
    print_error("Exception message: %s" % str(exc))
    exit(-1)


def main():
    """Main function."""

    component_list = ["FXU", "FXU-noLSU", "FXU-LSU", "VSU", "VSU-FXU"]
    ipcs = [float(x) / 10 for x in range(1, 41)]
    ipcs = ipcs[5:] + ipcs[:5]

    for name in component_list:
        for ipc in ipcs:
            generate_genetic(name, ipc)


def generate_genetic(compname, ipc):
    """Generate a microbenchmark stressing compname at the given ipc."""
    comps = []
    bcomps = []
    any_comp = False

    if compname.find("FXU") >= 0:
        comps.append(TARGET.elements["FXU0_Core0_SCM_Processor"])

    if compname.find("VSU") >= 0:
        comps.append(TARGET.elements["VSU0_Core0_SCM_Processor"])

    if len(comps) == 2:
        any_comp = True
    elif compname.find("noLSU") >= 0:
        bcomps.append(TARGET.elements["LSU0_Core0_SCM_Processor"])
    elif compname.find("LSU") >= 0:
        comps.append(TARGET.elements["LSU_Core0_SCM_Processor"])

    if (len(comps) == 1 and ipc > 2) or (len(comps) == 2 and ipc > 4):
        return True

    for elem in os.listdir(DIRECTORY):
        if not elem.endswith(".c"):
            continue
        if elem.startswith("%s:IPC:%.2f:DIST" % (compname, ipc)):
            print_info("Already generated: %s %d" % (compname, ipc))
            return True

    print_info("Going for IPC: %f and Element: %s" % (ipc, compname))

    def generate(name, *args):
        """Benchmark generation function.

        First argument is name, second the dependency distance and the
        third is the average instruction latency.
        """
        dist, latency = args

        wrapper = microprobe.code.get_wrapper("CInfPpc")
        synth = microprobe.code.Synthesizer(TARGET, wrapper())
        synth.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                value=RNDINT))
        synth.add_pass(
            microprobe.passes.structure.SimpleBuildingBlockPass(BENCHMARK_SIZE)
        )
        synth.add_pass(
            microprobe.passes.instruction.SetInstructionTypeByElementPass(
                TARGET,
                comps,
                {},
                block=bcomps,
                avelatency=latency,
                any_comp=any_comp))
        synth.add_pass(
            microprobe.passes.register.DefaultRegisterAllocationPass(
                dd=dist))
        bench = synth.synthesize()
        synth.save(name, bench=bench)

    # Set the genetic algorithm parameters
    ga_params = []
    ga_params.append((0, 20, 0.05))  # Average dependency distance design space
    ga_params.append((2, 8, 0.05))  # Average instruction latency design space

    # Set up the search driver
    driver = microprobe.driver.genetic.ExecCmdDriver(
        generate, 20, 30, 30, "'%s' %f " %
        (COMMAND, ipc), ga_params)

    starttime = runtime.time()
    print_info("Start search...")
    driver.run(1)
    print_info("Search end")
    endtime = runtime.time()

    print_info("Genetic time::%s" % (
        datetime.timedelta(seconds=endtime - starttime))
    )

    # Check if we found a solution
    ga_params = driver.solution()
    score = driver.score()

    print_info("IPC found: %f, score: %f" % (ipc, score))

    if score < 20:
        print_warning("Unable to find an optimal solution with IPC: %f:" % ipc)
        print_info("Generating the closest solution...")
        generate(
            "%s/%s:IPC:%.2f:DIST:%.2f:LAT:%.2f-check" %
            (DIRECTORY, compname, ipc, ga_params[0], ga_params[1]),
            ga_params[0], ga_params[1]
        )
        print_info("Closest solution generated")
    else:
        print_info(
            "Solution found for %s and IPC %f -> dist: %f , "
            "latency: %f " %
            (compname, ipc, ga_params[0], ga_params[1]))
        print_info("Generating solution...")
        generate("%s/%s:IPC:%.2f:DIST:%.2f:LAT:%.2f" %
                 (DIRECTORY, compname, ipc, ga_params[0], ga_params[1]),
                 ga_params[0], ga_params[1]
                 )
        print_info("Solution generated")
    return True


if __name__ == '__main__':
    # run main if executed from the COMMAND line
    # and the main method exists

    if len(sys.argv) != 3:
        print_info("Usage:")
        print_info("%s output_dir eval_cmd" % (sys.argv[0]))
        print_info("")
        print_info("Output dir: output directory for the generated benchmarks")
        print_info("eval_cmd: command accepting 2 parameters: the target IPC")
        print_info("          and the filename of the generate benchmark. ")
        print_info("          Output: the score used for the GA search. E.g.")
        print_info("          the close the IPC of the generated benchmark to")
        print_info("          the target IPC, the cmd should give a higher  ")
        print_info("          score. ")
        exit(-1)

    DIRECTORY = sys.argv[1]
    COMMAND = sys.argv[2]

    if not os.path.isdir(DIRECTORY):
        print_info("Output DIRECTORY '%s' does not exists" % (DIRECTORY))
        exit(-1)

    if not os.path.isfile(COMMAND):
        print_info("The COMMAND '%s' does not exists" % (COMMAND))
        exit(-1)

    if callable(locals().get('main')):
        main()

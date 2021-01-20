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
File: mp_epi

This script implements the tool that generates instruction-wise benchmarks
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import multiprocessing as mp
import os
import sys

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.code import get_wrapper
from microprobe.exceptions import MicroprobeException, MicroprobeValueError
from microprobe.target import import_definition
from microprobe.utils.cmdline import CLI, existing_dir, float_type, \
    int_type, new_file, parse_instruction_list, print_error, print_info
from microprobe.utils.logger import get_logger
from microprobe.utils.policy import find_policy


# Constants
LOG = get_logger(__name__)


# Functions
def _get_wrapper(name):
    try:
        return get_wrapper(name)
    except MicroprobeValueError as exc:
        raise MicroprobeException(
            "Wrapper '%s' not available. Check if you have the wrappers "
            "of the target installed or set up an appropriate "
            "MICROPROBEWRAPPERS environment variable. Original error was: %s" %
            (name, str(exc))
        )


def _generic_policy_wrapper(all_arguments):

    instruction, outputdir, outputname, target, kwargs, check = all_arguments

    bname = instruction.name
    bname = bname + "#DD_%d" % kwargs['dependency_distance']
    bname = bname + "#BS_%d" % kwargs['benchmark_size']
    bname = bname + "#DI_%s" % kwargs['data_init']

    if MICROPROBE_RC['debugwrapper']:
        policy = find_policy(target.name, 'debug')
    else:
        policy = find_policy(target.name, 'epi')

    extension = ""

    if target.name.endswith(
            "z64_mesa_st") or target.name.endswith("z64_mesa_smt2"):

        wrapper_name = "Avp"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset'],
        )
        extension = "avp"

    elif target.name.endswith("ppc64_mesa"):

        wrapper_name = "Tst"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            outputname.replace("%INSTR%", bname).replace("%EXT%",
                                                         "tst"),
            reset=kwargs['reset'],
        )
        extension = "tst"

    elif target.name.endswith("linux_gcc"):

        wrapper_name = "CInfGen"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset']
        )
        extension = "c"

    elif target.name.endswith("poe"):

        wrapper_name = "PoeSimple"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset'],
            endless=True
        )
        extension = "bin"

    elif target.name.endswith("cronus"):

        wrapper_name = "Cronus"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset'],
            endless=True
        )
        extension = "bin"

    elif target.name.endswith("test_p"):

        wrapper_name = "RiscvTestsP"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset'],
        )
        extension = "S"

    else:
        raise NotImplementedError(
            "Unsupported configuration '%s'" % target.name
        )

    if MICROPROBE_RC['debugwrapper']:
        extension = "s"

    extra_arguments = {}
    extra_arguments['instruction'] = instruction
    extra_arguments['benchmark_size'] = kwargs['benchmark_size']
    extra_arguments['dependency_distance'] = kwargs['dependency_distance']
    extra_arguments['data_init'] = kwargs['data_init']

    outputfile = os.path.join(outputdir, outputname)
    outputfile = outputfile.replace("%INSTR%", bname)
    outputfile = outputfile.replace("%EXT%", extension)

    if wrapper.outputname(outputfile) != outputfile:
        print_error(
            "Fix outputname to have a proper extension. E.g. '%s'" %
            wrapper.outputname(outputfile)
        )
        exit(-1)

    for prop in ["unsupported", "hypervisor", "privileged_optional",
                 "privileged", "syscall", "trap"]:
        if (hasattr(instruction, prop) and getattr(instruction, prop)
                and not kwargs['all']):
            print_info("%s not skip (reason: %s)!" % (instruction.name, prop))
            return False

    if kwargs['skip'] and os.path.isfile(outputfile):
        print_info("%s already generated!" % outputfile)
        return False

    outputfile = new_file(wrapper.outputname(outputfile), internal=True)
    synth = policy.apply(target, wrapper, **extra_arguments)

    if not kwargs["ignore_errors"]:
        print_info("Generating %s..." % outputfile)
        bench = synth.synthesize()
    else:

        if os.path.exists("%s.fail" % outputfile):
            print_error("%s failed before. Skip." % outputfile)
            return False
        elif check:
            return True

        try:
            print_info("Generating %s..." % outputfile)
            bench = synth.synthesize()
        except (MicroprobeException, AssertionError, AttributeError) as exc:

            with open("%s.fail" % outputfile, 'a'):
                os.utime("%s.fail" % outputfile, None)

            print_error("%s" % exc)
            print_error("Generation failed and ignore error flag set")
            return False

    synth.save(outputfile, bench=bench)
    print_info("%s generated!" % outputfile)

    return


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe epi tool",
        default_config_file="mp_epi.cfg",
        force_required=['target']
    )

    groupname = "EPI arguments"
    cmdline.add_group(
        groupname, "Command arguments related to EPI generation"
    )

    cmdline.add_option(
        "epi-output-file",
        "O",
        None,
        "Output file name",
        group=groupname,
        opt_type=new_file,
        required=False
    )

    cmdline.add_option(
        "epi-output-dir",
        "D",
        None,
        "Output directory name",
        group=groupname,
        opt_type=existing_dir,
        required=False
    )

    cmdline.add_option(
        "instructions",
        "ins",
        None,
        "Comma separated list of instructions to generate a benchmark with",
        group=groupname,
        opt_type=str,
        required=False
    )

    cmdline.add_option(
        "benchmark-size",
        "B",
        4096,
        "Size in instructions of the microbenchmark."
        " If more instruction are needed, nested loops are "
        "automatically generated",
        group=groupname,
        opt_type=int_type(1, 999999999999)
    )

    cmdline.add_option(
        "dependency-distance",
        "dd",
        0,
        "Average dependency distance between instructions. A value"
        " below 1 means not dependency between instructions. A value of "
        "1 means a chain of dependent instructions.",
        group=groupname,
        opt_type=float_type(0, 999999999999)
    )

    cmdline.add_option(
        "data-init",
        None,
        "random",
        "Data initialization values (memory and registers). It can be set"
        " to zero (all zeros) or to random. ",
        group=groupname,
        choices=["random", "zero"],
        opt_type=str
    )

    cmdline.add_flag(
        "reset",
        "R",
        "Reset the register contents on each loop iteration",
        group=groupname,
    )

    cmdline.add_flag(
        "all",
        "F",
        "Generate all instructions. By default only user "
        "level instructions are generated.",
        group=groupname,
    )

    cmdline.add_flag(
        "parallel",
        "p",
        "Generate benchmarks in parallel",
        group=groupname,
    )

    cmdline.add_flag(
        "skip",
        "s",
        "Skip benchmarks already generated",
        group=groupname,
    )

    cmdline.add_flag(
        "ignore-errors",
        "ie",
        "Ignore error during code generation (continue in case of "
        "an error in a particular parameter combination)",
        group=groupname,
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

    print_info("Checking input arguments for consistency...")

    if (
        "epi_output_file" not in arguments and
        "epi_output_dir" not in arguments
    ):
        print_error("No output provided")
        exit(-1)

    if (
        "epi_output_file" in arguments and
        "epi_output_dir" in arguments
    ):
        print_error("--epi-output-file and --epi-output-dir options conflict")
        print_error("Use one of them")
        exit(-1)

    if (
        "instructions" not in arguments and
        "epi_output_dir" not in arguments
    ):
        print_error("If --instructions is not provided, you need to provide")
        print_error("--epi-output-dir and not --epi-output-file")
        exit(-1)

    print_info("Importing target definition...")
    target = import_definition(arguments.pop('target'))

    policy = find_policy(target.name, 'epi')

    if 'all' not in arguments:
        arguments['all'] = False

    if policy is None:
        print_error("Target does not implement the default EPI policy")
        exit(-1)

    if 'instructions' not in arguments:
        arguments['instructions'] = list(target.isa.instructions.values())
        outputdir = arguments['epi_output_dir']
        outputname = "%INSTR%.%EXT%"

    else:

        arguments['instructions'] = parse_instruction_list(
            target, arguments['instructions']
        )

        arguments['all'] = True

        if ("epi_output_file" in arguments and
                len(arguments['instructions']) != 1):
            print_error("More than one microbenchmark to generate.")
            print_error("Use --epi-output-dir parameter")
            exit(-1)

        if "epi_output_file" in arguments:
            outputdir = os.path.dirname(arguments['epi_output_file'])
            outputname = arguments['epi_output_file']
        else:
            outputdir = arguments['epi_output_dir']
            outputname = "%INSTR%.%EXT%"

    if 'reset' not in arguments:
        arguments['reset'] = False

    if 'skip' not in arguments:
        arguments['skip'] = False

    if 'ignore_errors' not in arguments:
        arguments['ignore_errors'] = False

    if 'parallel' not in arguments:
        print_info("Start sequential generation. Use parallel flag to speed")
        print_info("up the benchmark generation.")
        for instruction in arguments['instructions']:
            _generic_policy_wrapper(
                (instruction,
                 outputdir,
                 outputname,
                 target,
                 arguments,
                 False))

    else:
        print_info("Start parallel generation. Threads: %s" % mp.cpu_count())
        pool = mp.Pool(processes=mp.cpu_count())
        args = [
            (instruction, outputdir, outputname, target, arguments, True)
            for instruction in arguments['instructions']
        ]
        regen = pool.map(_generic_policy_wrapper, args)
        args = [
            (instruction, outputdir, outputname, target, arguments, False)
            for instruction in arguments['instructions']
        ]
        args = [elem[0] for elem in zip(args, regen) if elem[1] is True]
        pool.map(_generic_policy_wrapper, args)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

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
File: mp_seqtune

This script implements the tool that to tune different parameters of the
input sequence provided, such as the memory access patterns, branch
behavior and replacement of instructions.
"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import itertools
import errno
import hashlib
import multiprocessing as mp
import os
import sys
import warnings

# Third party modules
from six.moves import range, zip

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.code import get_wrapper
from microprobe.exceptions import MicroprobeException, MicroprobeValueError
from microprobe.target import import_definition
from microprobe.utils.cmdline import CLI, existing_dir, float_type, \
    int_range, int_type, new_file, parse_instruction_list, \
    print_error, print_info, string_with_fields
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import iter_flatten, move_file
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

    configuration, outputdir, outputname, target, kwargs = all_arguments

    instructions, mem_switch, data_switch, switch_branch, branch_pattern, \
        replace_every, add_every, memory_streams, \
        benchmark_size = configuration

    extrapath = []
    extrapath.append("BS_%d" % benchmark_size)
    extrapath.append("MS_%d" % mem_switch)
    extrapath.append("DS_%d" % data_switch)
    extrapath.append("BP_%s" % branch_pattern)
    extrapath.append("SB_%d" % switch_branch)

    for repl in replace_every:
        extrapath.append("RE_%d_%s_%s" % (repl[2], repl[0].name, repl[1].name))

    for addl in add_every:
        extrapath.append("AE_%d_%s" % (addl[1],
                                       "_".join(
                                           [elem.name for elem in addl[0]]
        )
        )
        )

    for mems in memory_streams:
        extrapath.append(
            "ME_%d_%d_%d_%d_%d_%d_%d_%d" %
            (mems[0], mems[1], mems[2], mems[3],
             mems[4], mems[5], mems[6][0], mems[6][1])
        )

    outputfile = os.path.join(outputdir, "%DIRTREE%", outputname)
    outputfile = outputfile.replace(
        "%DIRTREE%", os.path.join(
            *([instr.name for instr in instructions] + extrapath)))

    if kwargs['shortnames']:
        outputfile = outputfile.replace(
            "%BASENAME%", "mp_seqtune_%s" % hashlib.sha1(
                "_".join(instr.name for instr in instructions).encode()
                ).hexdigest()[0:10] + "#" + "#".join(extrapath)
        )
    else:
        outputfile = outputfile.replace(
            "%BASENAME%", "_".join(
                instr.name for instr in instructions
            ) + "#" + "#".join(extrapath)
        )

    extension = ""
    if target.name.endswith("linux_gcc"):

        wrapper_name = "CInfGen"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset']
        )
        extension = "c"

    elif target.name.endswith("cronus"):

        wrapper_name = "Cronus"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset']
        )
        extension = "bin"

    elif target.name.endswith("mesa"):

        wrapper_name = "Tst"
        extension = "tst"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            os.path.basename(outputfile.replace("%EXT%", extension)),
            reset=kwargs['reset']
        )

    elif target.name.endswith("riscv64_test_p"):

        wrapper_name = "RiscvTestsP"
        extension = "S"
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            reset=kwargs['reset'],
            endless=True
        )

    elif target.environment.default_wrapper:

        wrapper_name = target.environment.default_wrapper
        wrapper_class = _get_wrapper(wrapper_name)
        wrapper = wrapper_class(
            endless=kwargs['endless'],
            reset=kwargs['reset']
        )

        outputfile = outputfile.replace(".%EXT%", "")
        outputfile = wrapper.outputname(outputfile)

    else:
        raise NotImplementedError(
            "Unsupported configuration '%s'" % target.name
        )

    if MICROPROBE_RC['debugwrapper']:
        extension = "s"

    outputfile = outputfile.replace("%EXT%", extension)

    if kwargs['skip']:
        if os.path.exists(outputfile):
            print_info("%s already exists!" % outputfile)
            return

        if kwargs["compress"] and os.path.exists("%s.gz" % outputfile):
            print_info("%s.gz already exists!" % outputfile)
            return

    if len(memory_streams) == 0:
        warnings.warn(
            "No memory streams provided "
            "using 1K stream stride 64 bytes"
        )
        memory_streams = [(1, 1024, 1, 64, 1)]

    streamid = 0
    new_memory_streams = []
    for stream in memory_streams:
        for elem in range(0, stream[0]):
            new_memory_streams.append([streamid] + list(stream)[1:])
            streamid += 1

    extra_arguments = {}
    extra_arguments['instructions'] = instructions
    extra_arguments['benchmark_size'] = benchmark_size
    extra_arguments['dependency_distance'] = kwargs['dependency_distance']
    extra_arguments['mem_switch'] = mem_switch
    extra_arguments['data_switch'] = data_switch
    extra_arguments['branch_pattern'] = branch_pattern
    extra_arguments['replace_every'] = replace_every
    extra_arguments['add_every'] = add_every
    extra_arguments['memory_streams'] = new_memory_streams
    extra_arguments['branch_switch'] = switch_branch

    if wrapper.outputname(outputfile) != outputfile:
        print_error(
            "Fix outputname to have a proper extension. E.g. '%s'" %
            wrapper.outputname(outputfile)
        )
        exit(-1)

    for instr in instructions:
        if instr.unsupported:
            print_info("%s not supported!" % instr.name)
            return

    policy = find_policy(target.name, 'seqtune')

    if not os.path.exists(os.path.dirname(outputfile)):
        os.makedirs(os.path.dirname(outputfile))

    outputfile = new_file(wrapper.outputname(outputfile), internal=True)

    print_info("Generating %s..." % outputfile)
    synth = policy.apply(target, wrapper, **extra_arguments)

    if not kwargs["ignore_errors"]:
        bench = synth.synthesize()
    else:

        if os.path.exists("%s.fail" % outputfile):
            print_error("%s failed before. Not generating" % outputfile)
            return

        try:
            bench = synth.synthesize()
        except Exception as exc:

            with open("%s.fail" % outputfile, 'a'):
                os.utime("%s.fail" % outputfile, None)

            print_error("%s" % exc)
            print_error("Generation failed for current configuration.")
            print_error("Generating next configurations.")
            return

    synth.save(outputfile, bench=bench)
    print_info("%s generated!" % outputfile)

    if kwargs['compress']:
        move_file(outputfile, "%s.gz" % outputfile)
        print_info("%s compressed to %s.gz" % (outputfile, outputfile))

    return


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe seqtune tool",
        default_config_file="mp_seqtune.cfg",
        force_required=['target']
    )

    groupname = "SEQTUNE arguments"
    cmdline.add_group(
        groupname, "Command arguments related to Sequence tuner generator"
    )

    cmdline.add_option(
        "seq-output-dir",
        "D",
        None,
        "Output directory name",
        group=groupname,
        opt_type=existing_dir,
        required=True
    )

    cmdline.add_option(
        "sequence",
        "seq",
        None,
        "Base instruction sequence to modify (command separated list of "
        "instructions). If multiple sequences are provided (separated by"
        " a space) they are combined (product).",
        group=groupname,
        opt_type=str,
        required=True,
        nargs="+"
    )

    cmdline.add_option(
        "repeat",
        "r",
        1,
        "If multiple sequences are provided in --sequence, this parameter"
        " specifies how many of them are concated to generate the final "
        "sequence.",
        group=groupname,
        opt_type=int_type(1, 999999999999),
    )

    cmdline.add_option(
        "replace-every",
        "re",
        None,
        "Replace every. String with the format 'INSTR1:INSTR2:RANGE' to "
        "specfy that INSTR1 will be replaced by INSTR2 every RANGE "
        "instructions. Range can be just an integer or a RANGE specifier of "
        "the form: #1:#2 to generate a range from #1 to #2, or #1:#2:#3 to "
        "generate a range between #1 to #2 with step #3. E.g. 10:20 generates "
        "10, 11, 12 ... 19, 20 and 10:20:2 generates 10, 12, 14, ... 18, 20.",
        group=groupname,
        opt_type=string_with_fields(":", 3, 3,
                                    [str, str, int_range(1, 10000)]),
        required=False,
        action="append"
    )

    cmdline.add_option(
        "add-every",
        "ae",
        None,
        "Add every. String with the format 'INSTR1:RANGE' to "
        "specfy that INSTR1 will be added to the sequence every RANGE "
        "instructions. Range can be just an integer or a RANGE specifier of "
        "the form: #1-#2 to generate a range from #1 to #2, or #1-#2-#3 to "
        "generate a range between #1 to #2 with step #3. E.g. 10:20 generates "
        "10, 11, 12 ... 19, 20 and 10:20:2 generates 10, 12, 14, ... 18, 20.",
        group=groupname,
        opt_type=string_with_fields(":", 2, 2,
                                    [str, int_range(1, 10000)]),
        required=False,
        action="append"
    )

    cmdline.add_option(
        "branch-every",
        "be",
        None,
        "Conditional branches are modeled not taken by default. Using this "
        "paratemeter, every N will be taken.",
        group=groupname,
        opt_type=int_range(1, 10000),
        required=False,
        action="append"
    )

    cmdline.add_option(
        "branch-pattern",
        "bp",
        None,
        "Branch pattern (in binary) to be generated. E.g 0010 will model the "
        "conditional branches as NotTaken NotTaken Taken NotTaken in a round "
        "robin fashion. One can use 'L<range>' to generate all the patterns "
        "possible of length #. E.g. 'L2-5' will generate all unique possible "
        "branch patterns of length 2,3,4 and 5.",
        group=groupname,
        opt_type=str,
        required=False,
        action="append")

    cmdline.add_flag(
        "data-switch",
        "ds",
        "Enable data switching for instruction. It tries to maximize the "
        "data switching factor on inputs and outputs of instructions.",
        group=groupname,
    )

    cmdline.add_flag(
        "switch-branch",
        "sb",
        "Switch branch pattern in each iteration.",
        group=groupname,
    )

    cmdline.add_flag(
        "memory-switch",
        "ms",
        "Enable data switching for memory operations. It tries to maximize the"
        " data switching factor on loads and store operations.",
        group=groupname,
    )

    cmdline.add_option(
        "memory-stream",
        "me",
        None,
        "Memory stream definition. String with the format "
        "NUM:SIZE:WEIGHT:STRIDE:REGS:RND:LOC1:LOC2 where NUM is the number "
        "of streams of "
        "this type, SIZE is the working set size of the stream in bytes, "
        "WEIGHT is the probability of the stream. E.g. streams with the same"
        "weight will have same probability to be generated. "
        "STRIDE is the stride access patern between the elements of the "
        "stream and REGS is the number of register sets (address base + "
        "address index) to be used for each stream. "
        "RND controls the randomess of the generated memory access "
        "stream. -1 is full randomness, 0 is not randomness, and any "
        "value above 0 control the randomness range. E.g. a value of "
        "1024 randomizes the accesses within 1024 bytes memory ranges."
        "LOC1 and LOC2 control the temporal locality of the memory access "
        "stream in the following way: the last LOC1 accesses are going "
        "to be accessed again LOC2 times before moving forward to the "
        "next addresses. If LOC2 is 0 not temporal locality is generated "
        "besides the implicit one from the memory access stream definition. "
        "All the elements of "
        "this format stream can be just a number or a range specfication "
        "(start-end) or (start-end-step). This flag can be specified "
        "multiple times",
        group=groupname,
        opt_type=string_with_fields(":", 8, 8,
                                    [int_range(1, 100),
                                     int_range(1, 2**32),
                                     int_range(1, 10000),
                                     int_range(1, 2**32),
                                     int_range(1, 10),
                                     int_range(-1, 2**32),
                                     int_range(1, 2**32),
                                     int_range(0, 2**32),
                                     ]
                                    ),
        required=False,
        action="append"
    )

    cmdline.add_option(
        "benchmark-size",
        "B",
        [4096],
        "Size in instructions of the microbenchmark main loop.",
        group=groupname,
        opt_type=int_range(1, 999999999999),
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

    cmdline.add_flag(
        "reset",
        "R",
        "Reset the register contents on each loop iteration",
        group=groupname,
    )

    cmdline.add_flag(
        "endless",
        "e",
        "Some backends allow the control to wrap the sequence generated in an"
        " endless loop. Depending on the target specified, this flag will "
        "force to generate sequences in an endless loop (some targets "
        " might ignore it)",
        group=groupname,
    )

    cmdline.add_flag(
        "parallel",
        "p",
        "Generate benchmarks in parallel",
        group=groupname,
    )

    cmdline.add_option(
        "batch-number",
        "bn",
        1,
        "Batch number to generate. Check --num-batches option for more "
        "details",
        group=groupname,
        opt_type=int_type(1, 10000)
    )

    cmdline.add_option(
        "num-batches",
        "nb",
        1,
        "Number of batches. The number of microbenchmark to generate "
        "is divided by this number, and the number the batch number "
        "specified using -bn option is generated. This is useful to "
        "split the generation of many test cases in various batches.",
        group=groupname,
        opt_type=int_type(1, 10000)
    )

    cmdline.add_flag(
        "skip",
        "s",
        "Skip benchmarks already generated",
        group=groupname,
    )

    cmdline.add_flag(
        "shortnames",
        "sn",
        "Use short output names",
        group=groupname,
    )

    cmdline.add_flag(
        "compress",
        "CC",
        "Compress output files",
        group=groupname,
    )

    cmdline.add_flag(
        "count",
        "N",
        "Only count the number of sequence to generate. Do not generate "
        "anything",
        group=groupname,
    )

    cmdline.add_option(
        "max-memory",
        "Mm",
        999999999999,
        "Maximum memory for all the streams generated",
        group=groupname,
        opt_type=int_type(0, 999999999999)
    )

    cmdline.add_option(
        "min-memory",
        "mm",
        0,
        "Minimum memory for all the streams generated",
        group=groupname,
        opt_type=int_type(0, 999999999999)
    )

    cmdline.add_option(
        "max-regsets",
        "Mr",
        999999999999,
        "Maximum number of regsets for all the streams generated",
        group=groupname,
        opt_type=int_type(1, 999999999999)
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


def _generate_configurations(arguments):

    for relem in itertools.product(
            arguments["sequences"],
            repeat=arguments["repeat"]
            ):

        relem = list(itertools.chain.from_iterable(relem))
        bconfig = []
        bconfig.append(relem)
        bconfig.append(arguments["memory_switch"])
        bconfig.append(arguments["data_switch"])
        bconfig.append(arguments["switch_branch"])

        for pattern in arguments['branch_pattern']:
            cconfig = bconfig[:]
            cconfig.append(pattern)

            rmap = []
            rcomb = []
            for elem in arguments['replace_every']:
                rmap.append((elem[0][0], elem[1][0]))
                rcomb.append(elem[2])

            for relem in itertools.product(*rcomb):
                rconfig = cconfig[:]
                rconfig.append(list(zip((elem[0] for elem in rmap),
                                        (elem[1] for elem in rmap),
                                        relem)))

                for value in _generate_add_every(rconfig, arguments):
                    for size in arguments['benchmark_size']:
                        yield value + [size]


def _generate_add_every(rconfig, arguments):
    bconfig = rconfig[:]

    rmap = []
    rcomb = []
    for elem in arguments['add_every']:
        rmap.append(elem[0])
        rcomb.append(elem[1])

    for relem in itertools.product(*rcomb):
        cconfig = bconfig[:]
        cconfig.append(list(zip(rmap, relem)))

        for value in _generate_mem_streams(
                bconfig + [list(zip(rmap, relem))], arguments):
            yield value


def _generate_mem_streams(rconfig, arguments):
    bconfig = rconfig[:]

    rcomb = []

    for elem in arguments['memory_stream']:
        rcomb.append(
            [
                [val[0], val[1], val[2], val[3],
                 val[4], val[5], (val[6], val[7])]
                for val in
                itertools.product(*elem)
            ]
        )

    for relem in itertools.product(*rcomb):

        cconfig = bconfig[:]
        cconfig.append(list(relem))
        yield cconfig


def _process_branch_pattern(patterns):

    rpattern = []
    for pattern in patterns:
        if pattern.replace("0", "").replace("1", "") == "":
            rpattern.append(pattern)
        elif pattern.startswith("L"):
            pattern_lengths = int_range(1, 100)(pattern[1:])
            for pattern_length in pattern_lengths:
                strfmt = "0%db" % pattern_length
                rpattern += [format(elem, strfmt)
                             for elem in range(0, 2**pattern_length)]
        else:
            print_error("Wrong format for branch pattern '%s'." % pattern)
            exit(-1)

    rpattern = sorted(
        list(set(rpattern)),
        key=lambda x: len(x)  # pylint: disable=unnecessary-lambda
    )
    numbers = set([len(elem) for elem in rpattern])
    cmul = 1
    for num in numbers:
        cmul = cmul * num

    for idx, elem in enumerate(rpattern):
        rpattern[idx] = [elem, len(elem), elem * (cmul // len(elem))]

    rlist = []
    llist = []
    for elem in rpattern:
        if elem[2] in llist:
            continue
        rlist.append(elem[0])
        llist.append(elem[2])

    return rlist


def _process_branch_every(every_list):
    rlist = []
    for every in iter_flatten(every_list):
        rlist.append("0" * (every - 1) + "1")
    return rlist


def _filter_configurations(configurations, arguments):

    maxmem = arguments["max_memory"]
    maxregs = arguments["max_regsets"]
    minmem = arguments["min_memory"]

    fconfigs = []

    for config in configurations:

        memory = sum([elem[0] * elem[1] for elem in config[7]])

        if memory > maxmem:
            continue

        if memory < minmem:
            continue

        regs = sum([elem[0] * elem[4] for elem in config[7]])

        if regs > maxregs:
            continue

        fconfigs.append(config)

    return fconfigs


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    print_info("Arguments processed!")

    print_info("Checking input arguments for consistency...")

    flags = ["data_switch", "memory_switch",
             "ignore_errors", "switch_branch"]

    for flag in flags:
        if flag not in arguments:
            arguments[flag] = False

    args = ["replace_every", "add_every", "branch_every", "branch_pattern",
            "memory_stream"]
    for arg in args:
        if arg not in arguments:
            arguments[arg] = []

    if (len(arguments['branch_every']) >
            0 and len(arguments['branch_pattern']) > 0):
        print_error("--branch-every and --branch-pattern flags are "
                    "mutually exclusive. Use only on of them.")
        exit(-1)
    elif len(arguments['branch_pattern']) > 0:
        arguments['branch_pattern'] = _process_branch_pattern(
            arguments['branch_pattern']
        )
    elif len(arguments['branch_every']) > 0:
        arguments['branch_pattern'] = _process_branch_every(
            arguments['branch_every']
        )
    else:
        arguments['branch_pattern'] = ['0']

    if arguments["num_batches"] < arguments["batch_number"]:
        print_error(
            "Batch number should be within the number of batches specified"
        )
        exit(-1)

    print_info("Importing target definition...")
    target = import_definition(arguments.pop('target'))

    policy = find_policy(target.name, 'seqtune')

    if policy is None:
        print_error("Target does not implement the default SEQTUNE policy")
        exit(-1)

    arguments['sequences'] = [
        parse_instruction_list(target, elem) for elem in arguments['sequence']
    ]

    for elem in arguments["replace_every"]:
        elem[0] = parse_instruction_list(target, elem[0])
        elem[1] = parse_instruction_list(target, elem[1])

    for elem in arguments["add_every"]:
        elem[0] = parse_instruction_list(target, elem[0])

    configurations = _generate_configurations(arguments)
    configurations = _filter_configurations(configurations, arguments)

    if 'count' in arguments:
        print_info("Total number of variations defined : %s" %
                   len(list(configurations)))
        exit(0)

    outputdir = arguments['seq_output_dir']
    outputname = "%BASENAME%.%EXT%"

    if 'reset' not in arguments:
        arguments['reset'] = False

    if 'skip' not in arguments:
        arguments['skip'] = False

    if 'compress' not in arguments:
        arguments['compress'] = False

    if 'endless' not in arguments:
        arguments['endless'] = False

    if 'shortnames' not in arguments:
        arguments['shortnames'] = False

    # process batches
    print_info("Num configurations difined: %d" % len(configurations))
    print_info("Number of batches: %d " % arguments["num_batches"])
    print_info("Batch number: %d " % arguments["batch_number"])

    size = len(configurations) // arguments["num_batches"]
    size = size + 1

    configurations = configurations[
        (arguments["batch_number"] - 1) * size:
        arguments["batch_number"] * size
    ]

    if 'parallel' not in arguments:
        print_info("Start sequential generation. Use parallel flag to speed")
        print_info("up the benchmark generation.")
        for params in configurations:
            _generic_policy_wrapper(
                (params,
                 outputdir,
                 outputname,
                 target,
                 arguments))

    else:
        print_info("Start parallel generation. Threads: %s" % mp.cpu_count())
        pool = mp.Pool(processes=mp.cpu_count())
        pool.map(_generic_policy_wrapper,
                 [(params, outputdir, outputname, target,
                   arguments)
                  for params in configurations]
                 )


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

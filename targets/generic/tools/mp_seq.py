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
File: mp_seq

This script implements the tool that generates a variety of sequences from
the input isntructions provided
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import argparse
import itertools
import multiprocessing as mp
import os
import sys

# Third party modules
from six.moves import range

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.code import get_wrapper
from microprobe.exceptions import MicroprobeException, MicroprobeValueError
from microprobe.target import import_definition
from microprobe.utils.cmdline import CLI, existing_dir, float_type, \
    int_type, new_file, parse_instruction_list, print_error, print_info
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import findfiles, iter_flatten
from microprobe.utils.policy import find_policy


# Constants
LOG = get_logger(__name__)
_DIRCONTENTS = []
_BALANCE_EXECUTION = False


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

    instructions, outputdir, outputname, target, kwargs = all_arguments

    outputfile = os.path.join(outputdir, "%DIRTREE%", outputname)
    outputfile = outputfile.replace(
        "%DIRTREE%", os.path.join(
            *[instr.name for instr in instructions]))
    outputfile = outputfile.replace(
        "%INSTR%", "_".join(
            instr.name for instr in instructions))

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

    else:
        raise NotImplementedError(
            "Unsupported configuration '%s'" % target.name
        )

    if MICROPROBE_RC['debugwrapper']:
        extension = "s"

    outputfile = outputfile.replace("%EXT%", extension)

    if kwargs['skip'] and outputfile in _DIRCONTENTS:
        print_info("%s already exists!" % outputfile)
        return

    if kwargs['skip'] and os.path.isfile(outputfile):
        print_info("%s already exists!" % outputfile)
        return

    extra_arguments = {}
    extra_arguments['instructions'] = instructions
    extra_arguments['benchmark_size'] = kwargs['benchmark_size']
    extra_arguments['dependency_distance'] = kwargs['dependency_distance']
    extra_arguments['force_switch'] = kwargs['force_switch']

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

    policy = find_policy(target.name, 'seq')

    if not os.path.exists(os.path.dirname(outputfile)):
        os.makedirs(os.path.dirname(outputfile))

    outputfile = new_file(wrapper.outputname(outputfile), internal=True)

    print_info("Generating %s..." % outputfile)
    synth = policy.apply(target, wrapper, **extra_arguments)
    bench = synth.synthesize()
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
        "Microprobe seq tool",
        default_config_file="mp_seq.cfg",
        force_required=['target']
    )

    groupname = "SEQ arguments"
    cmdline.add_group(
        groupname, "Command arguments related to Sequence generation"
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
        "instruction-slots",
        "is",
        4,
        "Number of instructions slots in the sequence. E.g. '-l 4' will "
        "generate sequences of length 4.",
        group=groupname,
        opt_type=int_type(1, 999999999999)
    )

    cmdline.add_option(
        "instruction-groups",
        "ig",
        None,
        "Comma separated list of instruction candidates per group. E.g. "
        "-ins ins1,ins2 ins3,ins4. Defines two groups of instruction "
        "candidates: group 1: ins1,ins2 and group 2: ins3,ins4.",
        group=groupname,
        opt_type=str,
        action="append",
        nargs="+"
    )

    cmdline.add_option(
        "instruction-map",
        "im",
        None,
        "Comma separated list specifying groups instruction candidate groups "
        "to be used on each instruction slot. The list length should match "
        "the number of instruction slots defined.  A -1 value means all groups"
        " can be used for that slot. E.g. -im 1 2,3 will generate sequences "
        "containing in slot 1 instructions from group 1, and in slot 2 "
        "instructions from groups 2 and 3.",
        group=groupname,
        opt_type=str,
        required=False,
        action="append",
        nargs="+"
    )

    cmdline.add_option(
        "base-seq",
        "bs",
        None,
        "Comma separated list specifying the base instruction sequence",
        group=groupname,
        opt_type=str,
        required=False,
    )

    cmdline.add_option(
        "group-max",
        "gM",
        None,
        "Comma separated list specifying the maximum number of instructions "
        " of each group to be used. E.g. -gM 1,3 will generate sequences "
        "containing at most 1 instruction of group 1 and 3 instructions of "
        "group 2. A -1 value means no maximum. The list length should match "
        "the number of instruction groups defined.",
        group=groupname,
        opt_type=str,
        required=False,
        action="append",
        nargs="+"
    )

    cmdline.add_option(
        "group-min",
        "gm",
        None,
        "Comma separated list specifying the minimum number of instructions "
        " of each group to be used. E.g. -gm 1,3 will generate sequences "
        "containing at least 1 instruction of group 1 and 3 instructions of "
        "group 2. A -1 value means no minimum. The list length should match "
        "the number of instruction groups defined.",
        group=groupname,
        opt_type=str,
        required=False,
        action="append",
        nargs="+"
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

    cmdline.add_flag(
        "force-switch",
        "fs",
        "Force data switching in all instructions, fail if not supported.",
        group=groupname,
    )

    cmdline.add_flag(
        "reset",
        "R",
        "Reset the register contents on each loop iteration",
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
        "count",
        "N",
        "Only count the number of sequence to generate. Do not generate "
        "anything",
        group=groupname,
    )

    print_info("Processing input arguments...")
    cmdline.main(args, _main)


def _generate_sequences(
        slots,
        instruction_groups,
        instruction_map,
        group_max,
        group_min,
        base_seq):

    instr_names = []
    instr_objs = []
    print_info("")
    print_info("Groups defined:")
    for idx, igroup in enumerate(instruction_groups):
        print_info("\tGroup %d:\t Instructions: %s" %
                   ((idx + 1), ",".join([instr.name for instr in igroup])))
        for instr in igroup:
            instr_names.append(instr.name + "_GRP%05d" % (idx + 1))
            if instr not in instr_objs:
                instr_objs.append(instr)

    slot_dsrc = []
    for elem in range(0, slots):
        allowed_groups = instruction_map[elem]
        allowed_instructions = []
        for group in allowed_groups:
            allowed_instructions += [iname for iname in instr_names
                                     if iname.endswith("_GRP%05d" % group)]

        descriptor = [
            ['%d' % group for group in allowed_groups], allowed_instructions]

        slot_dsrc.append(descriptor)

    print_info("")
    print_info("Sequence definition:")
    print_info("\tSequence Length: %s" % slots)
    for idx, slot in enumerate(slot_dsrc):
        print_info("\t\tSlot %s:\tAllowed groups: %s"
                   "\tAllowed instructions: %s" % (idx + 1, ",".join(slot[0]),
                                                   ",".join(slot[1])))

    print_info("\tGroup constraints per sequence:")
    for idx, igroup in enumerate(instruction_groups):
        print_info("\t\tGroup %s:\tMin instr: %d\tMax intr: %d" %
                   (idx + 1, group_min[idx], group_max[idx]))
    print_info("")

    for seq in itertools.product(*[descr[1] for descr in slot_dsrc]):
        valid = True
        for idx, igroup in enumerate(instruction_groups):
            count = len([instr for instr in seq
                         if instr.endswith("_GRP%05d" % (idx + 1))])

            if count < group_min[idx]:
                valid = False
                break

            if count > group_max[idx]:
                valid = False
                break

        if valid:
            sequence = []
            for instrname in seq:
                for idx in range(0, len(instruction_groups)):
                    instrname = instrname.replace("_GRP%05d" % (idx + 1), "")
                sequence += [instr_obj for instr_obj in instr_objs
                             if instr_obj.name == instrname]
            yield base_seq + sequence


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    print_info("Arguments processed!")

    print_info("Checking input arguments for consistency...")

    slots = arguments['instruction_slots']

    instruction_groups = list(
        iter_flatten(arguments.get('instruction_groups', []))
    )
    check_group_length_func = int_type(1, len(instruction_groups))
    check_slots_length_func = int_type(0, slots)

    instruction_map = arguments.get('instruction_map', None)
    if instruction_map is None:
        instruction_map = ['-1'] * slots
    else:
        instruction_map = list(iter_flatten(instruction_map))

    if len(instruction_map) != slots:
        print_error('Instruction map: %s' % instruction_map)
        print_error(
            'Instruction map incorrect. Length should be: %s' %
            slots)
        exit(-1)

    new_map = []
    for gmap in instruction_map:
        ngmap = []

        if gmap == "-1":
            ngmap = list(range(1, len(instruction_groups) + 1))
            new_map.append(ngmap)
            continue

        for cmap in gmap.split(','):
            try:
                ngmap.append(check_group_length_func(cmap))
            except argparse.ArgumentTypeError as exc:
                print_error('Instruction map incorrect')
                print_error(exc)
                exit(-1)
        new_map.append(ngmap)

    instruction_map = new_map

    group_max = arguments.get('group_max', None)
    if group_max is None:
        group_max = ['-1'] * len(instruction_groups)
    else:
        group_max = list(iter_flatten(group_max))

    if len(group_max) != len(instruction_groups):
        print_error('Group max: %s' % group_max)
        print_error(
            'Group max incorrect. Length should be: %s' %
            len(instruction_groups))
        exit(-1)

    new_map = []
    for gmap in group_max:

        if gmap == "-1":
            new_map.append(slots)
            continue

        try:
            new_map.append(check_slots_length_func(gmap))
        except argparse.ArgumentTypeError as exc:
            print_error('Group max incorrect')
            print_error(exc)
            exit(-1)

    group_max = new_map

    group_min = arguments.get('group_min', None)
    if group_min is None:
        group_min = ['-1'] * len(instruction_groups)
    else:
        group_min = list(iter_flatten(group_min))

    if len(group_min) != len(instruction_groups):
        print_error('Group min: %s' % group_min)
        print_error(
            'Group min incorrect. Length should be: %s' %
            len(instruction_groups))
        exit(-1)

    new_map = []
    for gmap in group_min:

        if gmap == "-1":
            new_map.append(0)
            continue

        try:
            new_map.append(check_slots_length_func(gmap))
        except argparse.ArgumentTypeError as exc:
            print_error('Group min incorrect')
            print_error(exc)
            exit(-1)

    group_min = new_map

    print_info("Importing target definition...")
    target = import_definition(arguments.pop('target'))

    policy = find_policy(target.name, 'seq')

    if policy is None:
        print_error("Target does not implement the default SEQ policy")
        exit(-1)

    instruction_groups = [
        parse_instruction_list(target, group) for group in instruction_groups
    ]

    base_seq = []
    if 'base_seq' in arguments:
        base_seq = parse_instruction_list(target, arguments['base_seq'])

    sequences = [base_seq]
    if len(instruction_groups) > 0:
        sequences = _generate_sequences(slots,
                                        instruction_groups,
                                        instruction_map,
                                        group_max,
                                        group_min,
                                        base_seq)

    if 'count' in arguments:
        print_info("Total number of sequences defined : %s" %
                   len(list(sequences)))
        exit(0)

    outputdir = arguments['seq_output_dir']

    if _BALANCE_EXECUTION:
        global _DIRCONTENTS  # pylint: disable=global-statement
        _DIRCONTENTS = set(findfiles([outputdir], ""))

    outputname = "%INSTR%.%EXT%"

    if 'reset' not in arguments:
        arguments['reset'] = False

    if 'skip' not in arguments:
        arguments['skip'] = False

    if 'force_switch' not in arguments:
        arguments['force_switch'] = False

    if 'parallel' not in arguments:
        print_info("Start sequential generation. Use parallel flag to speed")
        print_info("up the benchmark generation.")
        for sequence in sequences:
            _generic_policy_wrapper(
                (sequence,
                 outputdir,
                 outputname,
                 target,
                 arguments))

    else:
        print_info("Start parallel generation. Threads: %s" % mp.cpu_count())
        pool = mp.Pool(processes=mp.cpu_count())
        pool.map(_generic_policy_wrapper,
                 [(sequence, outputdir, outputname, target,
                   arguments)
                  for sequence in sequences]
                 )


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

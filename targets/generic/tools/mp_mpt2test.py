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
File: mp_mpt2test

This script implements the tool that converts mpt files Test code.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import sys

# Own modules
import microprobe
import microprobe.code
from microprobe.code.address import InstructionAddress
from microprobe.code.ins import instruction_to_definition
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
from microprobe.utils.bin import interpret_bin
from microprobe.utils.cmdline import new_file_ext, print_info, print_warning
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)


# Functions
def generate(test_definition, outputfile, language, target, **kwargs):
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

    if 'raw_bin' in kwargs:
        print_info("Interpreting RAW dump...")

        sequence = []
        raw_dict = {}
        current_address = 0

        for entry in test_definition.code:
            if (not entry.assembly.upper().startswith("0X") and
                    not entry.assembly.upper().startswith("0B")):
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "assembly (%s)" % entry.assembly
                )

            if entry.label is not None:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "labels (%s)" % entry.label
                )

            if entry.decorators not in ['', ' ', None, []]:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "decorators (%s)" % entry.decorators
                )

            if entry.comments not in ['', ' ', None, []]:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "comments (%s)" % entry.comments
                )

            if entry.address is not None:
                current_address = entry.address

            if current_address not in raw_dict:
                raw_dict[current_address] = ""

            # Assume that raw dump use a 4 bytes hex dump
            if len(entry.assembly) != 10:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW 4-byte dump as it contains "
                    "lines with other formats (%s)" % entry.assembly
                )

            raw_dict[current_address] += entry.assembly[2:]

        if len(raw_dict) > 1:
            address_ant = sorted(raw_dict.keys())[0]
            len_ant = len(raw_dict[address_ant])//2

            # Assume that raw dump use a 4 bytes hex dump
            assert len_ant % 4 == 0

            for address in sorted(raw_dict.keys())[1:]:
                if address_ant + len_ant == address:
                    raw_dict[address_ant] += raw_dict[address]
                    len_ant = len(raw_dict[address_ant])//2
                    raw_dict.pop(address)
                else:
                    len_ant = len(raw_dict[address])//2
                    address_ant = address

                # Assume that raw dump use a 4 bytes hex dump
                assert len_ant % 4 == 0

        sequence = []
        for address in sorted(raw_dict.keys()):

            # Endianess will be big endian, because we are concatenating
            # full words resulting in the higher bits being encoded first

            code = interpret_bin(
                raw_dict[address], target, safe=True, little_endian=False,
                word_length=4
            )
            code[0].address = address + test_definition.default_code_address
            for i in range(1, len(code)):
                assert code[i-1].get_instruction_type().format.length > 0
                code[i].address = code[i-1].address + code[i-1].get_instruction_type().format.length
            sequence.extend(code)

    else:
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

    if test_definition.default_data_address is not None:
        print_warning("Default data address not needed")

    wrapper_kwargs = {}

    if language == "c":
        if kwargs.get("wrap_function", False):
            raise MicroprobeException("The wrap-function option is incompatible with the C langauge backend.")

        wrapper_name = "C"
        if kwargs.get("endless", False):
            print_warning("Using endless c wrapper")
            wrapper_name = "CInfGen"
    elif language == "asm":
        wrapper_name = "Assembly"
        if sequence[0].label is not None:
            start_label = sequence[0].label
        else:
            start_label = sequence[0].label = "START_TEST"

        wrapper_kwargs["sections"] = [addr + test_definition.default_code_address for addr in raw_dict.keys()]
        wrapper_kwargs["start_label"] = start_label

        reset_instructions = []

        if kwargs.get("wrap_function", False):
            print("Adding function wrapping instructions...")
            instructions = target.function_call("0x%x" % test_definition.default_code_address)
            instructions[0].set_label("LOOP_START")

            for instr in instructions:
                reset_instructions.append(instruction_to_definition(instr))
        else:
            print("Adding jump to test instructions...")
            source_address = InstructionAddress(
                base_address="dummy", # Rely on symbolic jump
                displacement=0
            )

            target_address = InstructionAddress(
                base_address=start_label,
                displacement=0
            )

            instr = target.branch_unconditional_relative(
                    source_address,
                    target_address
            )

            instr.set_label("LOOP_START")

            reset_instructions.append(instruction_to_definition(instr))

        if kwargs.get("endless", False):
            source_address = InstructionAddress(
                base_address="dummy", # Rely on symbolic jump
                displacement=0
            )

            target_address = InstructionAddress(
                base_address="LOOP_START",
                displacement=0
            )

            instr = target.branch_unconditional_relative(
                    source_address,
                    target_address
            )

            instr = instruction_to_definition(instr)

            if kwargs.get("wrap_function", False):
                print("Adding loop instruction after function wrapper")
                reset_instructions.append(instr)
            else:
                print("Adding loop instruction after test")
                sequence.append(instr)

        sequence = reset_instructions + sequence

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

    if kwargs.get("fix_indirect_branches", False):
        print_info("Fix indirect branches: On")
        synth.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass())
        synth.add_pass(microprobe.passes.branch.FixIndirectBranchPass())

    if kwargs.get("fix_branch_next", False):
        print_info("Force branch to next: On")
        synth.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass())
        synth.add_pass(microprobe.passes.branch.BranchNextPass(
            force=True))

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
        "MicroprobeTest (mpt) to test tool",
        mpt_options=True,
        default_config_file="mp_mpt2test.cfg",
        force_required=['target']
    )

    groupname = "MPT to test arguments"
    cmdline.add_group(
        groupname,
        "Command arguments related to MPT to test tool"
    )

    cmdline.add_option(
        "output-file",
        "O",
        None,
        "Output file name",
        group=groupname,
        opt_type=new_file_ext([".s", ".c"]),
        required=True
    )

    cmdline.add_option(
        "language",
        "l",
        "c",
        "Test language"
    )

    cmdline.add_flag(
        "safe-bin", None, "Ignore unrecognized binary codifications (do not"
                          "fail). Useful when MPTs are generated by dumping "
                          "directly code "
                          "pages, which contain padding zeros and other "
                          "non-code stuff)",
        groupname,
    )
    cmdline.add_flag(
        "raw-bin", None, "Process all instruction entries together. They "
                         "all shoud be binary entries. Implies --safe-bin "
                         "flag. Useful when MPTs are generated by dumping "
                         "directly code "
                         "pages, which contain padding zeros and other "
                         "non-code stuff)",
        groupname,
    )
    cmdline.add_flag(
        "endless", None, "Wrap the code generated within an endless loop",
        groupname
    )
    cmdline.add_flag(
        "wrap-function", None, "Wrap the code generated as a function instead of a regular branch",
        groupname
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

    print_info("Processing input arguments...")
    cmdline.main(args, _main)


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    print_info("Arguments processed!")

    if 'raw-bin' in arguments:
        arguments['safe-bin'] = True

    if 'safe-bin' in arguments:
        microprobe.MICROPROBE_RC['safe_bin'] = True

    print_info("Importing target definition...")
    target = import_definition(arguments.pop('target'))
    test_definition = arguments.pop('mpt_definition')
    outputfile = arguments.pop('output_file')
    language = arguments.pop('language')

    print_info("Start generating '%s'" % outputfile)
    generate(test_definition, outputfile, language, target, **arguments)
    print_info("'%s' generated!" % outputfile)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)
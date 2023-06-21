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
"""File: mp_mpt2elf.

This script implements the tool that converts mpt files to ELF
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import os.path
import sys

# Third party modules
import six

# Own modules
import microprobe.code
import microprobe.passes.address
import microprobe.passes.branch
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.memory
import microprobe.passes.register
import microprobe.passes.structure
import microprobe.passes.symbol
import microprobe.passes.variable
import microprobe.utils.cmdline
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.context import Context
from microprobe.code.ins import (
    instruction_from_definition,
    instruction_to_definition,
)
from microprobe.exceptions import (
    MicroprobeCodeGenerationError,
    MicroprobeException,
    MicroprobeMPTFormatError,
    MicroprobeValueError,
    MicroprobeRunCmdError,
)
from microprobe.target import import_definition
from microprobe.passes.instruction import SetInstructionOperandsByOpcodePass
from microprobe.utils.asm import (
    MicroprobeAsmInstructionDefinition,
    interpret_asm,
    instruction_to_asm_definition,
)
from microprobe.utils.bin import interpret_bin
from microprobe.utils.cmdline import (
    float_type,
    int_type,
    new_file_ext,
    print_error,
    print_info,
    print_warning,
    string_with_fields,
)
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Progress, twocs_to_int, findfiles
from microprobe.utils.mpt import MicroprobeTestRegisterDefinition
from microprobe.utils.run import run_cmd


__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
LOG = get_logger(__name__)
_FIX_ADDRESS_TOLERANCE = 64 * 1024


# Functions
def generate(test_definition, output_file, target, **kwargs):
    """
    Microbenchmark generation policy.

    :param test_definition: Test definition object
    :type test_definition: :class:`MicroprobeTestDefinition`
    :param output_file: Output file name
    :type output_file: :class:`str`
    :param target: Target definition object
    :type target: :class:`Target`
    """
    end_address_orig = None
    overhead = 0

    if len(test_definition.dat_mappings) > 0:
        #
        # Assuming MPT generated from MAMBO full system
        #
        dat = target.get_dat(dat_map=test_definition.dat_mappings)
        dat.control["DAT"] = True

        for instr in test_definition.code:
            instr.address = dat.translate(instr.address, rev=True)

        # Address order might have changed after mapping
        test_definition.set_instruction_definitions(
            sorted(test_definition.code, key=lambda x: x.address)
        )

        # remove not translated addresses (needed?)
        # variables = [var for var in test_definition.variables
        #             if var.address != dat.translate(var.address, rev=True)]
        # test_definition.set_variables_definition(variables)

        for var in test_definition.variables:
            var.address = dat.translate(var.address, rev=True)

        # Address order might have changed after mapping
        test_definition.set_variables_definition(
            sorted(test_definition.variables, key=lambda x: x.address)
        )

        if test_definition.default_code_address != 0:
            test_definition.default_code_address = dat.translate(
                test_definition.default_code_address, rev=True
            )
        if test_definition.default_data_address != 0:
            test_definition.default_data_address = dat.translate(
                test_definition.default_data_address, rev=True
            )
        for access in test_definition.roi_memory_access_trace:
            access.address = dat.translate(access.address, rev=True)

    if "raw_bin" in kwargs:
        print_info("Interpreting RAW dump...")

        sequence = []
        raw_dict = {}
        current_address = 0

        # Assume state file provides the initial code address
        displ = test_definition.default_code_address
        test_definition.set_default_code_address(0)

        executed_code = []
        align = 32
        for access in test_definition.roi_memory_access_trace:
            if access.data_type == "D":
                continue

            if ((access.address // align) * align) not in executed_code:
                executed_code.append((access.address // align) * align)

        for entry in test_definition.code:
            if not entry.assembly.upper().startswith(
                "0X"
            ) and not entry.assembly.upper().startswith("0B"):
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "assembly (%s)" % entry.assembly
                )

            if entry.label is not None:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "labels (%s)" % entry.label
                )

            if entry.decorators not in ["", " ", None, []]:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "decorators (%s)" % entry.decorators
                )

            if entry.comments not in ["", " ", None, []]:
                raise MicroprobeMPTFormatError(
                    "This is not a RAW dump as it contains "
                    "comments (%s)" % entry.comments
                )

            if entry.address is not None:
                current_address = entry.address + displ

            if (
                len(executed_code) > 0
                and ((current_address // align) * align) not in executed_code
            ):
                continue

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
            len_ant = len(raw_dict[address_ant]) // 2

            # Assume that raw dump use a 4 bytes hex dump
            assert len_ant % 4 == 0

            for address in sorted(raw_dict.keys())[1:]:
                if address_ant + len_ant == address:
                    raw_dict[address_ant] += raw_dict[address]
                    len_ant = len(raw_dict[address_ant]) // 2
                    raw_dict.pop(address)
                else:
                    len_ant = len(raw_dict[address]) // 2
                    address_ant = address

                # Assume that raw dump use a 4 bytes hex dump
                assert len_ant % 4 == 0

        sequence = []
        for address in sorted(raw_dict.keys()):
            # Endianess will be big endian, because we are concatenating
            # full words resulting in the higher bits being encoded first

            code = interpret_bin(
                raw_dict[address],
                target,
                safe=True,
                little_endian=False,
                word_length=4,
            )

            for instr in code:
                instr.address = address
                instr = instruction_from_definition(instr)
                address = address + instr.architecture_type.format.length
                instr = instruction_to_asm_definition(instr)
                sequence.append(instr)

        test_definition.set_instruction_definitions(sequence)

    reset_steps = []

    if "no_wrap_test" not in kwargs:
        if test_definition.default_code_address != 0:
            print_error("Default code address should be zero")
            exit(-1)

        print_info("Wrapping function...")
        start_symbol = "START_TEST"

        init_address = test_definition.default_code_address
        for register in test_definition.registers:
            if register.name == "PC":
                init_address = register.value
            if register.name == "PSW_ADDR":
                init_address = register.value

        if kwargs["fix_32bit_address"]:
            base = kwargs["fix_32bit_address"]
            print_info("Shifting addresses to belong to 32bit address space.")

            elements_outside_range = []
            for conj in [test_definition.code, test_definition.variables]:
                for elem in conj:
                    if elem.address is not None and elem.address >= 2**32:
                        elements_outside_range.append(elem)

            elements_outside_range = sorted(
                elements_outside_range, key=lambda el: el.address
            )

            print(len(elements_outside_range))

            print_info("Generating new mapping...")

            mapping = {}
            prev_mapped_address = None
            prev_address = None
            for elem in elements_outside_range:
                if prev_address is None:
                    next_address = base
                else:
                    offset = elem.address - prev_address
                    if offset <= 256 * 4096:  # Respect offsets of nearby
                        # pages to respect non-consecutive
                        # and pc-relative page accesses
                        next_address = prev_mapped_address + offset
                    else:
                        next_address = (prev_mapped_address & ~0xFFF) + 0x1000

                mapping[elem.address] = next_address

                prev_mapped_address = next_address
                prev_address = elem.address

            print_info(
                "Address of last section: 0x%X "
                % (mapping[elements_outside_range[-1].address])
            )
            print_info("Shifting %d elements " % (len(mapping)))

            for elem in test_definition.code:
                if elem.address in mapping:
                    elem.address = mapping[elem.address]

            prog = Progress(len(test_definition.variables))

            for elem in test_definition.variables:
                if elem.address in mapping:
                    elem.address = mapping[elem.address]

                for index in range(0, elem.num_elements, 8):
                    value = int.from_bytes(
                        elem.init_value[index: index + 8], "little"
                    )
                    page_addr = value & ~0xFFF
                    if page_addr in mapping:
                        new_value = mapping[page_addr] + (value & 0xFFF)
                        bytes_ = int.to_bytes(new_value, 8, "little")
                        for i, byte in enumerate(bytes_):
                            elem.init_value[index + i] = byte
                    elif value in mapping:
                        new_value = mapping[value]
                        bytes_ = int.to_bytes(new_value, 8, "little")
                        for i, byte in enumerate(bytes_):
                            elem.init_value[index + i] = byte

                prog()

            for register in test_definition.registers:
                if register.value >= 2**32:
                    if register.value in mapping:
                        register.value = mapping[register.value]
                    elif register.value & ~0xFFF in mapping:
                        register.value = mapping[register.value & ~0xFFF] + (
                            register.value & 0xFFF
                        )
                    else:
                        print_warning(
                            "Register %s's value is more than 32 bits but "
                            "is not in mapping: %X"
                            % (register.name, register.value)
                        )
                        closest_addr = None
                        closest_dist = 8 * 1024  # Only consider mappings
                        # 16kb apart
                        for map_addr in mapping:
                            dist = register.value - map_addr
                            if abs(dist) < abs(closest_dist):
                                closest_addr = map_addr
                                closest_dist = dist
                        if closest_addr is not None:
                            print_warning(
                                "  Closest mapped address: %X (distance: %d "
                                "bytes). Applying shift. Final address: %X"
                                % (
                                    closest_addr,
                                    closest_dist,
                                    mapping[closest_addr] + closest_dist,
                                )
                            )
                            register.value = (
                                mapping[closest_addr] + closest_dist
                            )

            for access in test_definition.roi_memory_access_trace:
                if access.address in mapping:
                    access.address = mapping[access.address]
                else:
                    page_addr = access.address & ~0xFFF
                    if page_addr in mapping:
                        access.address = mapping[page_addr] + (
                            access.address & 0xFFF
                        )
                    elif page_addr > 2**32:
                        print_warning(
                            "Access is more than 32 bits but is "
                            "not in mapping: %x" % access.address
                        )

        displacements = []
        for elem in test_definition.code:
            if elem.address is not None:
                if len(displacements) == 0:
                    displacements.append(
                        (elem.address, 4 * 1024, elem.address - init_address)
                    )
                else:
                    displacements.append(
                        (
                            elem.address,
                            elem.address - displacements[-1][0],
                            elem.address - init_address,
                        )
                    )

        # Get ranges with enough space to put init code
        # Assuming 4K space is enough
        displacements = [
            displ
            for displ in displacements
            if displ[1] >= 4 * 1024 and displ[2] <= 0
        ]

        if len(displacements) == 0:
            print_error(
                "Unable to find space for the initialization code. "
                "Check the mpt initial code address or state of PC "
                "for correctness."
            )
            exit(-1)

        displ_fixed = False
        if kwargs["fix_start_address"]:
            displacement = kwargs["fix_start_address"]
            print_info("Start point set to 0x%X" % displacement)
            displ_fixed = True
        elif "fix_long_jump" in kwargs:
            displacement = sorted(displacements, key=lambda x: x[0])[0][0]
            if displacement > 2**32:
                displacement = 0x1000000
                print_info("Start point set to 0x%X" % displacement)
                displ_fixed = True
        else:
            displacement = sorted(displacements, key=lambda x: x[2])[-1][0]

        start_symbol = None
        init_found = False
        for instr in test_definition.code:
            if instr.address == init_address:
                if instr.label is None:
                    instr.label = "START_TEST"
                start_symbol = instr.label
                init_found = True
                break

        if not init_found:
            print_error(
                "Initial instruction address (%s) not found. This can "
                "be related to wrong MPT format or decoding missmatch "
                "during raw bin interpretation." % hex(init_address)
            )
            exit(-1)

        if start_symbol is None:
            if test_definition.code[0].label is None:
                test_definition.code[0].label = "START_TEST"
            start_symbol = test_definition.code[0].label

        if displacement is None:
            displacement = 0

        instructions = []
        reset_steps = []

        if "wrap_endless" in kwargs and "reset" in kwargs:
            target.scratch_var.set_address(
                Address(base_address=target.scratch_var.name)
            )

            new_ins, overhead, reset_steps = _compute_reset_code(
                target,
                test_definition,
                kwargs,
            )
            instructions += new_ins

        instructions += target.hook_before_test_instructions()

        if "fix_long_jump" in kwargs:
            instructions += target.function_call(init_address, long_jump=True)
        else:
            instructions += target.function_call(
                ("%s" % start_symbol).replace("+0x-", "-0x"),
            )

        instructions += target.hook_after_test_instructions()

        if "wrap_endless" in kwargs:
            instructions += target.hook_after_reset_instructions()  # TODO fix
            instructions += _compute_reset_jump(target, instructions)

        instructions += target.hook_test_end_instructions()

        instructions_definitions = []
        for instruction in instructions:
            instruction.set_label(None)

            if not displ_fixed:
                displacement = (
                    displacement - instruction.architecture_type.format.length
                )

            current_instruction = MicroprobeAsmInstructionDefinition(
                instruction.assembly(),
                None,
                None,
                None,
                instruction.comments,
            )
            instructions_definitions.append(current_instruction)

        instruction = target.nop()
        instruction.set_label(None)

        if not displ_fixed:
            displacement = (
                displacement - instruction.architecture_type.format.length
            )

        # To avoid overlaps
        if not displ_fixed:
            align = 0x100
            displacement = ((displacement // align) + 0) * align

        instructions_definitions[0].address = displacement
        assert instructions_definitions[0].address is not None

        # instr = MicroprobeAsmInstructionDefinition(
        #     instruction.assembly(), "ELF_ABI_EXIT", None, None, None)

        # end_address_orig = \
        #    (test_definition.default_code_address + displacement_end -
        #    instruction.architecture_type.format.length)

        instructions_definitions[0].label = "mpt2elf_endless"

        test_definition.register_instruction_definitions(
            instructions_definitions,
            prepend=True,
        )

        assert test_definition.code[0].address is not None

        if not displ_fixed:
            test_definition.set_default_code_address(
                test_definition.default_code_address + displacement,
            )

            for elem in test_definition.code:
                if elem.address is not None:
                    elem.address = elem.address - displacement

        else:
            test_definition.set_default_code_address(displacement)
            for elem in test_definition.code:
                if elem.address is not None:
                    elem.address = elem.address - displacement

    variables = test_definition.variables
    variables = [
        var
        for var in test_definition.variables
        if var.address is None or var.address >= 0x00100000
    ]

    test_definition.set_variables_definition(variables)

    print_info("Interpreting asm ...")

    sequence_orig = interpret_asm(
        test_definition.code,
        target,
        [var.name for var in variables] + [target.scratch_var.name],
        show_progress=True,
    )

    if len(sequence_orig) < 1:
        raise MicroprobeMPTFormatError(
            "No instructions found in the 'instructions' entry of the MPT"
            " file. Check the input file.",
        )

    raw = test_definition.raw
    raw["FILE_FOOTER"] = (
        "# mp_mpt2elf: Wrapping overhead: %03.2f %%" % overhead
    )

    # end_address = end_address_orig
    ckwargs = {
        # 'end_address': end_address,
        # 'reset': False,
        # 'endless': 'endless' in kwargs
    }

    wrapper_name = "AsmLd"

    if test_definition.default_data_address is not None:
        ckwargs["init_data_address"] = test_definition.default_data_address

    if test_definition.default_code_address is not None:
        ckwargs["init_code_address"] = test_definition.default_code_address

    try:
        code_wrapper = microprobe.code.get_wrapper(wrapper_name)
    except MicroprobeValueError as exc:
        raise MicroprobeException(
            "Wrapper '%s' not available. Check if you have the wrappers"
            " of the target installed or set up an appropriate "
            "MICROPROBEWRAPPERS environment variable. Original error "
            "was: %s" % (wrapper_name, str(exc)),
        )

    wrapper = code_wrapper(**ckwargs)

    print_info("Setup synthesizer ...")
    synthesizer = microprobe.code.Synthesizer(
        target,
        wrapper,
        no_scratch=True,
        extra_raw=raw,
    )

    variables = test_definition.variables
    registers = test_definition.registers
    sequence = sequence_orig

    synthesizer.add_pass(
        microprobe.passes.initialization.AddInitializationInstructionsPass(
            target.hook_test_init_instructions()
        ),
    )

    if len(registers) >= 0:
        cr_reg = [register for register in registers if register.name == "CR"]

        registers = [
            register for register in registers if register.name != "CR"
        ]

        if cr_reg:
            value = cr_reg[0].value
            for idx in range(0, 8):
                cr = MicroprobeTestRegisterDefinition(
                    "CR%d" % idx,
                    (value >> (28 - (idx * 4))) & 0xF,
                )
                registers.append(cr)

        synthesizer.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                registers,
                skip_unknown=True,
                warn_unknown=True,
                skip_control=True,
                force_reserved=True,
            ),
        )

    synthesizer.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(
            len(sequence),
        ),
    )

    synthesizer.add_pass(
        microprobe.passes.variable.DeclareVariablesPass(
            variables,
        ),
    )

    synthesizer.add_pass(
        microprobe.passes.instruction.ReproduceSequencePass(sequence),
    )

    if target.name.startswith("power"):
        fix_branches = [
            instr.name
            for instr in target.instructions.values()
            if instr.branch_conditional
        ]

        if "raw_bin" in kwargs:
            # We do not know what is code and what is data, so we safely
            # disable the asm generation and keep the values
            for orig in [21, 17, 19]:
                synthesizer.add_pass(
                    microprobe.passes.instruction.DisableAsmByOpcodePass(
                        fix_branches, 0, ifval=orig
                    )
                )
        else:
            # We know what is code and what is data, so we can safely
            # fix the branch instructions
            for new, orig in [(20, 21), (16, 17), (18, 19)]:
                synthesizer.add_pass(
                    SetInstructionOperandsByOpcodePass(
                        fix_branches, 0, new, force=True, ifval=orig
                    )
                )

    if kwargs.get("fix_memory_registers", False):
        kwargs["fix_memory_references"] = True

    if kwargs.get("fix_memory_references", False):
        print_info("Fix memory references: On")

        synthesizer.add_pass(
            microprobe.passes.memory.FixMemoryReferencesPass(
                reset_registers=kwargs.get("fix_memory_registers", False),
            ),
        )

        synthesizer.add_pass(
            microprobe.passes.register.FixRegistersPass(
                forbid_writes=["GPR3"],
            ),
        )

    if kwargs.get("fix_memory_registers", False):
        print_info("Fix memory registers: On")
        synthesizer.add_pass(
            microprobe.passes.register.NoHazardsAllocationPass(),
        )

    if kwargs.get("fix_branch_next", False):
        print_info("Force branch to next: On")
        synthesizer.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass(
                force="fix_flatten_code" in kwargs, noinit=True
            )
        )
        synthesizer.add_pass(
            microprobe.passes.branch.BranchNextPass(force=True),
        )

    if kwargs.get("fix_indirect_branches", False):
        print_info("Fix indirect branches: On")
        synthesizer.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass(
                noinit=True
            ),
        )
        synthesizer.add_pass(
            microprobe.passes.branch.FixIndirectBranchPass(),
        )

    if displ_fixed:
        synthesizer.add_pass(
            microprobe.passes.address.SetInitAddressPass(displacement)
        )

    synthesizer.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass(
            noinit=True,
            init_from_first=not displ_fixed,
        ),
    )

    synthesizer.add_pass(
        microprobe.passes.variable.UpdateVariableAddressesPass(),
    )

    synthesizer.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass(onlyraw=True),
    )

    print_info("Start synthesizer ...")
    bench = synthesizer.synthesize()

    # Save the microbenchmark
    synthesizer.save(output_file, bench=bench)

    print_info("'%s' generated!" % output_file)

    _compile(output_file, target, **kwargs)

    return


def _compile(filename, target, **kwargs):
    if "compiler" not in kwargs:
        print_info("Compiler not provided")
        print_info("To compiler the code, first extract the custom")
        print_info("ld script embedded in the assembly as comments to do")
        print_info("so execute:")
        print_info("grep 'MICROPROBE LD' %s | cut -d '@' -f 2" % filename)
        print_info("then compile using gcc and providing the ld script")
        print_info("using the -T option.")
        return

    print_info("Compiling %s ..." % filename)

    outputname = ".".join(filename.split(".")[:-1] + ["elf"])
    ldscriptname = ".".join(filename.split(".")[:-1] + ["ldscript"])

    fdout = open(ldscriptname, "w")
    fdin = open(filename, "r")
    for line in fdin.readlines():
        if "MICROPROBE LD" in line:
            line = line.split("@")[1]
            fdout.write(line)
    fdout.close()
    fdin.close()

    try:
        baseldscriptname = findfiles(
            MICROPROBE_RC["template_paths"], "%s.ldscript" % target.name
        )[0]
    except IndexError:
        print_error(
            "Unable to find template ld script: %s.ldscript" % target.name
        )
        exit(-1)

    routines_name = None

    try:
        routines_name = findfiles(
            MICROPROBE_RC["template_paths"], "%s_routines.s" % target.name
        )[0]
    except IndexError:
        pass

    cprog = kwargs["compiler"]

    cflags = " -o %s" % outputname
    cflags += " -T %s" % ldscriptname
    cflags += " -T %s " % baseldscriptname
    cflags += kwargs["compiler_flags"]
    # We only support BFD linker
    cflags += " -fuse-ld=bfd "

    if routines_name is not None:
        cflags += " " + routines_name

    cmd = "%s %s %s" % (cprog, cflags, filename)

    print_info("Executing compilation command")
    print_info("%s" % cmd)
    try:
        run_cmd(cmd)
        print_info("'%s' generated!" % outputname)
    except MicroprobeRunCmdError:
        cflags += " -static"
        cmd = "%s %s %s" % (cprog, cflags, filename)
        print_info("Executing compilation command (statically)")
        print_info("%s" % cmd)
        try:
            run_cmd(cmd)
            print_info("'%s' generated!" % outputname)
        except MicroprobeRunCmdError:
            print_info(
                "'%s' not generated due compilation"
                " issues. Try manual compilation." % outputname
            )


def _compute_reset_code(target, test_def, args):
    instructions = interpret_asm(
        test_def.code,
        target,
        [var.name for var in test_def.variables],
        show_progress=True,
    )

    # TODO: This can be done in parallel or look for speed up the process
    instructions = [
        instruction_from_definition(instr) for instr in instructions
    ]

    instruction_dict = {}
    address = test_def.default_code_address
    progress = Progress(
        len(test_def.roi_memory_access_trace),
        msg="Building instruction dictionary",
    )
    for instr in instructions:
        progress()
        if instr.address is not None:
            if instr.address.base_address == "code":
                address = (
                    test_def.default_code_address + instr.address.displacement
                )
                instr.set_address(address)
        else:
            address = address + instr.architecture_type.format.length
            instr.set_address(address)
        instruction_dict[instr.address] = instr

    free_regs = []
    written_after_read_regs = []
    read_regs = []
    level = 0
    dynamic_count = 0
    progress = Progress(
        len(test_def.roi_memory_access_trace),
        msg="Evaluating register usage",
    )
    reset_regs = set()
    for access in test_def.roi_memory_access_trace:
        progress()

        if access.data_type == "D":
            continue

        dynamic_count += 1
        try:
            instr = instruction_dict[access.address]
            uses = instruction_dict[access.address].uses()
            sets = instruction_dict[access.address].sets()

        except KeyError:
            print_error(
                "Access to from instruction at address "
                "0x%016X registered but such instruction is not"
                " present in the definition." % access.address,
            )
            exit(1)

        # POWER Calls
        if instr.mnemonic == "BL":
            level += 1
        elif instr.mnemonic == "BCL":
            level += 1
        elif instr.mnemonic == "BCCTRL":
            if instr.operands()[2].value in [0, 3]:
                level += 1

        # POWER Returns
        if instr.mnemonic == "BCLR":
            if ((instr.operands()[0].value & 0b10100) == 20) and (
                instr.operands()[2].value == 0
            ):
                level -= 1

        # Z Calls
        if instr.mnemonic == "BRASL":
            if instr.operands()[0].value == target.registers["GR14"]:
                level += 1
        if instr.mnemonic == "BASR":
            if instr.operands()[0].value == target.registers["GR14"]:
                level += 1

        # Z Returns
        if instr.mnemonic == "BCR":
            if (instr.operands()[1].value == target.registers["GR14"]) and (
                instr.operands()[0].value == 15
            ):
                level -= 1

        # TODO: this should include RISCV instructions for call
        # and return, but currently we do not have memory access traces
        # for such platforms

        for reg in uses:
            if reg not in read_regs:
                read_regs.append(reg)

        for reg in sets:
            if reg in free_regs:
                continue
            elif reg not in read_regs:
                free_regs.append(reg)
            elif reg not in written_after_read_regs:
                written_after_read_regs.append(reg)

        reset_regs = set(read_regs).intersection(
            set(written_after_read_regs),
        )

    reset_regs = sorted(reset_regs)

    assert len(free_regs) == len(set(free_regs))
    assert len(set(free_regs).intersection(set(reset_regs))) == 0

    if len(test_def.roi_memory_access_trace) == 0:
        # We do not have memory access trace, assume calling conventions
        reset_regs = target.volatile_registers

    reset_regs = [
        reg for reg in reset_regs if reg in target.volatile_registers
    ]

    if len(reset_regs) == 0 and len(test_def.roi_memory_access_trace) == 0:
        print_info(
            "No memory access trace found. Resetting volatile registers."
        )
        reset_regs = target.volatile_registers

    unused_regs = sorted(
        (reg for reg in target.registers.values() if reg not in read_regs),
    )

    #
    # Make sure scratch registers are reset last
    #
    for reg in target.scratch_registers:
        if reg in reset_regs:
            reset_regs.remove(reg)
            reset_regs.append(reg)

    free_regs = unused_regs + free_regs

    # Know which ones are not used (or written) and which ones are used
    # Use them as base / temporal registers for addresses

    # Check addresses
    conflict_addresses = {}
    new_ins = []
    progress = Progress(
        len(test_def.roi_memory_access_trace),
        msg="Evaluating memory usage",
    )
    for access in test_def.roi_memory_access_trace:
        progress()
        if access.data_type == "I":
            continue
        val = conflict_addresses.get(
            access.address,
            [access.length, access.access_type],
        )
        if access.access_type not in val[1]:
            val[1] += access.access_type
        val[0] = max(val[0], access.length)
        conflict_addresses[access.address] = val

    fix_addresses = []
    for address in conflict_addresses:
        value = conflict_addresses[address]
        if value[1] == "RW":
            wvalue = None
            for var in test_def.variables:
                if var.var_type.upper() in ["CHAR", "UINT8_T"]:
                    elem_size = 1
                else:
                    raise NotImplementedError
                end_address = var.address + var.num_elements * elem_size
                if var.address <= address < end_address:
                    offset = int((address - var.address) / elem_size)
                    svalue = var.init_value[
                        offset:offset + int(value[0] / elem_size)
                    ]
                    svalue = "".join(
                        reversed(["%02X" % tval for tval in svalue])
                    )  # TODO: Reverse ONLY on little endian archs
                    wvalue = int(svalue, 16)
                    break

            if wvalue is None:
                print_error(
                    "Unable to restore original value for address 0x%X"
                    % address,
                )
                exit(1)

            if value[0] <= 8:
                fix_addresses.append((address, value[0], wvalue))
            else:
                for selem in range(0, value[0] // 8):
                    sfmt = "%%0%dX" % (2 * value[0])
                    nvalue = sfmt % wvalue
                    nvalue = int(nvalue[selem * 16:(selem + 1) * 16], 16)
                    fix_addresses.append((address + selem * 8, 8, nvalue))

    reset_steps = []

    context = Context()
    context.set_symbolic(True)

    if len(fix_addresses) > 0:
        # TODO: This can be optimized. Reduce the number of instructions to
        # be added by sorting the reset code (shared values or similar
        # addresses)
        # TODO: This can be optimized for use vector registers when
        # needed
        #
        print_info("Adding instructions to reset memory state")
        reset_registers = [
            reg
            for reg in free_regs
            if reg.type.used_for_address_arithmetic and reg.name != "GPR0"
        ]

        if len(reset_registers) == 0:
            print_error(
                "No free register available for resetting memory"
                " contentents."
            )
            exit(1)

        reset_register = reset_registers[0]
        zero_register = None

        if len(reset_registers) > 1:
            # Set a register to zero, which is always useful for
            # address computation
            zero_register = reset_registers[1]
            new_instructions = target.set_register(
                zero_register,
                0,
                context,
                opt=False,
            )
            for ins in new_instructions:
                ins.add_comment(
                    "Reset code. Setting %s to 0X%016X"
                    % (zero_register.name, 0),
                )
            reset_steps.append([new_instructions[:], zero_register, 0])
            context.set_register_value(zero_register, 0)
            new_ins.extend(new_instructions)

        for address, length, value in fix_addresses:
            address_obj = Address(base_address="data", displacement=address)
            new_instructions = target.set_register(
                reset_register,
                value,
                context,
                opt=False,
            )

            for ins in new_instructions:
                ins.add_comment(
                    "Reset code. Setting %s to 0X%016X"
                    % (reset_register.name, value),
                )

            reset_steps.append([new_instructions[:], reset_register, value])
            context.set_register_value(reset_register, value)

            try:
                store_ins = target.store_integer(
                    reset_register,
                    address_obj,
                    length * 8,
                    context,
                )
                new_instructions += store_ins
                reset_steps.append(
                    [store_ins, reset_register, address_obj, length],
                )

            except MicroprobeCodeGenerationError:
                areg = [
                    reg
                    for reg in free_regs
                    if reg.type.used_for_address_arithmetic
                    and reg.name != "GPR0"
                    and reg != reset_register
                    and reg != zero_register
                ][0]

                set_ins = target.set_register(
                    areg,
                    address,
                    context,
                    opt=False,
                )
                new_instructions += set_ins
                reset_steps.append([set_ins, areg, address_obj])

                context.set_register_value(areg, address_obj)

                store_ins = target.store_integer(
                    reset_register,
                    address_obj,
                    length * 8,
                    context,
                )
                new_instructions += store_ins
                reset_steps.append(
                    [store_ins, reset_register, address_obj, length],
                )

                for ins in set_ins:
                    ins.add_comment(
                        "Reset code. Setting %s to 0X%016X"
                        % (areg.name, address),
                    )

            for ins in store_ins:
                ins.add_comment(
                    "Reset code. Setting mem content in 0X%016X" % (address),
                )

            new_ins.extend(new_instructions)

    # Reset contents of used registers
    for reset_register in reset_regs:
        try:
            value = [
                reg
                for reg in test_def.registers
                if reg.name == reset_register.name
            ][0].value
        except IndexError:
            continue

        new_instructions = target.set_register(
            reset_register,
            value,
            context,
            opt=False,
        )
        reset_steps.append([new_instructions, reset_register, value])
        context.set_register_value(reset_register, value)

        for ins in new_instructions:
            ins.add_comment(
                "Reset code. Setting %s to 0X%016X"
                % (reset_register.name, value),
            )

        new_ins.extend(new_instructions)

    try:
        overhead = ((len(new_ins) * 1.0) / dynamic_count) * 100
    except ZeroDivisionError:
        print_warning(
            "Unable to compute overhead. Zero dynamic instruction " "count"
        )
        overhead = 0

    print_info(
        "%03.2f%% overhead added by resetting code" % overhead,
    )
    if overhead > args["wrap_endless_threshold"]:
        print_error(
            "Instructions added: %d" % len(new_ins),
        )
        print_error(
            "Total instructions: %d" % dynamic_count,
        )
        print_error(
            "Reset code above --wrap-endless-threshold. Stopping generation.",
        )
        exit(1)

    return new_ins, overhead, reset_steps


def _compute_reset_jump(target, instrs):
    source_instruction = InstructionAddress(
        base_address="code",
        displacement=0,
    )

    displacement = 0
    for instr in instrs:
        displacement = displacement - instr.architecture_type.format.length

    target_instruction = InstructionAddress(
        base_address="code",
        displacement=displacement,
    )

    return target.branch_unconditional_relative2(
        source_instruction,
        target_instruction,
    )


# Main
def main():
    """Program main."""
    args = sys.argv[1:]
    cmdline = microprobe.utils.cmdline.CLI(
        "MicroprobeTest (mpt) to ELF tool",
        mpt_options=True,
        default_config_file="mp_mpt2elf.cfg",
        force_required=["target"],
    )

    group_name = "MPT to ELF arguments"
    cmdline.add_group(
        group_name,
        "Command arguments related to MPT to ELF tool",
    )

    cmdline.add_option(
        "elf-output-file",
        "O",
        None,
        "ELF output file name",
        group=group_name,
        opt_type=new_file_ext(".s"),
        required=True,
    )

    cmdline.add_option(
        "compiler",
        None,
        None,
        "Path to the compiler",
        group=group_name,
    )

    cmdline.add_option(
        "compiler-flags",
        None,
        "",
        "Compiler flags to use, if compiler is provided",
        group=group_name,
    )

    group_name = "Fixing options"
    cmdline.add_group(
        group_name,
        "Command arguments related to fixing options",
    )
    cmdline.add_flag(
        "fix-indirect-branches",
        None,
        "Fix branches without known target",
        group_name,
    )
    cmdline.add_flag(
        "fix-branch-next",
        None,
        "Force target of branches to be the next " "sequential instruction",
        group_name,
    )
    cmdline.add_flag(
        "fix-memory-references",
        None,
        "Ensure that registers used by instructions accessing "
        "storage are initialized to valid locations",
        group_name,
    )
    cmdline.add_flag(
        "fix-memory-registers",
        None,
        "Fix non-storage instructions touching registers used for"
        " storage address computations (implies "
        "--fix-memory-references flag)",
        group_name,
    )
    cmdline.add_flag(
        "fix-flatten-code",
        None,
        "All code is flatten using consecutive addresses",
        group_name,
    )
    cmdline.add_flag(
        "safe-bin",
        None,
        "Ignore unrecognized binary codifications (do not"
        "fail). Useful when MPTs are generated by dumping "
        "directly code "
        "pages, which contain padding zeros and other "
        "non-code stuff)",
        group_name,
    )
    cmdline.add_flag(
        "raw-bin",
        None,
        "Process all instruction entries together. They "
        "all shoud be binary entries. Implies --safe-bin "
        "flag. Useful when MPTs are generated by dumping "
        "directly code "
        "pages, which contain padding zeros and other "
        "non-code stuff)",
        group_name,
    )
    cmdline.add_flag(
        "fix-long-jump",
        None,
        "Sometimes the generated code is unable compile due a long jump "
        "displacement required to jump to the start insturction.",
        group_name,
    )

    cmdline.add_option(
        "fix-start-address",
        "S",
        None,
        "Sometimes the user requires the main start point to be on specific "
        "address to avoid compilation issues or comply with the execution "
        "environment requirements. This flag forces the main entry point of "
        "execution to be at the specified address. It is up to the user to "
        "define a proper entry point that does not clash with existing code.",
        group=group_name,
        opt_type=int_type(0, 2**64),
    )

    cmdline.add_option(
        "fix-32bit-address",
        "X",
        None,
        "Sometimes the user requires the addresses of the content to be "
        "within a 32bit address space. However, a test may incorporate "
        "content outside of that address space. This flag forces the "
        "variables to be shifted to fit within this limit, starting at the "
        "specified address. It is up to the user to define a proper starting "
        "address that does not clash with the existing code.",
        group=group_name,
        opt_type=int_type(0, 2**32),
    )

    group_name = "Wrapping options"
    cmdline.add_group(
        group_name,
        "Command arguments related to wrapping options",
    )
    cmdline.add_flag(
        "no-wrap-test",
        None,
        "By default the code is wrapped like it was "
        "a function call, use this flag to disable the "
        "wrapping",
        group_name,
    )
    cmdline.add_flag(
        "wrap-endless",
        None,
        "Use this flag to wrap the code in an endless "
        "loop assuming it is a function. "
        "If needed (--reset option), additional "
        "instructions are added to reset the "
        "the initial state between loop iterations. ",
        group_name,
    )
    cmdline.add_option(
        "wrap-endless-threshold",
        None,
        1,
        "Maximum percentage of instructions allowed in the reset code if "
        "--wrap-endless and --reset is used. I.e. if 10 is set, the tool will "
        "fail if the reset code required is more than 10%% of the actual "
        "code of the test case."
        " Default is 1%%.",
        group=group_name,
        opt_type=float_type(0, 1000),
        required=False,
    )
    cmdline.add_flag(
        "reset",
        None,
        "Use this flag to enable the generation of reset "
        "code if wrap-endless is enabled.",
        group_name,
    )

    print_info("Processing input arguments...")
    cmdline.main(args, _main)


def _main(arguments):
    """Program main, after processing the command line arguments.

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """
    print_info("Arguments processed!")
    print_info("Importing target definition...")

    if "raw_bin" in arguments:
        arguments["safe_bin"] = True

    if "safe_bin" in arguments:
        microprobe.MICROPROBE_RC["safe_bin"] = True

    if "fix_start_address" not in arguments:
        arguments["fix_start_address"] = None

    if "fix_32bit_address" not in arguments:
        arguments["fix_32bit_address"] = None

    if "no_wrap_test" in arguments and "wrap_endless" in arguments:
        print_error(
            "--no-wrap-test specified and --wrap-endless specified. "
            "Incompatible options."
        )

    target = import_definition(arguments.pop("target"))
    test_definition = arguments["mpt_definition"]
    output_file = arguments["elf_output_file"]

    print_info("Start generating '%s'" % output_file)
    generate(test_definition, output_file, target, **arguments)


if __name__ == "__main__":  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get("main")):
        main()
        exit(0)

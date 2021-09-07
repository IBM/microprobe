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
"""File: mp_mpt2tst.

This script implements the tool that converts mpt files to TSTs for simulation.
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
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.context import Context
from microprobe.code.ins import instruction_from_definition, \
    instruction_to_definition
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeException, MicroprobeMPTFormatError, MicroprobeValueError
from microprobe.target import import_definition
from microprobe.utils.asm import MicroprobeAsmInstructionDefinition,\
    interpret_asm
from microprobe.utils.cmdline import float_type, int_type, new_file_ext,\
    print_error, print_info, print_warning, string_with_fields
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Progress, twocs_to_int
from microprobe.utils.mpt import MicroprobeTestRegisterDefinition

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

    reset_steps = []
    if 'no_wrap_test' not in kwargs and False:

        start_symbol = "START_TEST"

        displacement = None
        for elem in test_definition.code:
            if elem.address is not None:
                if displacement is None:
                    displacement = elem.address
                displacement = min(displacement, elem.address)

        if test_definition.code[0].label is not None:
            start_symbol = test_definition.code[0].label
        else:
            test_definition.code[0].label = "START_TEST"

        if displacement is None:
            displacement = 0

        displacement_end = displacement
        instructions = []
        reset_steps = []
        if 'wrap_endless' in kwargs:
            new_ins, overhead, reset_steps = _compute_reset_code(
                target,
                test_definition,
                kwargs,
            )
            instructions += new_ins

        instructions += target.function_call(
            ("%s+0x%x" %
             (start_symbol, (-1) * displacement)).replace("+0x-", "-0x"),
        )

        if 'wrap_endless' not in kwargs:
            instructions += [target.nop()]
        else:
            instructions += _compute_reset_jump(target, len(instructions))

        instructions_definitions = []
        for instruction in instructions:
            instruction.set_label(None)
            displacement = (displacement -
                            instruction.architecture_type.format.length)
            current_instruction = MicroprobeAsmInstructionDefinition(
                instruction.assembly(), None, None, None, instruction.comments,
            )
            instructions_definitions.append(current_instruction)

        instruction = target.nop()
        instruction.set_label(None)
        displacement = (displacement -
                        instruction.architecture_type.format.length)
        end_address_orig = \
            (test_definition.default_code_address + displacement_end -
             instruction.architecture_type.format.length)

        test_definition.register_instruction_definitions(
            instructions_definitions,
            prepend=True,
        )

        test_definition.set_default_code_address(
            test_definition.default_code_address + displacement,
        )

        for elem in test_definition.code:
            if elem.address is not None:
                elem.address = elem.address - displacement

    variables = test_definition.variables

    print_info("Interpreting asm ...")
    sequence_orig = interpret_asm(
        test_definition.code, target,
        [var.name for var in variables],
        show_progress=True,
    )

    if len(sequence_orig) < 1:
        raise MicroprobeMPTFormatError(
            "No instructions found in the 'instructions' entry of the MPT"
            " file. Check the input file.",
        )

    raw = test_definition.raw

    shift_offset, addresses = _compute_offset(
        0,
        target,
        test_definition,
    )

    thread_id = 1

    shift_value = shift_offset * (thread_id - 1)
    end_address = end_address_orig
    if end_address:
        end_address = end_address_orig + shift_value
    ckwargs = {
        'reset': False,
        'endless': 'endless' in kwargs
    }

    # if test_definition.default_data_address is not None:
    #    ckwargs['init_data_address'] = \
    #        test_definition.default_data_address + shift_value

    # if test_definition.default_code_address is not None:
    #    ckwargs['init_code_address'] = \
    #        test_definition.default_code_address + shift_value

    wrapper_name = "Cronus"

    try:
        code_wrapper = microprobe.code.get_wrapper(wrapper_name)
    except MicroprobeValueError as exc:
        raise MicroprobeException(
            "Wrapper '%s' not available. Check if you have the wrappers"
            " of the target installed or set up an appropriate "
            "MICROPROBEWRAPPERS environment variable. Original error "
            "was: %s" %
            (wrapper_name, str(exc)),
        )

    wrapper = code_wrapper(os.path.basename(output_file), **ckwargs)

    print_info("Setup synthesizer ...")
    synthesizer = microprobe.code.Synthesizer(
        target, wrapper, no_scratch=True,
        extra_raw=raw,
    )

    print_info("Processing thread-%d" % thread_id)
    synthesizer.set_current_thread(thread_id)

    variables = test_definition.variables
    registers = test_definition.registers
    sequence = sequence_orig

    cr_reg = [
        register for register in registers if register.name == "CR"
    ]

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
            registers, skip_unknown=True, warn_unknown=True,
            force_reserved=False, skip_control=True
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
                forbid_writes=['GPR3'],
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
                force="fix_flatten_code" in kwargs
            )
        )
        synthesizer.add_pass(
            microprobe.passes.branch.BranchNextPass(force=True),
        )

    if kwargs.get("fix_indirect_branches", False):
        print_info("Fix indirect branches: On")
        synthesizer.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass(),
        )
        synthesizer.add_pass(
            microprobe.passes.branch.FixIndirectBranchPass(),
        )

    synthesizer.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass(),
    )

    synthesizer.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass(),
    )

    print_info("Start synthesizer ...")
    bench = synthesizer.synthesize()

    # Save the microbenchmark
    synthesizer.save(output_file, bench=bench)
    return


def _compute_offset(smt_shift, target, test_def):
    """Compute required offset bettween threads to avoid conflicts."""
    addresses = []

    instructions = interpret_asm(
        test_def.code, target, [var.name for var in test_def.variables],
    )
    instructions = [
        instruction_from_definition(instr) for instr in instructions
    ]

    address = test_def.default_code_address
    for instr in instructions:
        if instr.address is not None:
            if instr.address.base_address == "code":
                address = test_def.default_code_address + \
                          instr.address.displacement
                instr.set_address(address)
        else:
            address = address + instr.architecture_type.format.length

        addresses.append(address)

    for var in test_def.variables:
        addresses.append(var.address)
        if var.var_type.upper() in ["CHAR", "UINT8_T"]:
            addresses.extend(
                range(var.address, var.address + var.num_elements),
            )
        else:
            raise NotImplementedError(
                "Unable to compute touched addresses for "
                "type '%s'" % var.var_type
            )

    if test_def.roi_memory_access_trace:
        addresses = []
        for access in test_def.roi_memory_access_trace:
            addresses.extend(
                range(access.address, access.address + access.length),
            )

    offset = ((max(addresses) / (4 * 1024)) + 1) * (4 * 1024)
    offset = int(offset)
    max_range = offset
    min_range = (min(addresses) / (4 * 1024)) * (4 * 1024)

    print_info("Computed offset needed: %d bytes" % offset)
    print_info(
        "Computed offset needed: %d megabytes" %
        (offset / (1024 * 1024)),
    )

    if smt_shift != -1:
        if offset > smt_shift:
            print_warning(
                "Offset forced to be %d bytes. There is overlapping accross "
                "threads" % smt_shift,
            )
        else:
            print_info(
                "Offset forced to be %d bytes." % smt_shift,
            )
        return smt_shift, (min_range, max_range, set(addresses))

    return offset, (min_range, max_range, set(addresses))


def _shift_and_fix_variables(
    variables, offset, addresses, min_address, big_endian,
        ):
    """Shift variables and their contents."""
    svariables = []
    for variable in variables:

        variable = variable.copy()
        variable.address = variable.address + offset
        if variable.var_type.upper() in ["CHAR", "UINT8_T"]:
            cbytes = 8
            for idx in range(0, variable.num_elements):
                value = variable.init_value[idx:idx + cbytes]

                # Assuming 64-bit addresses
                if len(value) < cbytes:
                    continue

                # Assuming addresses are 8 byte aligned in memory
                if (variable.address + idx) % 8 != 0:
                    continue

                # Get value in bit/little endian
                if big_endian:
                    value_str = "".join([
                        "%02X" % val for val in value
                    ])
                else:
                    value_str = "".join([
                        "%02X" % val for val in reversed(value)
                    ])
                value = int(value_str, 16)

                if not (addresses[0] <= value <= addresses[1] and
                        value > min_address):
                    continue

                distance = min((abs(value - addr) for addr in addresses[2]))
                if distance > _FIX_ADDRESS_TOLERANCE:
                    continue

                nvalue = value + offset
                fmt_str = "%%0%dX" % (2 * cbytes)
                nvalue = fmt_str % nvalue

                print_info(
                    "Shifting pointer in variable: '%s' at"
                    " address '0x%016X' from '0x%s' to value "
                    "'0x%s" %
                    (variable.name, variable.address +
                     idx, value_str, nvalue),
                )

                if len(nvalue) > (2 * cbytes):
                    raise MicroprobeValueError(
                        "Overflow during variable shifting",
                    )
                if big_endian:
                    nvalue = [
                        int(nvalue[idx2:idx2 + 2], 16)
                        for idx2 in range(0, 2 * cbytes, 2)
                    ]
                else:
                    nvalue = [
                        int(nvalue[idx2:idx2 + 2], 16)
                        for idx2 in reversed(range(0, 2 * cbytes, 2))
                    ]

                variable.init_value[idx:idx + cbytes] = nvalue
        else:
            raise NotImplementedError(
                "Unable to shift variable "
                "type '%s'" % variable.var_type
            )

        svariables.append(variable)

    return svariables


def _shift_and_fix_registers(registers, offset, addresses, min_address):
    """Shift register contents."""
    sregisters = []
    for register in registers:
        register = register.copy()
        if not register.name.startswith("GPR"):
            # Do not shift not GPR registers
            sregisters.append(register)
            continue

        # if GPR value is a negative one, do not shift it
        value = twocs_to_int(register.value, 64)
        if value < 0:
            sregisters.append(register)
            continue

        if not ((addresses[0] <= register.value < addresses[1]) and
                register.value > min_address):
            sregisters.append(register)
            continue

        distance = min((abs(register.value - addr) for addr in addresses[2]))
        if distance > _FIX_ADDRESS_TOLERANCE:
            sregisters.append(register)
            continue

        print_info(
            "Shift '%s' from '0x%016X' to '0x%016X'" %
            (register.name,
             register.value,
             register.value + offset),
        )
        register.value = register.value + offset

        fmt_str = "{0:064b}"
        value_coded = fmt_str.format(register.value)
        if len(value_coded) > 64:
            print_warning(
                "Overflow during shifting. Cropping of"
                " register '%s'" % register.name
            )
            register.value = int(value_coded[-64:], 2)
        sregisters.append(register)

    return sregisters


def _shift_and_fix_code(
    target, code, offset, addresses, reset_steps, registers,
        ):
    """Shift code and fix reset code."""
    scode = []
    for instruction in code:
        instruction = instruction.copy()
        # Fix and shift decorators (not need to modify code)
        for key, values in instruction.decorators.items():
            if not isinstance(values, list):
                values = [values]
            if key in ['MA', 'BT']:
                for idx in range(0, len(values)):
                    if addresses[0] <= values[idx] <= addresses[1]:
                        values[idx] = values[idx] + offset
        scode.append(instruction)

    cidx = 0
    context = Context()
    context.set_symbolic(False)

    for reset_step in reset_steps:

        rins = reset_step[0]
        cins = scode[cidx:cidx+len(rins)]
        rreg = reset_step[1]

        try:
            rval = [reg for reg in registers if reg.name == rreg.name][0].value
        except IndexError:
            # This was a support register to compute an address,
            # it should be fixed
            rval = 0

        for rin, cin in zip(rins, cins):
            if rin.name != cin.instruction_type.name:
                print_error("Unable to fix the reset code")
                exit(1)

        if len(reset_step) == 3:
            rins, reset_register, value = reset_step
            if not isinstance(value, six.integer_types):
                # All addresses should be offset
                value += offset
                nins = target.set_register(
                    reset_register,
                    value.displacement,
                    context,
                    opt=False,
                )
                print_info(
                    "Fixing reset code for reg: %s. "
                    "New value: 0x%016X" %
                    (rreg.name, value.displacement),
                )
            else:
                if abs(value-rval) == offset:
                    # This has been shifted, force offset
                    value += offset
                    print_info(
                        "Fixing reset code for reg: %s. "
                        "New value: 0x%016X" %
                        (rreg.name, value),
                    )
                nins = target.set_register(
                    reset_register, value, context, opt=False,
                )

            context.set_register_value(reset_register, value)
        elif len(reset_step) == 4:
            rins, reset_register, address_obj, length = reset_step
            # All addresses should be offsetted
            address_obj += offset
            nins = target.store_integer(
                reset_register, address_obj, length * 8, context,
            )
            print_info(
                "Fixing reset code for reg: %s. "
                "New value: 0x%016X" %
                (rreg.name, address_obj.displacement),
            )
        else:
            raise NotImplementedError(
                "Unable to shift and fix code"
            )

        if len(rins) != len(nins):
            print_error("Original resetting code:")
            for ins in rins:
                print_error(ins.assembly())
            print_error("New resetting code:")
            for ins in nins:
                print_error(ins.assembly())
            print_error("New resetting code differs from original in length")
            exit(1)

        for ins in nins:
            if len(reset_step) == 3:
                if not isinstance(value, six.integer_types):
                    value = value.displacement
                ins.add_comment(
                    "Reset code. Setting %s to 0X%016X" %
                    (reset_register.name, value),
                )
            else:
                ins.add_comment(
                    "Reset code. Setting mem content in 0X%016X" %
                    (address_obj.displacement),
                )

        for idx, (nin, cin) in enumerate(zip(nins, cins)):
            if nin.name != cin.instruction_type.name:
                print_warning("New code differs from original in opcodes")
            scode[cidx+idx] = instruction_to_definition(nin)
            scode[cidx+idx].comments = scode[cidx+idx].comments[1:]

        cidx += len(rins)

    return scode


def _process_preload_data(data, args, offset=0):
    data_size = args['preload_data'] / args['smt_mode']
    code_size = args['preload_code'] / args['smt_mode']
    only_loads = args.get('preload_data_only_loads', False)
    only_stores = args.get('preload_data_only_stores', False)

    if only_loads and only_stores:
        print_warning(
            "Both --preload-data-only-loads and --preload-data-only-stores"
            " specified. No data will be pre-load!",
        )

    if only_loads:
        data = [
            access for access in data if access.data_type == "I" or
            (
                access.data_type ==
                "D" and
                access.access_type == "R"
            )
        ]

    if only_stores:
        data = [
            access for access in data if access.data_type == "I" or
            (
                access.data_type ==
                "D" and
                access.access_type ==
                "R"
            )
        ]

    fdata = []
    if len(args['preload_data_range']) > 0:
        for access in data:
            if access.data_type == "I":
                fdata.append(access)
                continue

            for start, end in args['preload_data_range']:
                if access.address >= start and (
                        access.address + access.length - 1) < end:
                    fdata.append(access)
                    break
        data = fdata

    addresses_read = []
    ccode = 0
    cdata = 0
    for access in data:
        if access.data_type == "D" and cdata >= data_size:
            continue
        if access.data_type == "I" and ccode >= code_size:
            continue

        for address in range(access.address, access.address + access.length):
            if address in addresses_read:
                continue

            addresses_read.append(address)

            if access.data_type == "D":
                cdata += 1
            else:
                ccode += 1

    for idx in range(0, len(addresses_read)):
        addresses_read[idx] = addresses_read[idx] + offset

    return set(addresses_read)


def _compute_reset_code(target, test_def, args):
    instructions = interpret_asm(
        test_def.code, target, [var.name for var in test_def.variables],
    )
    instructions = [
        instruction_from_definition(instr) for instr in instructions
    ]

    instruction_dict = {}
    address = test_def.default_code_address
    for instr in instructions:
        if instr.address is not None:
            if instr.address.base_address == "code":
                address = test_def.default_code_address + \
                          instr.address.displacement
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

        # Calls
        if instr.mnemonic == "BL":
            level += 1
        elif instr.mnemonic == "BCL":
            level += 1
        elif instr.mnemonic == "BCCTRL":
            if instr.operands()[2].value in [0, 3]:
                level += 1

        # Returns
        if instr.mnemonic == "BCLR":
            if (((instr.operands()[0].value & 0b10100) == 20) and
                    (instr.operands()[2].value == 0)):
                level -= 1

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
    reset_regs = [
        reg for reg in reset_regs if reg in target.volatile_registers]
    unused_regs = sorted(
        (reg for reg in target.registers.values() if reg not in read_regs),
    )

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
                if var.address <= address <= end_address:
                    offset = int((address - var.address) / elem_size)
                    svalue = var.init_value[
                        offset:offset + int(value[0] / elem_size)
                    ]
                    svalue = "".join(["%02X" % tval for tval in svalue])
                    wvalue = int(svalue, 16)
                    break

            if wvalue is None:
                print_error(
                    "Unable to restore original value for address 0x%X" %
                    address,
                )
                exit(1)

            if value[0] <= 8:
                fix_addresses.append((address, value[0], wvalue))
            else:
                for selem in range(0, value[0]//8):
                    sfmt = "%%0%dX" % (2*value[0])
                    nvalue = sfmt % wvalue
                    nvalue = int(nvalue[selem*16:(selem+1)*16], 16)
                    fix_addresses.append(
                        (address + selem * 8,
                         8,
                         nvalue)
                    )

    reset_steps = []

    context = Context()
    context.set_symbolic(False)

    if len(fix_addresses) > 0:

        # TODO: This can be optimized. Reduce the number of instructions to
        # be added by sorting the reset code (shared values or similar
        # addresses)
        #
        print_info("Adding instructions to reset memory state")

        reset_register = [
            reg
            for reg in free_regs
            if reg.type.used_for_address_arithmetic and
            reg.name != "GPR0"
        ][0]

        for address, length, value in fix_addresses:
            address_obj = Address(base_address="data", displacement=address)
            new_instructions = target.set_register(
                reset_register, value, context, opt=False,
            )

            for ins in new_instructions:
                ins.add_comment(
                    "Reset code. Setting %s to 0X%016X" %
                    (reset_register.name, value),
                )

            reset_steps.append([new_instructions[:], reset_register, value])
            context.set_register_value(reset_register, value)

            try:
                store_ins = target.store_integer(
                    reset_register, address_obj, length * 8, context,
                )
                new_instructions += store_ins
                reset_steps.append(
                    [store_ins, reset_register, address_obj, length],
                )

            except MicroprobeCodeGenerationError:
                areg = [
                    reg for reg in free_regs
                    if reg.type.used_for_address_arithmetic and reg.name !=
                    "GPR0"
                ][1]

                set_ins = target.set_register(
                    areg, address, context, opt=False,
                )
                new_instructions += set_ins
                reset_steps.append([set_ins, areg, address_obj])

                context.set_register_value(areg, address_obj)

                store_ins = target.store_integer(
                    reset_register, address_obj, length * 8, context,
                )
                new_instructions += store_ins
                reset_steps.append(
                    [store_ins, reset_register, address_obj, length],
                )

                for ins in set_ins:
                    ins.add_comment(
                        "Reset code. Setting %s to 0X%016X" %
                        (areg.name, address),
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
                reg for reg in test_def.registers if reg.name ==
                reset_register.name
            ][0].value
        except IndexError:
            continue

        new_instructions = target.set_register(
            reset_register, value, context, opt=False,
        )
        reset_steps.append([new_instructions, reset_register, value])
        context.set_register_value(reset_register, value)

        for ins in new_instructions:
            ins.add_comment(
                "Reset code. Setting %s to 0X%016X" %
                (reset_register.name, value),
            )

        new_ins.extend(new_instructions)

    try:
        overhead = (((len(new_ins) * 1.0) / dynamic_count) * 100)
    except ZeroDivisionError:
        print_warning("Unable to compute overhead. Zero dynamic instruction "
                      "count")
        overhead = 0

    print_info(
        "%03.2f%% overhead added by resetting code" % overhead,
    )
    if overhead > args['wrap_endless_threshold']:
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


def _compute_reset_jump(target, num_ins):
    source_instruction = InstructionAddress(
        base_address="code", displacement=0,
    )
    target_instruction = InstructionAddress(
        base_address="code", displacement=num_ins * (-4),
    )
    return [
        target.branch_unconditional_relative(
            source_instruction, target_instruction,
        ),
    ]


# Main
def main():
    """Program main."""
    args = sys.argv[1:]
    cmdline = microprobe.utils.cmdline.CLI(
        "MicroprobeTest (mpt) to BIN tool",
        mpt_options=True,
        avp_options=False,
        default_config_file="mp_mpt2bin.cfg",
        force_required=['target'],
    )

    group_name = "MPT to BIN arguments"
    cmdline.add_group(
        group_name, "Command arguments related to MPT to BIN tool",
    )

    cmdline.add_option(
        "bin-output-file",
        "O",
        None,
        "BIN output file name",
        group=group_name,
        opt_type=new_file_ext(".bin"),
        required=True,
    )
    cmdline.add_flag(
        "big-endian", None, "Test case in big endian (default is little "
                            "endian)",
        group_name,
    )

    group_name = "Fixing options"
    cmdline.add_group(
        group_name,
        "Command arguments related to fixing options",
    )
    cmdline.add_flag(
        "fix-indirect-branches", None, "Fix branches without known target",
        group_name,
    )
    cmdline.add_flag(
        "fix-branch-next", None, "Force target of branches to be the next "
                                 "sequential instruction",
        group_name,
    )
    cmdline.add_flag(
        "fix-memory-references", None,
        "Ensure that registers used by instructions accessing "
        "storage are initialized to valid locations", group_name,
    )
    cmdline.add_flag(
        "fix-memory-registers", None,
        "Fix non-storage instructions touching registers used for"
        " storage address computations (implies "
        "--fix-memory-references flag)", group_name,
    )
    cmdline.add_flag(
        "fix-flatten-code", None,
        "All code is flatten using consecutive addresses",
        group_name,
    )
    cmdline.add_flag(
        "safe-bin", None, "Ignore unrecognized binary codifications (do not"
                          "fail). Useful when MPTs are generated by dumping "
                          "directly code "
                          "pages, which contain padding zeros and other "
                          "non-code stuff)",
        group_name,
    )

    group_name = "Wrapping options"
    cmdline.add_group(
        group_name,
        "Command arguments related to wrapping options",
    )
    cmdline.add_flag(
        "no-wrap-test", None, "By default the code is wrapped like it was "
                              "a function call, use this flag to disable the "
                              "wrapping",
        group_name,
    )
    cmdline.add_flag(
        "wrap-endless", None, "Use this flag to wrap the code in an endless "
                              "loop assuming it is a function. "
                              "If needed, additional instructions are "
                              "added to reset the "
                              "the initial state between loop iterations. ",
        group_name,
    )
    cmdline.add_option(
        "wrap-endless-threshold",
        None,
        1,
        "Maximum percentage of instructions allowed in the reset code if "
        "--wrap-endless loop is used. I.e. if 10 is set, the tool will "
        "fail if the reset code required is more than 10%% of the actual "
        "code of the test case."
        " Default is 1%%.",
        group=group_name,
        opt_type=float_type(0, 1000),
        required=False,
    )
    cmdline.add_flag(
        "endless", None, "Use this flag to wrap the code in an endless "
                         "loop.",
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

    if 'safe-bin' in arguments:
        microprobe.MICROPROBE_RC['safe_bin'] = True

    target = import_definition(arguments.pop('target'))
    test_definition = arguments['mpt_definition']
    output_file = arguments['bin_output_file']

    print_info("Start generating '%s'" % output_file)
    generate(
        test_definition, output_file, target, **arguments
    )
    print_info("'%s' generated!" % output_file)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

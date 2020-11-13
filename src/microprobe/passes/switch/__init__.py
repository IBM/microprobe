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
""":mod:`microprobe.passes.switch` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import itertools
import random
import re

# Third party modules
from six.moves import range

# Own modules
import microprobe.passes
import microprobe.utils.distrib
from microprobe.code.address import Address, MemoryValue
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeValueError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import OrderedDict

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = ['SwitchingInstructions', 'SwitchingStores', 'Switching']

# Functions


# Classes
class Switching(microprobe.passes.Pass):
    """Switching pass.

    """

    def __init__(self, instr, operands, num_targets):
        """

        :param instr:
        :type instr:
        :param operands:
        :type operands:
        :param num_targets:
        :type num_targets:
        """

        super(Switching, self).__init__()
        self._instr = instr
        self._operands = operands
        self._targets = num_targets
        self._description = "Manual switching per instruction"

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        target_descriptors = []
        value_dict = {}

        for idx in range(0, self._targets):
            base_descriptor = [None,  # target register
                               False,  # initialized
                               itertools.cycle(
                                   self._operands
                               )  # required operands
                               ]
            for dummy in range(0, idx):
                next(base_descriptor[2])

            target_descriptors.append(base_descriptor)

        iter_descriptor = itertools.cycle(
            target_descriptors
        )  # required operands

        context = building_block.context

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:
                if instr.architecture_type == self._instr:

                    if len(instr.operands()) == 0:
                        continue

                    descriptor = next(iter_descriptor)
                    operands = next(descriptor[2])

                    if descriptor[0] is None:
                        valid_values = set(
                            instr.operands()[0].type.values()
                        ).difference(
                            set(context.reserved_registers)
                        )
                        valid_value = list(valid_values)[0]
                        context.add_reserved_registers([valid_value])
                        descriptor[0] = valid_value

                        for xreg in instr.architecture_type.sets(
                            [descriptor[0]] + [None] * (len(descriptor) - 1)
                        ):

                            if not instr.allows(xreg):
                                instr.add_allow_register(xreg)

                            if xreg not in context.reserved_registers:
                                context.add_reserved_registers([xreg])

                        if operands[0] is not None and not descriptor[1]:
                            building_block.add_init(
                                target.set_register(
                                    valid_value, operands[0]
                                )
                            )

                    final_operands = [descriptor[0]]
                    if not instr.allows(descriptor[0]):
                        instr.add_allow_register(descriptor[0])

                    for idx, operand in enumerate(operands[1:]):

                        if operand not in value_dict:

                            if instr.operands()[idx + 1][0].immediate():
                                pass
                            else:
                                valid_values = set(
                                    instr.operands()[
                                        idx + 1
                                    ][0].values()
                                ).difference(
                                    context.reserved_registers
                                )
                                valid_value = list(valid_values)[0]
                                context.add_reserved_registers([valid_value])

                                building_block.add_init(
                                    target.set_register(
                                        valid_value, operand
                                    )
                                )
                                value_dict[operand] = valid_value

                        if instr.operands()[idx + 1][0].immediate():
                            final_operands.append(operand)
                        else:
                            instr.add_allow_register(value_dict[operand])
                            final_operands.append(value_dict[operand])

                    instr.set_operands(final_operands)

                    for mkreg in instr.sets():
                        if not instr.allows(mkreg):

                            instr.add_allow_register(mkreg)

                        if mkreg not in context.reserved_registers:

                            context.add_reserved_registers([mkreg])

                    for mkreg in instr.uses():
                        if not instr.allows(mkreg):

                            instr.add_allow_register(mkreg)
                        if mkreg not in context.reserved_registers:
                            context.add_reserved_registers([mkreg])


class SwitchingInstructions(microprobe.passes.Pass):
    """SwitchingInstructions pass.

    """

    def __init__(self, replicate=1, strict=False):
        """

        :param replicate:  (Default value = 1)

        """
        super(SwitchingInstructions, self).__init__()
        self._description = "Maximize switching factors on instruction "\
                            "operands"
        self._replicate = replicate
        self._strict = strict

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        descriptors = {}
        context = building_block.context

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                if instr.switching == "None":
                    if self._strict:
                        raise MicroprobeCodeGenerationError(
                            "No switching defined for '%s'" % instr
                        )
                    LOG.warning("No switching defined for '%s'", instr)
                    continue

                if instr.architecture_type not in descriptors:

                    LOG.debug("Initializing switching for '%s'", instr)

                    statuses = []
                    for status in instr.switching:
                        statuses.append(status)

                    status_idx = 0
                    repl_idx = 0

                    output_registers = [None] * self._replicate

                    for idx in range(0, self._replicate):
                        for operand in instr.operands():
                            if operand.is_output:

                                assert output_registers[idx] is None

                                if statuses[0][0] == "None":

                                    continue

                                try:

                                    output_registers[idx] = \
                                        [reg for reg in
                                         operand.type.values() if reg not in
                                         context.reserved_registers][0]

                                except IndexError:

                                    LOG.critical(
                                        [reg for reg in operand.type.values()
                                         if reg not in
                                         context.reserved_registers])

                                    LOG.critical(operand)
                                    LOG.critical(building_block.context.dump())
                                    raise NotImplementedError

                                context.add_reserved_registers(
                                    [output_registers[idx]]
                                )

                                building_block.add_init(
                                    target.set_register(
                                        output_registers[idx], statuses[0][
                                            0
                                        ], building_block.context
                                    )
                                )

                                building_block.context.set_register_value(
                                    output_registers[idx], statuses[0][0]
                                )

                                LOG.debug(
                                    "Output register set to '%x'",
                                    statuses[0][0]
                                )

                    LOG.debug("Output registers: %s", output_registers)
                    LOG.debug("Statuses: %s", statuses)
                    LOG.debug("Index: %d", status_idx)
                    LOG.debug("Replication Index: %d", repl_idx)

                    descriptors[instr.architecture_type] = \
                        (output_registers, status_idx, repl_idx,
                         statuses * self._replicate, 1)

                else:

                    output_registers, status_idx, repl_idx, statuses, count = \
                        descriptors[instr.architecture_type]

                    descriptors[instr.architecture_type] = \
                        (output_registers, status_idx,
                         repl_idx, statuses, count + 1)

        for key, values in descriptors.items():

            output_registers, status_idx, repl_idx, statuses, count = values
            descriptors[key] = (
                output_registers, status_idx, repl_idx, statuses, count
            )

        LOG.debug("Setting up switching")

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                LOG.debug("Instruction: '%s'", instr)

                if instr.switching == "None":
                    LOG.debug("No switching defined for '%s'", instr)
                    continue

                if len(
                    [
                        oper for oper in instr.operands() if oper.value is None
                    ]
                ) == 0:
                    LOG.debug(
                        "Operands of the instructions already set '%s'", instr
                    )
                    continue

                output_registers, status_idx, repl_idx, statuses, count = \
                    descriptors[instr.architecture_type]

                output_register = output_registers[repl_idx]

                if count == 0 and statuses[0][0] != "None":
                    LOG.debug(
                        "Skip last switch if not pair to maintain "
                        "switching effects"
                    )
                    LOG.debug("Current count: %s", count)

                    LOG.critical(
                        instr.architecture_type, count, repl_idx, status_idx,
                        len(statuses)
                    )

                    # TODO: add strict/not strict parameter
                    exit(0)

                if output_register is not None:
                    instr.add_allow_register(output_register)

                status = statuses[
                    repl_idx * (len(statuses) // self._replicate) + status_idx
                ]

                LOG.debug("Current descriptor:")
                LOG.debug("Output register: %s", output_register)
                LOG.debug("Statuses: %s", statuses)
                LOG.debug("Index: %d", status_idx)
                LOG.debug("Replication Index: %d", repl_idx)
                LOG.debug("Current status: %s", status)
                LOG.debug("Current count: %s", count)

                memoperand_idx = 0
                memoperand_list = [
                    memop
                    for memop in instr.memory_operands()
                    if memop.address is not None
                ]

                operand_idx = 0
                operand_list = [
                    oper
                    for oper in instr.operands()
                    if oper.value is None and oper.is_input and
                    not oper.type.constant
                ]

                # if len(operand_list) == 0:
                #    for oper in instr.operands():
                #        LOG.debug(oper)
                #    raise MicroprobeCodeGenerationError(
                #        "No operand to switch. All already set?"
                #    )

                LOG.debug("Switching instruction: %s", instr)
                LOG.debug("Operands to switch:")
                for oper in operand_list:
                    LOG.debug(oper)

                for switch_input in status[1:]:

                    LOG.debug("Init value to set: %s", switch_input)
                    LOG.debug("Operand idx: %d", operand_idx)

                    if switch_input == "None":
                        # Nothing to do. Assume a register or immediate
                        LOG.debug("Skip")
                        operand_idx += 1

                    elif isinstance(switch_input, str) and \
                            switch_input.startswith("Mem:"):

                        LOG.debug("Memory operand")
                        # Memory
                        required_value = int(switch_input.split(":")[1], 0)
                        memoperand = memoperand_list[memoperand_idx]
                        address = memoperand.address

                        # we can modify a bit the address if we maintain the
                        # same cache line

                        # linesize = target.cache_hierarchy.data_linesize()
                        memory_set = False
                        # for displacement in range(
                        #    0, linesize / 8, memoperand.length
                        # ):

                        for displacement in [0]:

                            address = address + displacement
                            memvalue = building_block.context.get_memory_value(
                                address
                            )

                            LOG.debug("Required value: 0x%x", required_value)
                            LOG.debug("Target address: %s", address)
                            LOG.debug("Current memory value: %s", memvalue)

                            if memvalue is None:

                                LOG.debug("Initialize memory contents")

                                mycontext = target.wrapper.context()
                                treg = target.scratch_registers[0]
                                instrs = target.set_register(
                                    treg, required_value,
                                    mycontext
                                )
                                areg = target.scratch_registers[1]
                                instrs += target.set_register_to_address(
                                    areg, address,
                                    mycontext
                                )
                                mycontext.set_register_value(
                                    areg, address
                                )

                                reg0 = \
                                    target.get_register_for_address_arithmetic(
                                        mycontext
                                    )
                                instrs += target.set_register(
                                    reg0, 0,
                                    mycontext
                                )
                                mycontext.set_register_value(
                                    reg0, 0
                                )

                                instrs += target.store_integer(
                                    treg, address, memoperand.length * 8,
                                    mycontext
                                )

                                building_block.add_init(instrs, prepend=True)
                                building_block.context.set_memory_value(
                                    MemoryValue(
                                        address, required_value,
                                        memoperand.length
                                    )
                                )

                                # memoperand.set_address(
                                #    address, building_block.context
                                # )

                                LOG.debug("Memory contents initialized")
                                memory_set = True
                                break

                            elif memvalue.value == required_value and \
                                    memvalue.length == memoperand.length:

                                # perfect, nothing to do
                                LOG.debug(
                                    "Memory contents already contain the"
                                    " required value."
                                )

                                # memoperand.set_address(
                                #     address, building_block.context
                                # )

                                memory_set = True
                                break

                        if memory_set is False:

                            LOG.warning(
                                "Unable to set the memory to the"
                                " required value."
                            )

                        memoperand_idx += 1

                    else:

                        LOG.debug("Required value: %s", switch_input)
                        operand = operand_list[operand_idx]
                        LOG.debug("Operand: %s", operand)

                        if operand.is_output:

                            LOG.debug(
                                "Operand is output. Already fixed to "
                                "'%s' ", output_register
                            )
                            operand.set_value(output_register)

                        elif operand.type.immediate:

                            LOG.debug(
                                "Operand is immediate. Set to '%s' (0x%X)",
                                switch_input, switch_input
                            )
                            operand.set_value(switch_input)

                        elif building_block.context.register_has_value(
                            switch_input
                        ) and building_block.context.registers_get_value(
                                    switch_input
                                )[0] in operand.type.values():

                            treg = building_block.context.registers_get_value(
                                switch_input
                            )[0]

                            LOG.debug("Value already in register '%s'", treg)
                            operand.set_value(treg)

                        else:

                            LOG.debug("Initializing register contents")
                            tregs = [
                                reg
                                for reg in operand.type.values()
                                if reg not in context.reserved_registers
                            ]

                            if len(tregs) == 0:
                                # raise MicroprobeCodeGenerationError(
                                #    "No free registers available to switching"
                                # )
                                LOG.debug(
                                    "No free registers available to switching"
                                )
                            else:
                                treg = tregs[0]
                                instrs = target.set_register(
                                    treg, switch_input, context
                                )

                                operand.set_value(treg)
                                building_block.add_init(instrs)
                                building_block.context.set_register_value(
                                    treg, switch_input
                                )
                                building_block.context.add_reserved_registers(
                                    [treg]
                                )
                                LOG.debug(
                                    "Register '%s' set to '%s'", treg,
                                    switch_input
                                )

                        operand_idx += 1

                repl_idx += 1
                repl_idx = repl_idx % self._replicate

                if repl_idx == 0:
                    status_idx += 1
                    status_idx = status_idx % (
                        len(statuses) // self._replicate)

                descriptors[instr.architecture_type] = \
                    (output_registers, status_idx, repl_idx, statuses,
                     count - 1)


class SwitchingStores(microprobe.passes.Pass):
    """SwitchingStores pass.

    """

    def __init__(self, store_pattern):
        """

        :param store_pattern:

        """
        super(SwitchingStores, self).__init__()
        self._description = "Maximize switching factors on instruction "\
                            "store activities"
        self._pattern = store_pattern

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        descriptors = {}

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                if not instr.access_storage:

                    continue

                memoperands = [
                    operand
                    for operand in instr.memory_operands() if operand.is_store
                ]

                if len(memoperands) == 0:
                    # No stores
                    continue

                memoperand = memoperands[0]

                operands = [
                    operand
                    for operand in instr.operands()
                    if not operand.value and not operand.type.immediate
                ]

                if len(operands) == 0:

                    continue

                elif len(operands) > 1:

                    LOG.critical(operands)
                    raise NotImplementedError

                operand = operands[0]

                if memoperand.address is None:

                    continue

                if memoperand.address not in descriptors:

                    descriptors[memoperand.address] = \
                        itertools.cycle(self._pattern)

                pattern = next(descriptors[memoperand.address])

                needs_init = True
                if building_block.context.register_has_value(pattern):

                    treg = building_block.context.registers_get_value(
                        pattern
                    )[0]

                    if treg.type == list(operand.type.values())[0].type:
                        operand.set_value(treg)
                        needs_init = False

                if needs_init:
                    LOG.debug("Initializing register contents")
                    treg = [
                        reg
                        for reg in operand.type.values()
                        if reg not in building_block.context.reserved_registers
                    ][0]

                    instrs = target.set_register(
                        treg, pattern, building_block.context
                    )

                    operand.set_value(treg)
                    building_block.add_init(instrs)

                    building_block.context.set_register_value(treg, pattern)
                    building_block.context.add_reserved_registers([treg])
                    LOG.debug("Register '%s' set to '%s'", treg, pattern)

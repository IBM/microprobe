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
""":mod:`microprobe.passes.register` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import itertools
import random
import re

# Third party modules
from six.moves import zip
import six

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
__all__ = [
    'DefaultRegisterAllocationPass',
    'CycleMinimalAllocationPass',
    'FixRegistersPass',
    'NoHazardsAllocationPass',
    'RandomAllocationPass'
]

# Functions


# Classes
class DefaultRegisterAllocationPass(microprobe.passes.Pass):
    """DefaultRegisterAllocationPass pass.

    """

    def __init__(self, minimize=False, value=None, dd=0, relax=False):
        """

        :param minimize:  (Default value = False)
        :param value:  (Default value = None)
        :param dd:  (Default value = 1)

        """
        super(DefaultRegisterAllocationPass, self).__init__()
        self._min = minimize
        if self._min:
            raise NotImplementedError(
                "Feature changed need to be"
                " reimplemented"
            )

        if isinstance(dd, six.integer_types):
            self._dd = lambda: dd  # Dependency distance
        elif isinstance(dd, float):
            self._dd = microprobe.utils.distrib.discrete_average(dd)
        elif callable(dd):
            self._dd = dd
        else:
            raise MicroprobeValueError("Invalid parameter")

        self._relax = relax

        if value is not None:
            self._immediate = value
            if value == "zero":
                self._immediate = 0
        else:
            self._immediate = "random"
        self._description = "Default register allocation (required always to" \
                            " set any remaining operand). minimize=%s, " \
                            "value=%s, dd=%s" % (minimize, value, dd)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        allregs = target.registers
        lastdefined = {}
        lastused = {}
        rregs = set(building_block.context.reserved_registers)

        # TODO: All this pass has to be reimplemented

        for reg in allregs.values():

            if reg in rregs:
                # TODO:  rregs can be used but only as input, now we discard
                #        them for input and output
                continue

            if reg.type not in lastused:
                lastused[reg.type] = OrderedDict()
                lastdefined[reg.type] = OrderedDict()

            lastdefined[reg.type][reg] = 0
            lastused[reg.type][reg] = 1

        idx = 1
        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                dependency_ok = False

                used = []
                defined = []

                distance = self._dd()

                for operand in instr.operands():

                    if operand.value is not None:
                        # operand already set
                        pass
                    elif operand.type.immediate:
                        if self._immediate != "random":
                            try:
                                svalue = self._immediate
                                while callable(svalue):
                                    svalue = svalue()
                                operand.set_value(svalue)
                            except MicroprobeValueError:

                                LOG.warning(
                                    "Operand '%s' in instruction '%s' "
                                    "not modeled properly. Tried to "
                                    "'%s' value ...", operand.type,
                                    instr.name, svalue
                                )

                                value = list(operand.type.values())[0]
                                operand.set_value(value)

                                LOG.warning("Operand set to: '%s'", value)

                        else:
                            operand.set_value(operand.type.random_value())

                    elif operand.type.address_relative:

                        LOG.warning(
                            "Operand '%s' in instruction '%s' "
                            "not modeled properly", operand.type, instr.name
                        )
                        operand.set_value(list(operand.type.values())[0])

                    else:

                        if operand.is_input and distance > 0 and \
                           not dependency_ok and idx > distance:

                            LOG.debug("Setting dependency distance")

                            regs = list(operand.type.values())
                            valid_values = []

                            for reg in regs:

                                if len(
                                    rregs.intersection(
                                        operand.type.access(reg)
                                    )
                                ) == 0:
                                    valid_values.append(reg)

                            if (len(valid_values) == 0 and
                                    operand.is_input and
                                    not operand.is_output):
                                # Try to use reserved values
                                # if the operand is reading only
                                valid_values = list(operand.type.values())

                            LOG.debug("Current idx: %d", idx)
                            LOG.debug("Requested idx: %d", idx - distance)

                            reg = microprobe.utils.distrib.sort_by_distance(
                                valid_values, lastdefined[regs[0].type],
                                lastused[regs[0].type], idx - distance, instr,
                                idx
                            )

                            LOG.debug("%s selected", reg)

                            if reg in lastdefined[regs[0].type]:
                                LOG.debug(
                                    "Last defined: %s", lastdefined[
                                        regs[0].type
                                    ][reg]
                                )

                            if reg in lastused[regs[0].type]:
                                LOG.debug(
                                    "Last used: %s", lastused[
                                        regs[0].type
                                    ][reg]
                                )

                            dependency_ok = True

                        else:

                            regs = list(operand.type.values())
                            valid_values = []

                            for reg in regs:
                                if len(
                                    rregs.intersection(
                                        operand.type.access(reg)
                                    )
                                ) == 0:
                                    valid_values.append(reg)

                            if (len(valid_values) == 0 and
                                    operand.is_input and
                                    not operand.is_output):
                                # Try to use reserved values
                                # if the operand is reading only
                                valid_values = list(operand.type.values())

                            if len(valid_values) == 0:
                                LOG.critical("Instruction: %s", instr)
                                LOG.critical("Operand: %s", operand)
                                LOG.critical("Possible all values: %s",
                                             sorted(operand.type.values()))
                                LOG.critical(
                                    "Possible values: %s",
                                    sorted(regs))
                                LOG.critical(
                                    "Reserved values: %s",
                                    sorted(rregs))
                                raise MicroprobeCodeGenerationError(
                                    "Unable to find proper operand"
                                    " values for register allocation."
                                )

                            if regs[0].type not in lastused:
                                raise MicroprobeCodeGenerationError(
                                    "Unable to find proper operand"
                                    " values for register allocation."
                                    " No registers of type '%s' "
                                    "available." % regs[0].type
                                )

                            reg = microprobe.utils.distrib.sort_by_usage(
                                valid_values, lastused[regs[0].type],
                                lastdefined[regs[0].type]
                            )

                        operand.set_value(reg)

                        if self._min is False:
                            for reg in operand.uses():
                                LOG.debug("Updating usage of %s", reg)
                                LOG.debug(list(lastused[reg.type].keys()))
                                if reg in lastused[reg.type]:
                                    del lastused[reg.type][reg]
                                lastused[reg.type][reg] = idx
                                used.append(reg)
                                LOG.debug(list(lastused[reg.type].keys()))

                        if operand.is_output:
                            for reg in operand.sets():
                                LOG.debug("Updating definition of %s", reg)
                                if reg in lastdefined[reg.type]:
                                    del lastdefined[reg.type][reg]
                                lastdefined[reg.type][reg] = idx
                                defined.append(reg)

                                LOG.debug("Updating usage of %s", reg)
                                LOG.debug(list(lastused[reg.type].keys()))
                                if reg in lastused[reg.type]:
                                    del lastused[reg.type][reg]
                                lastused[reg.type][reg] = idx
                                used.append(reg)
                                LOG.debug(list(lastused[reg.type].keys()))

                # if self._min is True:
                #    for reg in instr.uses():
                #        if reg in lastused[reg.type]:
                #            del lastused[reg.type][reg]
                #        lastused[reg.type][reg] = idx
                #        used.append(reg)
                #    for reg in instr.sets():
                #        if reg in lastused[reg.type]:
                #            del lastused[reg.type][reg]
                #        lastused[reg.type][reg] = idx
                #        used.append(reg)

                fail = rregs.intersection(set(instr.sets()))

                if len(fail) > 0 and not self._relax:
                    for reg in fail:
                        if not instr.allows(reg):
                            raise MicroprobeCodeGenerationError(
                                "Instruction '%s' sets a reserved"
                                " register but not allowed before:"
                                "Register: %s. Reserved: %s" % (
                                    instr.name, reg.name,
                                    sorted([reg.name for reg in rregs])
                                )
                            )

                for reg in instr.uses():
                    if reg not in used and reg not in rregs:
                        LOG.debug("Updating usage of %s", reg)
                        lastused[reg.type][reg] = idx

                for reg in instr.sets():
                    if reg not in defined and reg not in rregs:
                        LOG.debug("Updating definition of %s", reg)
                        del lastdefined[reg.type][reg]
                        lastdefined[reg.type][reg] = idx

                LOG.debug("Instruction: %s", instr)
                LOG.debug("Last used rank:")
                for rtype in lastused:
                    for reg in lastused[rtype]:
                        if lastused[rtype][
                            reg
                        ] > 0 and reg.name.startswith("GPR"):
                            LOG.debug("%s: %d", reg.name, lastused[rtype][reg])
                LOG.debug("Last defined rank:")
                for rtype in lastdefined:
                    for reg in lastdefined[rtype]:
                        if lastdefined[rtype][
                            reg
                        ] > 0 and reg.name.startswith("GPR"):
                            LOG.debug(
                                "%s: %d", reg.name, lastdefined[rtype][reg]
                            )

                idx = idx + 1


class CycleMinimalAllocationPass(microprobe.passes.Pass):
    """CycleMinimalAllocationPass pass.

    """

    def __init__(self, size, reads, writes, value=None):
        """

        :param size:
        :param reads:
        :param writes:
        :param value:  (Default value = None)

        """
        super(CycleMinimalAllocationPass, self).__init__()
        self._size = size  # groups size
        self._reads = reads  # max reads in a group to the same register
        self._writes = writes  # max writes in a group to the same register
        self._rdwr = min(reads, writes)
        if value is not None:
            self._immediate = value
        else:
            self._immediate = "random"

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        lastdefined = {}
        lastreaded = {}
        lastdefread = {}

        def reset_dictionaries():
            """ Reset the local dependency tracking dictionaries """

            allregs = list(target.registers.values())
            allregs.sort(key=lambda x: int(re.findall(r'\d+', str(x))[0]))

            for reg in allregs:
                if reg.type not in lastreaded:
                    lastreaded[reg.type] = OrderedDict()

                if reg.type not in lastdefined:
                    lastdefined[reg.type] = OrderedDict()

                if reg.type not in lastdefread:
                    lastdefread[reg.type] = OrderedDict()

                lastreaded[reg.type][reg] = 0

                if reg not in building_block.context.reserved_registers:

                    lastdefined[reg.type][reg] = 0
                    lastdefread[reg.type][reg] = 0

        def remove_dict_key(reg):
            """

            :param reg:

            """
            if reg in lastdefined[reg.type]:
                del lastdefined[reg.type][reg]
            if reg in lastreaded[reg.type]:
                del lastreaded[reg.type][reg]
            if reg in lastdefread[reg.type]:
                del lastdefread[reg.type][reg]

        def update_dictionaries(instr):
            """

            :param instr:

            """

            for reg, arch_operands in zip(
                instr.operand_fields(), instr.architecture_type.operands()
            ):
                operand, ins_input, output = arch_operands
                if reg is not None and not operand.immediate():

                    if ins_input and output:
                        lastdefread[reg.type][reg] += 1
                        if reg in lastdefined[reg.type]:
                            del lastdefined[reg.type][reg]
                        if reg in lastreaded[reg.type]:
                            del lastreaded[reg.type][reg]
                        if lastdefread[reg.type][reg] == self._rdwr:
                            remove_dict_key(reg)
                    elif output:
                        lastdefined[reg.type][reg] += 1
                        if reg in lastdefread[reg.type]:
                            del lastdefread[reg.type][reg]
                        if reg in lastreaded[reg.type]:
                            del lastreaded[reg.type][reg]
                        if lastdefined[reg.type][reg] == self._writes:
                            remove_dict_key(reg)
                    elif ins_input:
                        if reg in lastreaded[reg.type]:
                            lastreaded[reg.type][reg] += 1
                            if lastreaded[reg.type][reg] == self._reads:
                                remove_dict_key(reg)
                        if reg in lastdefined[reg.type]:
                            del lastdefined[reg.type][reg]
                        if reg in lastdefread[reg.type]:
                            del lastdefread[reg.type][reg]

        def update_group(group):
            """

            :param group:

            """
            for instr in group:
                instroperands = []
                oper_idx_io = 0
                oper_idx_i = 0
                oper_idx_o = 0
                for operand, ins_input, output in instr.operands():

                    if operand.immediate():

                        if self._immediate is not "random" and \
                                operand.check(self._immediate, safe=True):

                            instroperands.append(self._immediate)

                        elif self._immediate is not "random" and \
                                not operand.check(self._immediate, safe=True):

                            instroperands.append(operand.max)

                        else:

                            instroperands.append(
                                operand.assembly(
                                    operand.random_value()
                                )
                            )

                    elif not operand.immediate():

                        regs = list(operand.values())
                        rtype = regs[0].type

                        if ins_input and output:

                            regs = [
                                elem
                                for elem in lastdefread[rtype].keys()
                                if elem in regs
                            ]
                            regs.sort(
                                key=lambda x,
                                ltype=rtype: lastdefread[ltype][x],
                                reverse=True)
                            reg = regs[oper_idx_io]

                            if reg in lastreaded[rtype]:

                                del lastreaded[rtype][reg]

                            if reg in lastdefined[rtype]:

                                del lastdefined[rtype][reg]

                            oper_idx_io += 1

                        elif ins_input:

                            regs = [
                                elem
                                for elem in lastreaded[rtype].keys()
                                if elem in regs
                            ]
                            regs.sort(
                                key=lambda x,
                                ltype=rtype: lastreaded[ltype][x],
                                reverse=True)
                            reg = regs[oper_idx_i]
                            if reg in lastdefread[rtype]:
                                del lastdefread[rtype][reg]
                            if reg in lastdefined[rtype]:
                                del lastdefined[rtype][reg]
                            oper_idx_i += 1

                        elif output:

                            regs = [
                                elem
                                for elem in lastdefined[rtype].keys()
                                if elem in regs
                            ]
                            regs.sort(
                                key=lambda x,
                                ltype=rtype: lastdefined[ltype][x],
                                reverse=True)
                            reg = regs[oper_idx_o]
                            if reg in lastdefread[rtype]:
                                del lastdefread[rtype][reg]
                            if reg in lastreaded[rtype]:
                                del lastreaded[rtype][reg]
                            oper_idx_o += 1
                        else:
                            assert False, "Something wrong"

                        instroperands.append(reg)

                instr.set_operands(instroperands)
                instr.check()
                update_dictionaries(instr)

        idx = 0
        group = []
        reset_dictionaries()
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                update_dictionaries(instr)
                group.append(instr)
                if idx % self._size == (self._size - 1):
                    update_group(group)
                    group = []
                    lastdefined = {}
                    lastreaded = {}
                    lastdefread = {}
                    reset_dictionaries()

                idx = idx + 1
            if len(group) > 0:
                update_group(group)
                group = []
                lastdefined = {}
                lastreaded = {}
                lastdefread = {}
                reset_dictionaries()

        return []


class NoHazardsAllocationPass(microprobe.passes.Pass):
    """Avoid all possible data hazards:

    read after write (RAW), a true dependency
    write after read (WAR), an anti-dependency
    write after write (WAW), an output dependency


    """

    def __init__(self):
        """ """
        super(NoHazardsAllocationPass, self).__init__()
        self._description = "Perform register allocation avoiding RAW, WAR "\
                            "and WAR dependency hazards"

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        rregs = set(building_block.context.reserved_registers)

        inputs = set()
        inputoutputs = set()
        outputs = set()

        LOG.debug("-" * 80)
        LOG.debug("BEGIN")
        LOG.debug("Inputs: %s", inputs)
        LOG.debug("InputsOutputs: %s", inputoutputs)
        LOG.debug("Outputs: %s", outputs)
        LOG.debug("Reserved %s", rregs)
        LOG.debug("-" * 80)

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                for operand in instr.operands():

                    if operand.type.immediate:
                        continue

                    if isinstance(operand.value, Address):
                        continue

                    if operand.value is None and \
                            len(list(operand.type.values())) > 1:
                        continue

                    if len(list(operand.type.values())) == 1:
                        operand.set_value(list(operand.type.values())[0])

                    skip = False
                    for reg in operand.uses():
                        if operand.value in rregs:
                            skip = True
                            break

                    for reg in operand.sets():
                        if operand.value in rregs:
                            skip = True
                            break

                    if skip:
                        continue

                    if operand.is_input and operand.is_output:
                        for reg in operand.sets():
                            inputoutputs.add(reg)
                        for reg in operand.uses():
                            inputoutputs.add(reg)
                    elif operand.is_input:
                        for reg in operand.uses():
                            inputs.add(reg)
                    elif operand.is_output:
                        for reg in operand.sets():
                            outputs.add(reg)

        LOG.debug("-" * 80)
        LOG.debug("OPERANDS SETS PROCESSED")
        LOG.debug("Inputs: %s", inputs)
        LOG.debug("InputsOutputs: %s", inputoutputs)
        LOG.debug("Outputs: %s", outputs)
        LOG.debug("Reserved %s", rregs)
        LOG.debug("-" * 80)

        # Minimum allocation, make everybody happy with enough operand
        # values
        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                for operand in instr.operands():

                    if operand.type.immediate:
                        continue

                    if operand.value is not None:
                        continue

                    regs = set(operand.type.values())
                    values = set()

                    for reg in regs:

                        if len(
                            rregs.intersection(
                                operand.type.access(reg)
                            )
                        ) > 0:
                            continue

                        values.add(reg)

                    # values.difference_update(rregs)

                    if operand.is_input and operand.is_output:

                        # values.difference_update(inputoutputs)
                        values.difference_update(inputs)
                        values.difference_update(outputs)

                        if len(values) > 0:

                            for value in values:

                                valid_val = True
                                to_add = []

                                for val in operand.type.access(value):

                                    to_add.append(val)

                                    if val in inputs or val in outputs:
                                        valid_val = False

                                if valid_val:

                                    inputoutputs.update(set(to_add))
                                    break

                    elif operand.is_output:

                        values.difference_update(inputoutputs)
                        values.difference_update(inputs)
                        values.difference_update(outputs)

                        if len(values) > 0:

                            for value in values:

                                valid_val = True
                                to_add = []

                                for val in operand.type.access(value):

                                    to_add.append(val)

                                    if (
                                        val in inputoutputs or val in inputs or
                                        val in outputs
                                    ):
                                        valid_val = False

                                if valid_val:

                                    outputs.update(set(to_add))
                                    break

                    elif operand.is_input:

                        values.difference_update(inputoutputs)
                        # values.difference_update(inputs)
                        values.difference_update(outputs)

                        if len(values) > 0:

                            for value in values:

                                valid_val = True

                                to_add = []
                                for val in operand.type.access(value):

                                    to_add.append(val)

                                    if val in inputoutputs or val in outputs:
                                        valid_val = False

                                if valid_val:
                                    inputs.update(set(to_add))
                                    break

                    else:
                        raise MicroprobeCodeGenerationError(
                            "Unknown operand type"
                        )

        inputs = sorted(list(inputs))
        inputoutputs = sorted(list(inputoutputs))
        outputs = sorted(list(outputs))

        LOG.debug("-" * 80)
        LOG.debug("BEFORE ALLOCATING")
        LOG.debug("Inputs: %s", inputs)
        LOG.debug("InputsOutputs: %s", inputoutputs)
        LOG.debug("Outputs: %s", outputs)
        LOG.debug("Reserved %s", rregs)
        LOG.debug("-" * 80)

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                LOG.debug("#" * 80)
                LOG.debug("BEGIN INSTRUCTION %s", instr.name)
                LOG.debug("Inputs: %s", inputs)
                LOG.debug("InputsOutputs: %s", inputoutputs)
                LOG.debug("Outputs: %s", outputs)
                LOG.debug("Reserved %s", rregs)

                for operand in instr.operands():

                    LOG.debug("-" * 80)
                    LOG.debug("BEGIN OPERAND")
                    LOG.debug(operand)
                    LOG.debug("Inputs: %s", inputs)
                    LOG.debug("InputsOutputs: %s", inputoutputs)
                    LOG.debug("Outputs: %s", outputs)
                    LOG.debug("Reserved %s", rregs)

                    LOG.debug("BEGIN OPERAND")

                    if operand.type.immediate:
                        LOG.debug("IMMEDIATE")
                        continue

                    if isinstance(operand.value, Address):
                        LOG.debug("ADDRESS")
                        continue

                    if operand.type.constant:
                        LOG.debug("CONSTANT")

                        value = list(operand.type.values())[0]
                        operand.set_value(value)

                        # Update queues
                        for value in operand.type.access(operand.value):

                            if value in inputoutputs:
                                inputoutputs.remove(value)
                                inputoutputs.append(value)
                            elif value in inputs:
                                if operand.is_output:
                                    inputs.remove(value)
                                    inputoutputs.append(value)
                                else:
                                    inputs.remove(value)
                                    inputs.append(value)
                            elif value in outputs:
                                if operand.is_input:
                                    outputs.remove(value)
                                    inputoutputs.append(value)
                                else:
                                    outputs.remove(value)
                                    outputs.append(value)

                        continue

                    if operand.is_input and operand.is_output:
                        queue = inputoutputs
                    elif operand.is_input:
                        queue = inputs
                    elif operand.is_output:
                        queue = outputs

                    if len(queue) == 0:
                        queue = inputoutputs

                    if operand.value is not None:
                        LOG.debug("ALREADY SET")
                        LOG.debug("Set value: %s", operand.value)

                        for value in operand.type.access(operand.value):
                            if value not in rregs and value in queue:

                                queue.remove(value)
                                queue.append(value)

                            elif value not in rregs and \
                                    value in inputs:

                                inputs.remove(value)
                                inputs.append(value)

                            elif value not in rregs and \
                                    value in outputs:

                                outputs.remove(value)
                                outputs.append(value)

                            elif value not in rregs and \
                                    value in inputoutputs:

                                inputoutputs.remove(value)
                                inputoutputs.append(value)

                        continue

                    # get the operand type
                    regt = list(operand.type.values())[0].type

                    LOG.debug("NOT SET")
                    LOG.debug("TYPE: %s", regt)

                    regs = [
                        reg
                        for reg in queue
                        if reg.type == regt and
                        reg in list(operand.type.values())
                    ]

                    # if values are not found, fail-back to input output list
                    if len(regs) == 0:
                        LOG.debug("SWITCH!")
                        LOG.debug(queue)
                        LOG.debug(inputoutputs)
                        queue = inputoutputs
                        regs = [
                            reg
                            for reg in queue
                            if reg.type == regt and
                            reg in list(operand.type.values())
                        ]

                    # Check if all possible values are reserved, if so, just
                    # pick one and add a comment
                    if (
                        set(operand.type.values()).issubset(rregs) and
                        len(regs) == 0
                    ):
                        operand.set_value(list(operand.type.values())[0])
                        LOG.debug("Operand forced to: %s",
                                  list(operand.type.values())[0])
                        instr.add_comment(
                            "Operand '%s' using reserved value" %
                            operand)
                        if not instr.allows(list(operand.type.values())[0]):
                            instr.add_allow_register(
                                list(operand.type.values())[0])
                        continue
                    elif len(regs) == 0:
                        LOG.debug("Operand forced to: %s",
                                  list(operand.type.values())[0])
                        operand.set_value(list(operand.type.values())[0])
                        instr.add_comment(
                            "Operand '%s' using first value" % operand)
                        if not instr.allows(list(operand.type.values())[0]):
                            instr.add_allow_register(
                                list(operand.type.values())[0])
                        continue

                    if len(regs) == 0:
                        # Fall-back in case not regs are provided
                        regs = list(operand.type.values())

                    LOG.debug("Operand set to: %s", regs[0])
                    operand.set_value(regs[0])

                    for value in operand.type.access(operand.value):

                        if value in inputoutputs:
                            inputoutputs.remove(value)

                        if value in inputs:
                            inputs.remove(value)

                        if value in outputs:
                            outputs.remove(value)

                        queue.append(value)

                    LOG.debug("*" * 80)


class FixRegistersPass(microprobe.passes.Pass):
    """DefaultRegisterAllocationPass pass.

    """

    def __init__(self, forbid_writes=None, forbid_reads=None):
        """ """
        super(FixRegistersPass, self).__init__()
        self._description = "Fix readed/written register"
        self._writes = forbid_writes
        self._reads = forbid_reads

    def __call__(self, building_block, target):

        if self._writes is not None:
            self._writes = [target.registers[regname]
                            for regname in self._writes]

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                for operand in instr.operands():

                    if self._writes is not None:
                        sets = operand.sets()
                        for elem in sets:
                            if elem in self._writes:
                                operand.unset_value()

                    if self._reads is not None:
                        uses = operand.sets()
                        for elem in uses:
                            if elem in self._reads:
                                operand.unset_value()


class RandomAllocationPass(microprobe.passes.Pass):
    """RandomAllocationPass pass.

    """

    def __init__(self):
        """ """
        super(RandomAllocationPass, self).__init__()
        self._description = "Random Allocation of operands"

    def __call__(self, building_block, dummy_target):

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                for operand in instr.operands():
                    operand.set_value(operand.type.random_value())

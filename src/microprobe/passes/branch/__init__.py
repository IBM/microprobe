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
""":mod:`microprobe.passes.branch` module

"""
# Futures
from __future__ import absolute_import

# Built-in modules
import collections
import itertools

# Third party modules

# Own modules
from microprobe.code.address import InstructionAddress
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.passes import Pass
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict


# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = ['BranchNextPass',
           'FixIndirectBranchPass',
           'InitializeBranchDecorator',
           "LinkBbls"]

# Functions


# Classes
class BranchNextPass(Pass):
    """BranchNextPass pass.

    """

    def __init__(self, branch=None, force=False):
        """

        :param branch:  (Default value = None)

        """
        super(BranchNextPass, self).__init__()
        self._description = "Set the branch target of each branch to the " \
                            "next instruction."
        self._branch = branch
        self._force = force
        if branch is not None:
            self._description += "Only model '%s'" % branch

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        if not building_block.context.register_has_value(0):
            reg = target.get_register_for_address_arithmetic(
                building_block.context
            )
            building_block.add_init(
                target.set_register(
                    reg, 0, building_block.context
                )
            )
            building_block.context.set_register_value(reg, 0)
            building_block.context.add_reserved_registers([reg])

        counter = 0
        all_counter = 0
        rregs = 0
        labels = []

        label_instruction_map = {}

        instr_ant = None

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                if instr_ant is None:
                    instr_ant = instr

                    if instr.label is None:
                        first_label = "first"
                        instr.set_label("first")
                        label_instruction_map[first_label] = instr
                    else:
                        first_label = instr.label
                        label_instruction_map[first_label] = instr

                    continue

                if not instr_ant.branch:
                    instr_ant = instr
                    continue

                if self._branch is not None and \
                        instr_ant.name != self._branch:
                    instr_ant = instr
                    continue

                LOG.debug("Setting target for branch: '%s'", instr_ant)
                target_set = False

                for memoperand in instr_ant.memory_operands():

                    if not memoperand.descriptor.is_branch_target:
                        continue

                    if memoperand.address is not None and not self._force:
                        continue

                    if target_set:
                        continue

                    LOG.debug("Computing label")

                    if instr_ant.branch_relative:

                        if instr.label is None:
                            label = "rel_branch_%d" % all_counter
                            instr.set_label(label)
                            LOG.debug(
                                "Branch relative, new label: '%s'", label
                            )
                        else:
                            label = instr.label
                            LOG.debug(
                                "Branch relative, existing label: '%s'", label
                            )

                    elif rregs < 5:

                        if instr.label is None:
                            label = "abs_branch_%d" % counter
                            labels.append(label)
                            instr.set_label(label)
                            LOG.debug(
                                "Branch absolute, new label: '%s'", label
                            )
                        else:
                            label = instr.label
                            LOG.debug(
                                "Branch absolute, exiting label: '%s'", label
                            )

                        label_instruction_map[label] = instr
                    else:
                        label = labels[counter % 5]

                    assert label is not None

                    taddress = InstructionAddress(base_address=label)

                    if instr_ant.branch_relative:
                        taddress.set_target_instruction(instr)
                    else:
                        taddress.set_target_instruction(
                            label_instruction_map[label]
                        )

                    try:
                        memoperand.set_address(
                            taddress, building_block.context
                        )
                        target_set = True
                        instr_ant.add_comment("Branch fixed to: %s" % taddress)

                    except MicroprobeCodeGenerationError:

                        reg = \
                            target.get_register_for_address_arithmetic(
                                building_block.context)
                        building_block.add_init(
                            target.set_register_to_address(
                                reg, taddress, building_block.context
                            )
                        )
                        building_block.context.set_register_value(
                            reg, taddress
                        )

                        building_block.context.add_reserved_registers([reg])

                        memoperand.set_address(
                            taddress, building_block.context
                        )

                        rregs += 1
                        target_set = True
                        instr_ant.add_comment("Branch fixed to: %s" % taddress)

                if not instr_ant.branch_relative:
                    counter += 1
                else:
                    all_counter += 1

                instr_ant = instr

        bbl = building_block.cfg.bbls[-1]
        if bbl.instrs[-1].branch:
            LOG.debug("Last instruction is a BRANCH: %s", bbl.instrs[-1])
            for memoperand in bbl.instrs[-1].memory_operands():

                if not memoperand.descriptor.is_branch_target:
                    continue

                if memoperand.address is not None and not self._force:
                    continue

                target_set = False
                for operand in memoperand.operands:
                    if operand.value is not None and not self._force:
                        target_set = True
                        break

                if target_set:
                    continue

                if (len(building_block.fini) >
                        0 and bbl.instrs[-1].branch_relative):

                    if building_block.fini[0].label is None:
                        label = "rel_branch_%d" % all_counter
                        building_block.fini[0].set_label(label)
                    else:
                        label = building_block.fini[0].label

                    taddress = InstructionAddress(base_address=label)
                    taddress.set_target_instruction(
                        label_instruction_map[first_label]
                    )
                else:
                    assert first_label is not None

                    taddress = InstructionAddress(base_address=first_label)
                    taddress.set_target_instruction(
                        label_instruction_map[first_label]
                    )

                try:
                    memoperand.set_address(
                        taddress, building_block.context
                    )
                except MicroprobeCodeGenerationError:

                    reg = \
                        target.get_register_for_address_arithmetic(
                            building_block.context)
                    building_block.add_init(
                        target.set_register_to_address(
                            reg, taddress, building_block.context
                        )
                    )
                    building_block.context.set_register_value(
                        reg, taddress
                    )

                    building_block.context.add_reserved_registers([reg])

                    memoperand.set_address(
                        taddress, building_block.context
                    )

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        pass_ok = True
        for bbl in building_block.cfg.bbls:
            instr_ant = None

            for instr in bbl.instrs:

                if instr_ant is None:
                    instr_ant = instr
                    continue

                if not instr_ant.branch:
                    instr_ant = instr
                    continue

                pass_ok = pass_ok and instr.label != ""

                for memoperand in instr_ant.memory_operands():

                    if not memoperand.descriptor.is_branch_target:
                        continue

                    taddress = InstructionAddress(base_address=instr.label)
                    pass_ok = pass_ok and memoperand.address == taddress

                instr_ant = instr

        return pass_ok


class FixIndirectBranchPass(Pass):
    """FixIndirectBranchPass pass.

    """

    def __init__(self):
        """

        """
        super(FixIndirectBranchPass, self).__init__()
        self._description = "Fix indirect branches or replace them by "\
            "regular branch to next"

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        for bbl in building_block.cfg.bbls:

            instr_ant = None

            for instr in bbl.instrs:

                if instr_ant is None:
                    instr_ant = instr

                if not instr_ant.branch:
                    instr_ant = instr
                    continue

                target_set, branch_operand = self.check_branch(instr_ant)

                if target_set:
                    instr_ant = instr
                    continue

                if branch_operand:
                    raise NotImplementedError
                else:
                    self._fix_branch(instr_ant, instr, target)

                instr_ant = instr

        last_ins = building_block.cfg.bbls[-1].instrs[-1]

        if not last_ins.branch:
            return

        target_set, branch_operand = self.check_branch(instr_ant)

        if target_set:
            return

        if branch_operand:
            raise NotImplementedError
        else:
            first_ins = building_block.cfg.bbls[0].instrs[0]
            self._fix_branch(last_ins, first_ins, target)

    @staticmethod
    def check_branch(local_instr):
        """

        :param local_instr:
        :type local_instr:
        """

        target_set = False
        branch_operand = False

        for memoperand in local_instr.memory_operands():

            if not memoperand.descriptor.is_branch_target:
                continue

            branch_operand = True

            if memoperand.address is not None:
                target_set = True

        return target_set, branch_operand

    @staticmethod
    def _fix_branch(instr_ant, instr, target):
        """

        :param local_instr:
        :type local_instr:
        """

        new_branch = target.branch_unconditional_relative(
            instr_ant.address, instr.address
        )

        instr_ant.set_arch_type(new_branch.architecture_type)
        instr_ant.set_operands([op.value for op in new_branch.operands()])


class LinkBbls(Pass):
    """LinkBbls pass.

    """

    def __init__(self):
        """

        """
        super(LinkBbls, self).__init__()
        self._description = "Add unconditional branch between consecutive" \
            " instructions without consecutive addresses if first " \
            "instruction is not a branch"

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        for bbl in building_block.cfg.bbls:

            instr_ant = None

            for instr in bbl.instrs:

                if instr_ant is None:
                    instr_ant = instr
                    continue

                if instr_ant.branch:
                    instr_ant = instr
                    continue

                if instr_ant.address is None:
                    instr_ant = instr
                    continue

                if instr.address is None:
                    instr_ant = instr
                    continue

                if ((instr_ant.architecture_type.format.length +
                     instr_ant.address) == instr.address):
                    instr_ant = instr
                    continue

                ninstr = target.branch_unconditional_relative(
                    instr_ant.architecture_type.format.length +
                    instr_ant.address, instr)

                ninstr.add_comment("LINKBBL ADDED")

                building_block.add_instructions([ninstr],
                                                after=instr_ant,
                                                before=instr)
                instr_ant = instr


class InitializeBranchDecorator(Pass):
    """InitializeBranchDecoratorPass pass.

    """

    _error_class = collections.namedtuple("LateErrorClass", ['next'])

    def __init__(self, default=None, indirect=None):

        self._default = default
        self._indirect = indirect

        self._description = "Initialize branch decorator. Default: %s . " \
            "Indirect: %s" % (self._default, self._indirect)

    def __call__(self, building_block, dummy_target):

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                if not (instr.branch or instr.trap):
                    continue

                if "BP" not in instr.decorators and instr.branch_conditional:
                    instr.add_decorator("BP", self._default)
                elif "BP" not in instr.decorators:
                    instr.add_decorator("BP", "T")

                pattern = instr.decorators["BP"]["value"]

                target_addr = None
                for memoper in instr.memory_operands():
                    if isinstance(memoper.address, InstructionAddress):
                        target_addr = memoper.address
                        break

                if target_addr is None:
                    for oper in instr.operands():
                        if isinstance(oper.value, InstructionAddress):
                            target_addr = oper.value
                            break

                if target_addr is None:
                    if "BT" in instr.decorators:
                        target_addr = instr.decorators["BT"]['value']
                    else:
                        target_addr = self._indirect
                else:
                    if "BT" in instr.decorators:
                        bt_addr = [
                            int(elem, 16) for elem
                            in instr.decorators["BT"]['value']
                        ]

                        if building_block.context.code_segment is not None:
                            bt_addr = [
                                elem - building_block.context.code_segment
                                for elem in bt_addr
                            ]

                        if instr.branch_conditional:
                            # Remove not taken branch addresses
                            bt_addr = [
                                elem for elem in bt_addr
                                if elem !=
                                instr.address.displacement +
                                instr.architecture_type.format.length
                            ]

                        # TODO: This code assumes branch there are
                        # no conditional branch indirect branches
                        if len(set(bt_addr)) > 1:
                            raise MicroprobeCodeGenerationError(
                                "BT decorator with multiple targets "
                                "defined but instruction '%s' already"
                                " defines the target in its codification."
                                % (instr.assembly())
                            )
                        elif len(set(bt_addr)) == 1:
                            bt_addr = bt_addr[0]

                            if "EA" in instr.decorators:
                                # if each in decorator, we are dealing
                                # with real addresses. No check for
                                # mismatch.
                                #
                                # TODO: Check that 'translated' addresses
                                # mismatch or enaure we always deal with
                                # logic addresses
                                #
                                LOG.warning(
                                    "Not checking for address missmatches"
                                )
                            elif bt_addr != target_addr.displacement:
                                raise MicroprobeCodeGenerationError(
                                    "BT decorator specified for "
                                    "instruction '%s' "
                                    "but it already provides "
                                    "the target in its "
                                    "codification and they miss-match!"
                                    % (instr.assembly())
                                )
                        instr.decorators.pop("BT")

                if not instr.branch_conditional and 'N' in pattern:
                    raise MicroprobeCodeGenerationError(
                        "Not take branch pattern provided for an "
                        "unconditional branch '%s'" % instr.assembly()
                    )

                if pattern is None:

                    def function_pattern():
                        raise MicroprobeCodeGenerationError(
                            "No branch pattern provided for branch '%s'" %
                            instr.assembly()
                        )

                    pattern_error = self._error_class(function_pattern)
                    instr.add_decorator("NI", pattern_error)
                    continue

                if target_addr is None:

                    def function_target_addr():
                        raise MicroprobeCodeGenerationError(
                            "No target address provided for branch '%s'" %
                            instr.assembly()
                        )

                    target_addr_error = self._error_class(function_target_addr)
                    instr.add_decorator("NI", target_addr_error)
                    continue

                if not isinstance(target_addr, list):
                    target_addr = [target_addr]

                for idx, address in enumerate(target_addr):

                    if isinstance(address, str):
                        address = int(address, 16)

                    if not isinstance(address, InstructionAddress):

                        code = 0
                        if building_block.context.code_segment is not None:
                            code = building_block.context.code_segment

                        target_addr[idx] = InstructionAddress(
                            base_address="code",
                            displacement=address -
                            code)

                next_address = instr.address + \
                    instr.architecture_type.format.length

                def pattern_gen(lnext_address, lpattern, ltarget_addr):

                    target_iter = itertools.cycle(list(lpattern))
                    taken_target_address = itertools.cycle(ltarget_addr)

                    while True:
                        if next(target_iter) is 'N':
                            yield lnext_address
                        else:
                            yield next(taken_target_address)

                instr.add_decorator(
                    "NI", itertools.cycle(
                        pattern_gen(next_address,
                                    pattern, target_addr)))


class NormalizeBranchTargetsPass(Pass):
    """NormalizeBranchTargetsPass pass.

    """

    def __init__(self):
        """ """
        super(NormalizeBranchTargetsPass, self).__init__()
        self._description = "Normalize branch targets to remove the usage" \
            "of labels"
        self._labels = RejectingDict()

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for instr in (elem for elem in building_block.init
                      if elem.label is not None):
            self._register_label(instr)

        for bbl in building_block.cfg.bbls:
            for instr in (elem for elem in bbl.instrs
                          if elem.label is not None):
                self._register_label(instr)

        for instr in (elem for elem in building_block.fini
                      if elem.label is not None):
            self._register_label(instr)

        for instr in building_block.init:
            self._normalize_label(instr)

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                self._normalize_label(instr)

        for instr in building_block.fini:
            self._normalize_label(instr)

        return []

    def _register_label(self, instruction):
        """

        :param instruction:

        """
        if instruction.label is None:
            return
        else:
            self._labels[instruction.label.upper()] = instruction

    def _normalize_label(self, instruction):
        """

        :param instruction:
        :param context:

        """

        for operand in instruction.operands():

            if operand.value is None:
                continue

            if not isinstance(operand.value, InstructionAddress):
                continue

            address = operand.value
            LOG.debug(
                "Normalizing label: '%s' of instruction '%s'", address,
                instruction.name
            )

            if address.target_instruction is not None:

                target_address = address.target_instruction.address

            elif (
                isinstance(address.base_address, str) and
                address.base_address.upper() in list(self._labels.keys())
            ):

                target_address = self._labels[
                    address.base_address.upper()].address + \
                    address.displacement

            else:
                LOG.critical(address.base_address)
                LOG.critical(address)
                LOG.critical(list(self._labels.keys()))
                raise NotImplementedError

            operand.set_value(target_address)

        for moperand in instruction.memory_operands():

            if moperand.address is None:
                continue

            if not isinstance(moperand.address, InstructionAddress):
                continue

            address = moperand.address
            LOG.debug(
                "Normalizing label: '%s' of instruction '%s'", address,
                instruction.name
            )

            if address.target_instruction is not None:

                target_address = address.target_instruction.address

            elif (
                isinstance(address.base_address, str) and
                address.base_address.upper() in list(self._labels.keys())
            ):

                target_address = self._labels[
                    address.base_address.upper()].address + \
                    address.displacement

            else:
                LOG.critical(address.base_address)
                LOG.critical(address)
                LOG.critical(list(self._labels.keys()))
                raise NotImplementedError

            moperand.update_address(target_address)

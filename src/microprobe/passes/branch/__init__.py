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
import copy
import re

# Third party modules

# Own modules
from microprobe.code.address import InstructionAddress
from microprobe.code.ins import Instruction, \
    instruction_set_def_properties
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeUncheckableEnvironmentWarning
from microprobe.passes import Pass
from microprobe.utils.asm import interpret_asm
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict, RNDINT
from microprobe.utils.distrib import probability, regular_probability


# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = ['BranchNextPass',
           'BranchBraidNextPass',
           'FixIndirectBranchPass',
           'InitializeBranchDecorator',
           'RandomizeByTypePass',
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


class BranchBraidNextPass(Pass):
    """BranchBraidNextPass pass.

    """

    def __init__(self, branch=None, force=False, bbl=20):
        """

        """
        super(BranchBraidNextPass, self).__init__()
        self._description = "Set the branch target of each branch to the " \
                            "next instruction but replicating the code " \
                            "creating a braid in execution."
        self._branch = branch
        self._force = force
        self._bbl = bbl
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
        first_branch_hit = False

        new_instructions = []
        current_bbl = []
        last_braid = None
        last_bbl_head = None
        first_braid = None

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
                    if first_branch_hit:
                        current_bbl.append(instr_ant)
                    instr_ant = instr
                    continue

                if self._branch is not None and \
                        instr_ant.name != self._branch:
                    if first_branch_hit:
                        current_bbl.append(instr_ant)
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

                if first_branch_hit:
                    current_bbl.append(instr_ant)

                if not first_branch_hit:
                    first_braid = instr_ant

                new_instructions.append(current_bbl)
                last_braid = instr_ant
                last_bbl_head = instr
                current_bbl = []

                first_branch_hit = True

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

        base_instructions = []
        for elem in new_instructions:
            if len(elem) == 0:
                continue
            base_instructions.append(elem[:])

        new_instructions = [
            elem for elem in new_instructions if len(elem) > 0
        ]

        for idx, elem in enumerate(new_instructions):
            if len(elem) == 0:
                continue
            new_instructions[idx] = [instr.copy() for instr in elem]

        assert len(base_instructions) == len(new_instructions)

        for elem in new_instructions:
            for elem2 in elem:
                elem2.add_comment("Braid instruction")

        def flatten(lst):
            return [item for sublist in lst for item in sublist]

        basel = []
        newl = []

        if first_braid is not None:
            basel.append(first_braid)
            newl.append(first_braid)

        basel.extend(flatten(base_instructions))
        newl.extend(flatten(new_instructions))

        if last_bbl_head is not None:
            basel.append(last_bbl_head)
            newl.append(last_bbl_head)

        # Fix labels and braid the branches
        translated_labels = {}
        for idx, (base, new) in enumerate(zip(basel, newl)):
            if base.label is None:
                continue

            if not base.label.startswith("rel_branch"):
                # This has a label, need to be fixed on new
                new.set_label("%s_braid" % base.label)
                translated_labels[base.label] = "%s_braid" % base.label
                continue

            # Braid the branches
            jbase = basel[idx-1]
            jnew = newl[idx-1]

            new.set_label("%s_2" % new.label)

            for memoperand in jbase.memory_operands():
                if not memoperand.descriptor.is_branch_target:
                    continue
                if not jbase.branch_relative:
                    continue
                taddress = InstructionAddress(base_address=new.label)
                taddress.set_target_instruction(new)
                memoperand.set_address(
                    taddress, building_block.context
                )

            if jbase is not jnew:

                if base is not new:
                    base.set_label("%s_1" % base.label)

                for memoperand in jnew.memory_operands():
                    if not memoperand.descriptor.is_branch_target:
                        continue
                    if not jnew.branch_relative:
                        continue
                    taddress = InstructionAddress(base_address=base.label)
                    taddress.set_target_instruction(base)
                    memoperand.set_address(
                        taddress, building_block.context
                    )

        for nins in newl:
            # Some operands of new instructions might refer to
            # translated labels. Update them.
            values = [oper.value for oper in nins.operands()]
            for idx, val in enumerate(values):
                if not isinstance(val, str):
                    continue
                translated = False
                for label in translated_labels:
                    for pattern in ["\\(%s\\)$", "^%s$"]:
                        bpattern = pattern % label
                        npattern = pattern % translated_labels[label]
                        npattern = npattern.replace("\\", "")
                        npattern = npattern.replace("^", "")
                        npattern = npattern.replace("$", "")
                        if re.search(bpattern, val):
                            val = re.sub(bpattern, npattern, val)
                            nins.operands()[idx].set_value(val, check=False)
                            translated = True
                            break
                    if translated:
                        break

        chunks = list(enumerate(zip(base_instructions, new_instructions)))

        for chunk in [chunks[i:i + self._bbl]
                      for i in range(0, len(chunks), self._bbl)]:
            bins = flatten([chk[1][0] for chk in chunk])
            nins = flatten([chk[1][1] for chk in chunk])

            assert len(bins) == len(nins)

            after_instr = bins[-1]
            lidx = chunk[-1][0]

            if lidx+1 >= len(chunks):
                before_instr = last_bbl_head
            else:
                before_instr = chunks[lidx+1][1][0][0]

            taddress = InstructionAddress(base_address=before_instr.label)
            taddress.set_target_instruction(before_instr)

            new_branch = target.branch_unconditional_relative(
                after_instr.architecture_type.format.length +
                after_instr.address, taddress
            )
            new_branch.add_comment("Jump to synch braid")

            building_block.add_instructions(
                [new_branch] + nins,
                after=after_instr,
                before=before_instr
            )

        # taddress = InstructionAddress(base_address=last_bbl_head.label)
        # taddress.set_target_instruction(last_bbl_head)
        # new_branch = target.branch_unconditional_relative(
        #    last_braid.architecture_type.format.length +
        #     last_braid.address, taddress
        # )
        # new_branch.add_comment("Branch to latest braid BBL")

        # new_instructions = [new_branch] # + new_instructions
        # building_block.add_instructions(new_instructions,
        #                                 after=last_braid,
        #                                before=last_bbl_head)

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

                self._fix_branch(instr_ant, instr, target)

                instr_ant = instr

        last_ins = building_block.cfg.bbls[-1].instrs[-1]

        if not last_ins.branch:
            return

        target_set, branch_operand = self.check_branch(instr_ant)

        if target_set:
            return
        else:
            # Last instruction is a branch without a target set.
            # Change to nop
            first_ins = building_block.cfg.bbls[0].instrs[0]
            self._fix_branch(last_ins, first_ins, target)
            last_ins.set_arch_type(target.nop().architecture_type)
            last_ins.set_operands([op.value for op in target.nop().operands()])

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

            operands = [operand for operand in memoperand.operands
                        if operand.type.address_base or
                        operand.type.address_index]
            branch_operand = len(operands) > 0

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

                if not (instr.branch or instr.trap or instr.syscall):
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
                    if (target_addr - instr.address ==
                            instr.architecture_type.format.length and
                            "T" not in pattern):
                        # This is taken branch to next instruction
                        pass
                    else:
                        raise MicroprobeCodeGenerationError(
                            "Not taken branch pattern provided for an "
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


class RandomizeByTypePass(Pass):
    """RandomizeByTypePass pass.

    """

    def __init__(self, instr1, instr2,
                 every, code, distance=1,
                 musage=None, reset=None):
        """
        :param instr1:
        :param instr2:
        :param every:

        """
        super(RandomizeByTypePass, self).__init__()

        if not isinstance(instr1, list):
            instr1 = [instr1]

        self._instr1 = instr1
        self._instr2 = instr2

        if every <= 0:
            fevery = None
        elif every >= 1:
            fevery = regular_probability(int(every))
        else:
            fevery = probability(every)

        self._every = fevery

        if distance < 1:
            raise MicroprobeCodeGenerationError(
                "Dependency distance should be 1 or larger"
            )

        self._distance = int(distance)
        self._code = code
        if musage is None:
            musage = -1
        self._musage = musage
        self._reset = reset
        self._description = "Randomize '%s' by '%s' every '%d' "\
            "by adding '%s' code at distance '%d', with max reg "\
            "usage of '%s' and reset mode: '%s'" \
            % (
                [instr.name for instr in instr1],
                instr2.name, every, code, distance,
                musage, reset
            )

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        if self._every is None:
            return

        creg = None
        usereg = []
        cusage = 0
        last_branch = None
        register = None
        zero_register = None
        tregister = None

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                if not instr.branch:
                    continue

                if instr.architecture_type in self._instr1:

                    mrandom = self._every()
                    if not mrandom:
                        if instr.branch:
                            last_branch = instr
                        continue

                    instr.set_arch_type(self._instr2)
                    instr.add_comment("Randomized branch")

                    # take on operand input
                    soperand = None
                    for operand in instr.operands():
                        if not operand.is_input:
                            continue
                        if operand.type.constant:
                            continue
                        if operand.type.immediate:
                            continue
                        if operand.type.float:
                            continue
                        if operand.type.address_relative:
                            continue
                        if operand.type.address_absolute:
                            continue
                        if operand.type.address_immediate:
                            continue
                        if operand.type.address_base:
                            continue
                        if operand.type.address_index:
                            continue
                        soperand = operand
                        break

                    if soperand is None:
                        LOG.debug(
                            "Unable to randomize branch "
                            "without input register operands"
                        )
                        if instr.branch:
                            last_branch = instr
                        continue

                    values = soperand.type.values()
                    values = [val for val in values if val not in
                              building_block.context.reserved_registers
                              and val not in target.control_registers]

                    if (creg in values and creg not in usereg and
                            (cusage < self._musage or self._musage == -1)):

                        # Current register is in valid values and has not
                        # been used much, just need to set operand value and
                        # random code
                        register = creg
                    else:
                        # New register, need to reset according to settings
                        registers = [
                            val for val in values
                            if val not in usereg
                        ]
                        if len(registers) == 0:
                            raise MicroprobeCodeGenerationError(
                                "No free registers available. Change the "
                                "generation policy settings."
                            )
                        register = registers[0]
                        creg = register

                        if len(registers) < 2 and tregister is None:
                            raise MicroprobeCodeGenerationError(
                                "No free registers available. Change the "
                                "generation policy settings."
                            )

                        if tregister is None:
                            tregister = registers[1]
                            building_block.context.add_reserved_registers(
                                [tregister]
                            )

                        if self._reset is not None and self._reset[0] == "add":
                            vrange = sorted(list(self._reset[1]))
                            diff = 0
                            if vrange[0] < 0:
                                diff = vrange[0]
                            value = RNDINT(maxmin=(vrange[0], vrange[1]))
                            value = value - diff
                            nins = target.add_to_register(register, value)
                            for ins in nins:
                                ins.add_comment(
                                    "Instrunction added by "
                                    "braid pass to avoid "
                                    "convergence to zero."
                                )
                            building_block.add_fini(nins)
                        elif (self._reset is not None and
                              self._reset[0] == "rnd"):

                            vrange = sorted(list(self._reset[1]))
                            diff = 0
                            if vrange[0] < 0:
                                diff = vrange[0]
                            value = RNDINT(maxmin=(vrange[0], vrange[1]))
                            value = value - diff

                            if len(usereg) == 0:
                                # First time
                                regs = [
                                    val for val in values
                                    if val not in usereg and val not in
                                    building_block.context.reserved_registers
                                ]

                                if len(regs) < 2:
                                    raise MicroprobeCodeGenerationError(
                                        "No free registers available. "
                                        "Change the "
                                        "generation policy settings."
                                    )

                                reg = regs[1]

                                nins = target.set_register(
                                    reg, RNDINT(), building_block.context
                                )
                                for ins in nins:
                                    ins.add_comment(
                                        "Instrunction added by "
                                        "randomize pass to avoid "
                                        "convergence to zero."
                                    )
                                building_block.add_init(nins)
                                nins = target.add_to_register(reg, value)
                                for ins in nins:
                                    ins.add_comment(
                                        "Instrunction added by "
                                        "randomize pass to avoid "
                                        "convergence to zero."
                                    )
                                building_block.add_fini(nins)
                                building_block.context.add_reserved_registers(
                                    [reg]
                                )
                                random_reg = reg

                            nins = target.randomize_register(
                                register, seed=random_reg
                            )

                            for ins in nins:
                                ins.add_comment(
                                    "Instrunction added by "
                                    "randomize pass to avoid "
                                    "convergence to zero."
                                )
                            building_block.add_fini(nins)
                        else:
                            raise NotImplementedError

                    # Set operand
                    operand.set_value(tregister)
                    cusage = cusage + 1

                    if self._code is not None:
                        code = self._code.replace('@@REG@@', register.name)
                        code = code.replace('@@COUNT@@', str(cusage))
                        code = code.replace('@@BRREG@@', tregister.name)
                        instructions_def = interpret_asm(
                            code, target, building_block.labels
                        )
                        instructions = []
                        for definition in instructions_def:
                            instruction = Instruction()
                            instruction_set_def_properties(
                                instruction,
                                definition,
                                building_block=building_block,
                                target=target,
                                allowed_registers=[
                                    register.name, tregister.name
                                ]
                            )
                            instructions.append(instruction)

                        bdistance = bbl.distance(last_branch, instr)

                        if bdistance + 1 <= self._distance:
                            after_ins = last_branch
                        else:
                            after_ins = bbl.get_instruction_by_distance(
                                instr, self._distance * (-1)
                            )

                        building_block.add_instructions(
                            instructions,
                            after=after_ins,
                            before=instr
                            )

                    for operand in instr.operands():
                        if not operand.is_input:
                            continue
                        if operand.type.constant:
                            continue
                        if operand.type.immediate:
                            continue
                        if operand.type.float:
                            continue
                        if operand.type.address_relative:
                            continue
                        if operand.type.address_absolute:
                            continue
                        if operand.type.address_immediate:
                            continue
                        if operand.type.address_base:
                            continue
                        if operand.type.address_index:
                            continue
                        if operand.value is not None:
                            continue

                        if zero_register is None:
                            # Set the remaining operands to zero
                            values = operand.type.values()
                            values = [
                                val for val in values if val not in
                                building_block.context.reserved_registers
                                and val not in target.control_registers
                                and val not in usereg
                                and val not in [register, random_reg]
                            ]
                            if len(values) == 0:
                                raise MicroprobeCodeGenerationError(
                                    "No free registers available. Change the "
                                    "generation policy settings."
                                )

                            zero_register = values[0]
                            building_block.context.add_reserved_registers(
                                [zero_register]
                            )
                            nins = target.set_register(
                                zero_register, 0, building_block.context
                            )
                            for ins in nins:
                                ins.add_comment(
                                    "Instrunction added by "
                                    "randomize pass to avoid "
                                    "convergence to zero."
                                )
                            building_block.add_init(nins)

                        operand.set_value(zero_register)

                    # Use new register once one is exhausted (we can reset
                    # its value too)
                    if cusage >= self._musage:
                        usereg.append(register)
                        creg = None
                        cusage = 0

                    # reserve implicit operands (if they are not already
                    # reserved) and add them as allowed
                    for operand_descriptor in instr.implicit_operands:
                        register = list(operand_descriptor.type.values())[0]
                        instr.add_allow_register(register)

                        if operand_descriptor.is_output and register not \
                                in building_block.context.reserved_registers \
                                and register not in target.control_registers:
                            building_block.context.add_reserved_registers(
                                [register]
                            )

                    context_fix_functions = instr.check_context(
                        building_block.context
                    )
                    for context_fix_function in context_fix_functions:
                        try:
                            context_fix_function(target, building_block)
                        except MicroprobeUncheckableEnvironmentWarning as wue:
                            building_block.add_warning(str(wue))

                if instr.branch:
                    last_branch = instr

        if register is not None and register not in usereg:
            usereg.append(register)

        for register in usereg:
            building_block.context.add_reserved_registers([register])
            nins = target.set_register(
                register, RNDINT(), building_block.context
            )
            for ins in nins:
                ins.add_comment(
                    "Instrunction added by randomize pass to avoid "
                    "convergence to zero."
                )
            building_block.add_init(nins)

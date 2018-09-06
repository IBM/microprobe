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
""":mod:`microprobe.passes.symbol` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import copy
import itertools
import random

# Third party modules

# Own modules
import microprobe.code.ins
import microprobe.passes
import microprobe.utils.distrib
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import instruction_set_def_properties
from microprobe.code.var import Variable
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeUncheckableEnvironmentWarning, MicroprobeValueError
from microprobe.target.isa.instruction import InstructionType
from microprobe.utils.asm import interpret_asm
from microprobe.utils.distrib import generate_weighted_profile, \
    weighted_choice
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict, closest_divisor, \
    Progress

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = [
    'SetInstructionLabelByIndexPass',
    'ResolveSymbolicReferencesPass',
]

# Functions


# Classes
class SetInstructionLabelByIndexPass(microprobe.passes.Pass):
    """SetInstructionLabelByIndexPass pass.

    """

    def __init__(self, label, index=-1):
        """

        :param label:
        :type label:
        :param index:
        :type index:
        """

        super(SetInstructionLabelByIndexPass, self).__init__()
        self._label = label
        self._index = index

        self._description = "Set the label"

    def __call__(self, building_block, dummy_target):

        cindex = 0
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                cindex = cindex + 1
                if cindex == self._index:
                    instr.set_label(self._label)
                    return
        return


class ResolveSymbolicReferencesPass(microprobe.passes.Pass):
    """ResolveSymbolicReferencesPass pass.

    """

    def __init__(self, strict=False, instructions=None):
        """ """
        super(ResolveSymbolicReferencesPass, self).__init__()
        self._description = "Translate labels of address into values"
        self._labels = RejectingDict()
        self._strict = strict
        self._instructions = []
        if instructions is not None:
            self._instructions = instructions

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for instr in (elem for elem in building_block.init
                      if elem.label is not None):
            self._register_label(instr)

        for bbl in building_block.cfg.bbls:
            if MICROPROBE_RC['verbose']:
                progress = Progress(len(bbl.instrs),
                                    "Registering labels:")
            for instr in (elem for elem in bbl.instrs
                          if elem.label is not None):
                self._register_label(instr)

                if MICROPROBE_RC['verbose']:
                    progress()

        for instr in (elem for elem in building_block.fini
                      if elem.label is not None):
            self._register_label(instr)

        for instr in building_block.init:
            self._translate_label(instr, building_block.context)

        for bbl in building_block.cfg.bbls:
            if MICROPROBE_RC['verbose']:
                progress = Progress(len(bbl.instrs),
                                    "Translating labels:")
            for instr in bbl.instrs:
                self._translate_label(instr, building_block.context)
                if MICROPROBE_RC['verbose']:
                    progress()

        for instr in building_block.fini:
            self._translate_label(instr, building_block.context)

        return []

    def _register_label(self, instruction):
        """

        :param instruction:

        """
        if instruction.label is None:
            return
        else:
            self._labels[instruction.label.upper()] = instruction

    def _translate_label(self, instruction, context):
        """

        :param instruction:
        :param context:

        """

        if self._instructions != []:
            if instruction.name not in self._instructions:
                return

        for operand in instruction.operands():
            if operand.value is None:
                continue

            if not isinstance(operand.value, Address):
                continue

            address = operand.value
            LOG.debug(
                "Translating label: '%s' of instruction '%s'", address,
                instruction.name
            )

            if isinstance(address, InstructionAddress):

                if address.target_instruction is not None:

                    target_address = address.target_instruction.address
                    comment = "Reference to instruction at"

                elif (
                    isinstance(address.base_address, str) and
                    address.base_address.upper() in list(self._labels.keys())
                ):

                    target_address = self._labels[
                        address.base_address.upper()].address + \
                        address.displacement
                    comment = "Reference to %s at" % address

                elif (
                    isinstance(address.base_address, str) and
                    address.base_address.upper() == "CODE"
                ):

                    target_address = address
                    comment = "Reference to %s at" % address

                else:

                    LOG.critical(address.base_address)
                    LOG.critical(address)
                    LOG.critical(list(self._labels.keys()))
                    raise NotImplementedError

                if operand.type.address_relative:

                    if context.code_segment is not None:
                        instruction.add_comment(
                            "%s %s" % (
                                comment, hex(
                                    context.code_segment +
                                    target_address.displacement
                                )
                            )
                        )

                    relative_offset = target_address - instruction.address
                    operand.set_value(relative_offset, check=self._strict)

                else:

                    raise NotImplementedError

            elif isinstance(address.base_address, Variable):

                target_address = Address(
                    base_address=address.base_address.address,
                    displacement=address.displacement
                )

                if operand.type.address_relative:

                    # Code referencing data, fix address taking into account
                    # code and data offsets
                    if instruction.address.base_address == "code" and \
                            target_address.base_address == "data" and \
                            context.data_segment is not None and \
                            context.code_segment is not None:

                        instruction_address = Address(
                            base_address="temp",
                            displacement=context.code_segment +
                            instruction.address.displacement
                        )

                        data_address = Address(
                            base_address="temp",
                            displacement=context.data_segment +
                            target_address.displacement
                        )

                        # instruction_address = Address(base_address="data",
                        #        displacement=instruction.address.displacement)

                        relative_offset = data_address - instruction_address

                        try:
                            operand.set_value(relative_offset)
                        except MicroprobeValueError:
                            raise MicroprobeCodeGenerationError(
                                "Unable to codify the relative offset from "
                                "instruction at 0x%x to data at 0x%x. "
                                "Review the correctness of the addresses and "
                                "change them." %
                                (instruction_address.displacement,
                                 data_address.displacement)
                            )

                        comment = "Reference to var '%s' at" \
                            % address.base_address.name
                        instruction.add_comment(
                            "%s %s" % (
                                comment, hex(
                                    data_address.displacement
                                )
                            )
                        )

                    else:

                        LOG.critical(instruction.address.base_address)
                        LOG.critical(target_address.base_address)
                        LOG.critical(context.data_segment)
                        LOG.critical(context.code_segment)
                        LOG.critical(context.symbolic)

                        LOG.critical(target_address)

                        LOG.critical(instruction)
                        LOG.critical(operand)

                        raise NotImplementedError

                else:
                    raise NotImplementedError
            else:
                LOG.critical(instruction, instruction.address, address)
                LOG.critical(address.base_address, type(address.base_address))
                raise NotImplementedError

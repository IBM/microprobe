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
""":mod:`microprobe.code.bbl` module

"""

# Futures
from __future__ import absolute_import

# Third party modules
from six.moves import range

# Own modules
import microprobe.code.ins
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeValueError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Progress


# Constants
LOG = get_logger(__name__)
__all__ = ["Bbl", "replicate_bbls"]


# Functions
def replicate_bbls(bbl_list, displacement=None):
    """Returns a copy the given basic block list at the specified displacement.

    :param bbl_list: List of basic blocks to copy
    :type bbl_list: :class:`~.list` of :class:`~.Bbl`
    :param displacement: Displacement of the copied basic blocks
                         (Default value = None)
    :type displacement: :class:`~.int`

    """
    bbls_replicated = []

    for bbl in bbl_list:
        bbls_replicated.append(bbl.replicate(displacement=displacement))

    return bbls_replicated


# Classes
class Bbl(object):
    """Class to represent a basic block."""

    def __init__(self, size, instructions=None):
        """

        :param size:

        """
        if size < 1:
            raise MicroprobeValueError(
                "I can not create a Bbl with %d size" % size
            )

        if instructions is None:
            instructions = []

        self._copy_id = 0

        self._incstep = 10000
        self._instrs = [None] * max(self._incstep, (size + 1) * 10)
        self._pointer = 10

        self._instdic = {}

        self._address = None
        self._displacement = 0

        if MICROPROBE_RC["verbose"]:
            progress = Progress(size, "Initializing BBL:")

        if not instructions:
            for idx in range(0, size):
                # self._check_size()
                instr = microprobe.code.ins.Instruction()
                self._instrs[self._pointer] = instr
                self._instdic[instr] = self._pointer
                self._pointer += 10
                if MICROPROBE_RC["verbose"]:
                    progress()
        else:
            for idx in range(0, size):
                self._check_size()
                if idx < len(instructions):
                    self._instrs[self._pointer] = instructions[idx]
                else:
                    self._instrs[self._pointer] = \
                        microprobe.code.ins.Instruction()
                self._instdic[self._instrs[self._pointer]] = self._pointer
                self._pointer += 10
                if MICROPROBE_RC["verbose"]:
                    progress()

    @property
    def instrs(self):
        """List of instructions in the basic block
        (:class:`~.list` of :class:`~.Instruction`)


        """
        return [
            elem for elem in self._instrs[0:self._pointer] if elem is not None
        ]

    @property
    def address(self):
        """Basic block address (:class:`~.Address`)"""
        return self._address

    def set_address(self, address):
        """Set the basic block address.

        :param address: Address for the basic block
        :type address: :class:`~.Address`

        """
        self._address = address

    @property
    def displacement(self):
        """Displacement of the basic block (::class:`~.int`)"""
        return self._displacement

    def set_displacement(self, displacement):
        """Set the displacement of the basic block.

        :param displacement: Displacement for the basic block
        :type displacement: :class:`~.int`

        """
        self._displacement = displacement

    @property
    def size(self):
        """Size of the basic block, number of instructions (::class:`~.int`)"""
        return len(self.instrs)

    def _index(self, instr):
        """Returns the index of the given instruction within the basic block.

        Returns the index of the given instruction within the basic block.
        If the instruction is not found, return a negative number.

        :param instr: Instruction instance
        :type instr: :class:`~.Instruction`

        """
        return self._instdic.get(instr, -1)

    def get_instruction_index(self, instr):
        """Returns the index of the given instruction within the basic block.

        Returns the index of the given instruction within the basic block.
        If the instruction is not found, return a negative number.

        :param instr: Instruction instance
        :type instr: :class:`~.Instruction`

        """
        return self._index(instr)

    def reset_instruction(self, instr, new_instr):
        """Resets the instruction within a basic block by another instruction.

        Resets the instruction within a basic block by another instruction.
        If the instruction is not found, an exception is raised.

        :param instr: Instruction to replace
        :type instr: :class:`~.Instruction`
        :param new_instr: New instruction
        :type new_instr: :class:`~.Instruction`
        :raise microprobe.exceptions.MicroprobeCodeGenerationError: if the
            instruction is not found in the basic block

        """

        idx = self._index(instr)
        if idx < 0:
            raise MicroprobeCodeGenerationError(
                "Instruction not found "
                "in the basic block"
            )
        self._instrs[idx] = new_instr

    def remove_instructions_from(self, instr):
        """Removes the given instruction from the basic block.

        Removes the given instruction from the basic block. If the instruction
        is not found, the basic block is not changed.

        :param instr: Instruction to remove
        :type instr: :class:`~.Instruction`

        """

        idx = self._instdic.get(instr, -1)
        if idx < 0:
            return

        for linstr in [
                elem for elem in self._instrs[idx:self._pointer]
                if elem is not None
        ]:
            self._instdic.pop(linstr)

        self._instrs = self._instrs[0:idx]
        self._pointer = idx
        self._check_size()

    def insert_instr(self, instrs, before=None, after=None):
        """Inserts a list of instruction in the basic block.

        Inserts a list of instruction in the basic block. Before/After
        parameters specify the instructions before/after which the new
        instruction should be added.

        :param instrs: Instruction to insert
        :type instrs: :class:`~.list` of :class:`~.Instruction`
        :param before: Instructions will be inserted before this instruction
                       (Default value = None)
        :type before: :class:`~.list` of :class:`~.Instruction`
        :param after: Instructions will be inserted after this instruction
                      (Default value = None)
        :type after: :class:`~.list` of :class:`~.Instruction`

        """

        idx_before = self._index(before)
        idx_after = self._index(after)

        if idx_before == -1 and idx_after == -1:

            self._check_size(extra=len(instrs))
            self._instrs[self._pointer:self._pointer + len(instrs)] = instrs

            for instr in instrs:

                assert instr not in self._instdic, "Something wrong"
                self._instdic[instr] = self._pointer
                self._pointer += 1

        else:

            assert idx_before > idx_after or idx_before == -1, \
                "Something wrong"

            # assert idx_before == -1 and idx_after > -1

            if not any(
                    self._instrs[idx_after + 1:idx_after + 1 + len(instrs)]
            ):

                self._instrs[idx_after + 1:idx_after + 1 + len(instrs)] = \
                    instrs
                for instr in instrs:
                    assert instr not in self._instdic, "Something wrong"
                    self._instdic[instr] = idx_after + 1
                    idx_after += 1

            else:

                self._check_size(extra=len(instrs))
                self._instrs[(idx_after) + 1:len(instrs)] = instrs
                self._pointer += len(instrs)
                self._instdic = dict(
                    [
                        (v, idx)
                        for idx, v in enumerate(self._instrs) if v is not None
                    ]
                )

    def _increase(self, num):
        """Increases the basic block size by the number specified.

        :param num: Number of instructions to increase
        :type num: :class:`~.int`

        """

        instrs = []
        for dummy_idx in range(0, num):
            instrs.append(microprobe.code.ins.Instruction())

        self.insert_instr(instrs)

    def _check_size(self, extra=0):
        """Checks and fixes basic block size.

        :param extra:  (Default value = 0)

        """

        if self._pointer + extra >= len(self._instrs):
            self._instrs = self._instrs + [None] * self._incstep

    def replicate(self, displacement=0):
        """Replicates current basic block.

        Replicates current basic block with the given extra displacement.

        :param displacement: Extra displacement (Default value = 0)
        :type displacement: :class:`~.int`

        """

        new_bbl = Bbl(self.size)
        new_bbl.set_address(self.address + displacement)
        new_bbl.set_displacement(displacement)

        for idx, orig_instr in enumerate(self.instrs):

            new_instr = orig_instr.copy()

            if new_instr.label != "":
                new_instr.set_label("%s_%d" % (new_instr.label, self._copy_id))

            new_instr.set_address(orig_instr.address + displacement)
            new_bbl.reset_instruction(new_bbl.instrs[idx], new_instr)

        self._copy_id += 1
        return new_bbl

    def distance(self, instr1, instr2):
        i1 = self.get_instruction_index(instr1)
        i2 = self.get_instruction_index(instr2)
        idxs = list(sorted([i1, i2]))
        distance = [
            elem for elem in sorted(self._instdic.values())
            if elem > idxs[0] and elem <= idxs[1]
        ]
        return len(distance)

    def get_instruction_by_distance(self, instr, distance):
        i1 = self.get_instruction_index(instr)
        idx = sorted(self._instdic.values()).index(i1)
        if idx - distance >= 0:
            idx = idx + distance
        else:
            idx = 0
        idx = sorted(self._instdic.values())[idx]
        return self._instrs[idx]

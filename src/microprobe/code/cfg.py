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
""":mod:`microprobe.code.cfg` module

"""

# Futures
from __future__ import absolute_import, annotations
from typing import TYPE_CHECKING, List, Tuple

# Own modules
from microprobe.code.bbl import Bbl
from microprobe.utils.logger import get_logger
from microprobe.utils.typeguard_decorator import typeguard_testsuite

# Type hinting
if TYPE_CHECKING:
    from microprobe.code.ins import Instruction

# Constants
LOG = get_logger(__name__)
__all__ = ["Cfg"]

# Functions

# Classes


@typeguard_testsuite
class Cfg:
    """Class to represent the control flow graph of a building block."""

    def __init__(self):
        """ """
        self._cfg_nodes: List[Bbl] = []
        self._cfg_edges: List[Tuple[int, int]] = []
        self._idx = 0
        self._last_bbl = None
        self._first_bbl = None

    def add_bbl(self,
                bbl: Bbl | None = None,
                size: int = 1,
                instructions: List[Instruction] | None = None):
        """Adds a basic block to the control flow graph of the specified size.

        :param bbl: Basic block to add (if none, one is created)
                    (Default value = None)
        :type bbl: :class:`~.Bbl`
        :param size: Size of the new basic block (Default value = 1)
        :type size: ::class:`~.int`
        :param instructions: Instructions for the basic block
        :type instructions: :class:`~.list` of :class:`~.Instruction`

        """
        if bbl is None:

            if instructions is not None:
                bbl = Bbl(len(instructions), instructions=instructions)
            else:
                bbl = Bbl(size)

        self._cfg_nodes.append(bbl)
        self._cfg_edges.append((self._idx, self._idx + 1))

        if self._first_bbl is None:
            self._first_bbl = 0

        self._last_bbl = self._idx
        self._idx += 1
        return bbl

    def add_bbls(self, bbls: List[Bbl]):
        """Adds a list of basic blocks to the control flow graph.

        :param bbls: Lists of basic blocks to add.
        :type bbls: :class:`~.list` of :class:`~.Bbl`

        """
        for bbl in bbls:
            self.add_bbl(bbl=bbl)

    @property
    def bbls(self):
        """List of basic blocks in the CFG
        (:class:`~.list` of :class:`~.Bbl`)."""
        return self._cfg_nodes[:]

    def index(self, instr: Instruction):
        """Returns index of the basic block containing the given instruction.

        :param instr: Instruction to look for
        :type instr: :class:`~.Instruction`

        """
        rlist = [
            idx for idx, bbl in enumerate(self.bbls)
            if bbl.get_instruction_index(instr) >= 0
        ]

        if rlist:
            return -1
        return rlist[0]

    def get_bbl(self, index: int):
        """Returns the basic block at the specified index

        :param index: Index of the bbl
        :type index: :class:`~.int`

        """
        return self._cfg_nodes[index]

    def last_bbl(self):
        """Returns the last basic block of the CFG

        """
        return self._cfg_nodes[-1]

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
""":mod:`microprobe.passes.structure` module

"""

# Futures
from __future__ import absolute_import, division

# Built-in modules

# Third party modules
from six.moves import range

# Own modules
import microprobe.passes
from microprobe.code.address import InstructionAddress
from microprobe.code.bbl import replicate_bbls
from microprobe.utils.logger import get_logger

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = ['SimpleBuildingBlockPass', 'GenericCodeStructurePass']

# Functions


# Classes
class SimpleBuildingBlockPass(microprobe.passes.Pass):
    """SimpleBuildingBlockPass Class.

    This :class:`~.Pass` adds a single building block of a given instruction
    size to the given building block. The pass fails if the buiding block
    size differs in ratio more than the threshold provided.
    """

    def __init__(self, bblsize, threshold=0.1):
        """Create a SimpleBuildingBlockPass object.

        :param bblsize: Size of the building block to add
        :type bblsize: :class:`int`
        :param threshold: Allowed deviation from the size provided
                         (Default value = 0.1)
        :type threshold: :class:`float`
        :return: A new SimpleBuildingBlockPass object.
        :rtype: :class:`SimpleBuildingBlockPass`
        """
        super(SimpleBuildingBlockPass, self).__init__()
        self._bblsize = bblsize
        self._description = "Create a basic block with '%d' " \
                            "instructions" % self._bblsize
        self._threshold = threshold

    def __call__(self, building_block, dummy):
        """

        :param building_block:
        :param dummy:

        """

        building_block.cfg.add_bbl(size=self._bblsize)

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        pass_ok = True
        pass_ok = pass_ok and (len(building_block.cfg.bbls) == 1)
        for bbl in building_block.cfg.bbls:

            LOG.debug("BBL size: %d", bbl.size)
            LOG.debug("Expected BBL size: %d", self._bblsize)

            if (abs((bbl.size * 1.0) / self._bblsize) - 1) > self._threshold:
                LOG.warning(
                    "Percentage deviation: %.2f", abs(
                        (bbl.size * 1.0) / self._bblsize
                    ) - 1
                )
                pass_ok = False

        return pass_ok


class GenericCodeStructurePass(microprobe.passes.Pass):
    """ """

    def __init__(self, model):
        """

        :param model:

        """
        super(GenericCodeStructurePass, self).__init__()
        self._model = model

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        descriptors = self._model(building_block.code_size)

        current_displacement = 0
        orig_bbls = building_block.cfg.bbls[:]

        iteration_register = None
        first = True
        for idx, elem in enumerate(descriptors):
            chunks, displacement, iterations = elem

            LOG.debug("Descriptor info:")
            LOG.debug("  Chunks: %d", chunks)
            LOG.debug("  Displacement: %d", displacement)
            LOG.debug("  Iterations: %d", iterations)

            if chunks < 1 or iterations < 1:
                continue

            for dummy in range(0, iterations):

                first_chunk_in_iteration = None
                last_chunk_in_iteration = None

                for dummy in range(0, chunks):

                    if first:

                        LOG.debug("First Chunk - No copy")
                        first = False
                        current_chunk = orig_bbls
                        # prev_chunk = None

                    else:

                        LOG.debug("Other Chunk - Replicating")
                        # prev_chunk = current_chunk
                        current_chunk = replicate_bbls(
                            orig_bbls,
                            displacement=current_displacement
                        )

                        building_block.cfg.add_bbls(current_chunk)

                    if first_chunk_in_iteration is None:
                        first_chunk_in_iteration = current_chunk

                    last_chunk_in_iteration = current_chunk
                    current_displacement = current_displacement + displacement

            first_chunk_in_iteration = first_chunk_in_iteration[0]
            last_chunk_in_iteration = last_chunk_in_iteration[-1]

            if iterations > 1:

                LOG.debug("Adding loop control instructions")

                if iteration_register is None:

                    iteration_register = \
                        target.get_register_for_address_arithmetic(
                            building_block.context)
                    building_block.context.add_reserved_registers(
                        [iteration_register]
                    )

                    LOG.debug(
                        "Using register '%s' as loop control "
                        "register", iteration_register
                    )

                # set the number of iteration to the first
                newins = target.set_register(
                    iteration_register, 0, building_block.context
                )

                # pylint: disable=E1103
                first_chunk_in_iteration.insert_instr(
                    newins, before=first_chunk_in_iteration.instrs[0]
                )
                # pylint: enable=E1103

                # set the branch to the last
                label = "chunk_%d" % (idx)

                newins = target.add_to_register(iteration_register, 1)
                newins += target.compare_and_branch(
                    iteration_register, iterations, "<", label,
                    building_block.context
                )

                # pylint: disable=E1103
                first_chunk_in_iteration.instrs[0].setlabel(label)

                last_chunk_in_iteration.insert_instr(
                    newins, after=last_chunk_in_iteration.instrs[-1]
                )
                # pylint: enable=E1103

                # link_BBLS
        prev_bbl = None
        for bbl in building_block.cfg.bbls:

            if prev_bbl is not None:

                LOG.debug("Linking with previous chunk")
                source = InstructionAddress(
                    base_address="code",
                    displacement=prev_bbl.instrs[-1].address.displacement +
                    prev_bbl.instrs[-1].architecture_type.format.length
                )

                newins = target.branch_unconditional_relative(
                    source, bbl.instrs[0]
                )

                prev_bbl.insert_instr([newins], after=prev_bbl.instrs[-1])
            prev_bbl = bbl

        # exit(0)

    def check(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        raise NotImplementedError

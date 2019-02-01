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
""":mod:`microprobe.code.benchmark` module

"""

# Futures
from __future__ import absolute_import, print_function

# Own modules
import microprobe.code.cfg
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import OrderedDict

# Constants
LOG = get_logger(__name__)
__all__ = ["BuildingBlock", "Benchmark",
           "MultiThreadedBenchmark", "benchmark_factory"]


# Functions
def benchmark_factory(threads=1):
    if threads == 1:
        return Benchmark()
    else:
        return MultiThreadedBenchmark(num_threads=threads)


# Classes
class BuildingBlock(object):
    """Class to represent a benchmark building block.

    Class to represent a benchmark building block. The different building
    blocks of a benchmark such as function, basic blocks, loops, etc. should
    inherit from this class.


    """

    def __init__(self):
        """ """
        self._warnings = {}
        self._info = []
        self._pass_info = []
        self._requirements = []

    def add_warning(self, message):
        """Add a warning message to the building block.

        :param message: Warning message
        :type message: :class:`~.str`

        """

        if message not in self._warnings:
            self._warnings[message] = 1
        else:
            self._warnings[message] += 1

    @property
    def warnings(self):
        """List of warnings of the building block

        List of warnings of the building block
        (:class:`~.list` of :class:`~.str`)
        """
        return self._warnings

    def add_pass_info(self, message):
        """Add an pass information message to the building block.

        :param message: Information pass message
        :type message: :class:`~.str`

        """
        self._pass_info.append(message)

    def add_info(self, message):
        """Add an information message to the building block.

        :param message: Information message
        :type message: :class:`~.str`

        """
        self._info.append(message)

    @property
    def info(self):
        """List of information messages of the building block
        (:class:`~.list` of :class:`~.str`)


        """
        return self._info

    @property
    def pass_info(self):
        """List of information pass messages of the building block
        (:class:`~.list` of :class:`~.str`)


        """
        return self._pass_info

    def add_requirement(self, message):
        """Add an requirement message to the building block.

        :param message: Requirement message
        :type message: :class:`~.str`

        """
        self._requirements.append(message)

    @property
    def requirements(self):
        """List of requirement messages of the building block
        (:class:`~.list` of :class:`~.str`)


        """
        return self._requirements


class Benchmark(BuildingBlock):
    """Class to represent a benchmark (highest level building block)."""

    def __init__(self):
        """ """

        super(Benchmark, self).__init__()
        self._cfg = microprobe.code.cfg.Cfg()
        self._global_vars = OrderedDict()
        self._init = []
        self._fini = []
        self._vardisplacement = 0
        self._context = None
        self._num_threads = 1

    @property
    def init(self):
        """Initialization instructions

        Initialization instructions (:class:`~.list` of :class:`~.Instruction`)
        """
        return self._init

    def add_init(self, inits):
        """Appends the specified list of instructions to initialization list

        :param inits: List of instructions to be added
        :type inits: :class:`~.list` of :class:`~.Instruction`

        """
        LOG.debug("Add Init")
        for init in inits:
            LOG.debug("INIT: %s", init)
        self._init = self._init + inits

    def rm_init(self, inits):
        """Removes from the initialization list the specified instructions.

        :param inits: List of instructions to be removed
        :type inits: :class:`~.list` of :class:`~.Instruction`

        """
        self._init = self._init[0:-len(inits)]

    def add_fini(self, finis):
        """Appends the specified list of instructions to the finalization list

        :param finis: List of instructions to be added
        :type finis: :class:`~.list` of :class:`~.Instruction`

        """
        self._fini = self._fini + finis

    @property
    def fini(self):
        """Finalization instructions
        (:class:`~.list` of :class:`~.Instruction`)"""
        return self._fini

    @property
    def cfg(self):
        """Returns the benchmark control flow graph."""
        return self._cfg

    def set_cfg(self, cfg):
        """Sets the benchmarks control flow graph.

        :param cfg: Control flow graph
        :type cfg: :class:`~.Cfg`

        """
        self._cfg = cfg

    def registered_global_vars(self):
        """Returns the list of registered global variables."""
        return list(self._global_vars.values())

    def register_var(self, var, context):
        """Registers the given variable as a global variable.

        :param var: Variable to register
        :type var: :class:`~.Variable`

        """

        LOG.debug("Registering global var: '%s'", var.name)

        if var.name in self._global_vars:

            var2 = self._global_vars[var.name]
            if (var.value == var2.value and
                    var.address == var2.address and
                    var.address is not None and
                    MICROPROBE_RC['safe_bin']):
                LOG.warning(
                    "Variable: '%s' registered multiple times!", var.name
                )

                return

            LOG.critical("Registered variables: %s",
                         list(self._global_vars.keys()))
            raise MicroprobeCodeGenerationError(
                "Variable already registered: %s" % (var.name)
            )

        self._global_vars[var.name] = var

        if context.symbolic:

            LOG.debug("Context symbolic. No need to track base addresses")
            var_address = Address(base_address=var.name, displacement=0)
            var.set_address(var_address)

        elif var.address is None:
            LOG.debug("Context not symbolic and variable address not set")

            # if (self._vardisplacement == 0 and
            #        context.data_segment is not None):
            #     self._vardisplacement = context.data_segment

            address_ok = False

            while not address_ok:
                var_address = Address(
                    base_address="data",
                    displacement=self._vardisplacement
                )

                LOG.debug("Address before alignment: %s", var_address)

                align = var.align
                if align is None:
                    align = 1

                LOG.debug("Variable alignment: %s", align)
                LOG.debug("Current address: %s", var_address)

                if var_address.displacement % align != 0:
                    # alignment needed
                    var_address += align - (var_address.displacement % align)

                LOG.debug("Address after alignment: %s", var_address)
                LOG.debug(
                    "Current var displacement: %x", self._vardisplacement
                )

                var.set_address(var_address)
                over = self._check_variable_overlap(var)

                if over is not None:
                    self._vardisplacement = max(
                        self._vardisplacement,
                        over.address.displacement + over.size
                    )
                    continue

                address_ok = True
                LOG.debug("Variable registered at address: '%s'", var_address)

            self._vardisplacement = var_address.displacement + var.size

        else:
            LOG.debug("Using pre-defined address: '%s'", var.address)

        over = self._check_variable_overlap(var)
        if over is not None:
            raise MicroprobeCodeGenerationError(
                "Variable '%s' overlaps with variable '%s'" % (
                    var.name, over.name
                )
            )

    def _check_variable_overlap(self, var):

        return None

        vara = var.address
        vara2 = vara + var.size

        for rvar in self._global_vars.values():

            if var.name == rvar.name:
                continue

            rvara = rvar.address
            rvara2 = rvara + rvar.size

            if rvara < vara2 and rvara2 >= vara2:
                return rvar

            if rvara <= vara and rvara2 > vara:
                return rvar

            if rvara >= vara and rvara2 <= vara2:
                return rvar

            if rvara <= vara and rvara2 >= vara2:
                return rvar

        return None

    def set_context(self, context):
        """Set the execution context of the building block.

        :param context: Execution context
        :type context: :class:`~.Context`

        """
        self._context = context

    @property
    def context(self):
        """Return benchmark's context"""
        return self._context

    def add_instructions(self, instrs, after=None, before=None):
        """Adds the given instruction to the building block.

        Adds the given instructions right after the specified instruction and
        before the specified one. If the condition can not be fulfilled an
        specification exception is raised.

        :param instrs: Instruction to add
        :type instrs: :class:`~.list` of :class:`~.Instruction`
        :param after: Instruction after which to add the new instruction
                      (Default value = None)
        :type after: :class:`~.Instruction`
        :param before: Instruction before which to add the new instruction
                       (Default value = None)
        :type before: :class:`~.Instruction`

        """

        if after is None and before is None:
            bbl = self.cfg.last_bbl()
            bbl.insert_instr(instrs)

        elif after is not None and before is None:
            idx_after = self.cfg.index(after)
            bbl = self.cfg.get_bbl(idx_after)
            bbl.insert_instr(instrs, after=after)

        elif after is None and before is not None:
            idx_before = self.cfg.index(before)
            bbl = self.cfg.get_bbl(idx_before)
            bbl.insert_instr(instrs, before=before)

        elif after is not None and before is not None:
            idx_before = self.cfg.index(before)
            idx_after = self.cfg.index(after)

            if idx_before < idx_after:
                bbl = self.cfg.get_bbl(idx_before)
                bbl.insert_instr(instrs)
            elif idx_before == idx_after:
                bbl = self.cfg.get_bbl(idx_before)
                bbl.insert_instr(instrs, after=after, before=before)
            else:
                raise MicroprobeCodeGenerationError(
                    "Attempt to inserst instruction in a position that it is"
                    " not possible"
                )

    @property
    def code_size(self):
        """Return benchmark's size"""

        size = 0
        for bbl in self.cfg.bbls:
            for instr in bbl.instrs:
                size += instr.architecture_type.format.length

        return size

    @property
    def labels(self):
        """Return the a list of the current defined labels and symbols"""
        labels = [key.upper() for key in self._global_vars.keys()]
        for bbl in self.cfg.bbls:
            for instr in bbl.instrs:
                if instr.label is not None:
                    labels.append(instr.label.upper())

        labels += [
            instr.label.upper()
            for instr in self._fini if instr.label is not None
        ]

        labels += [
            instr.label.upper()
            for instr in self._init if instr.label is not None
        ]

        return labels

    def set_current_thread(self, idx):
        """ """
        self._current_thread = idx
        if not 1 <= idx <= self._num_threads + 1:
            raise MicroprobeCodeGenerationError(
                "Unknown thread id: %d (min: 1, max: %d)" %
                (idx, self._num_threads + 1)
            )


class MultiThreadedBenchmark(Benchmark):
    """ """

    def __init__(self, num_threads=1):
        """ """
        self._num_threads = num_threads
        self._threads = {}
        for idx in range(1, num_threads + 1):
            self._threads[idx] = Benchmark()
        self._current_thread = 1

    def __getattr__(self, attribute_name):
        return self._threads[
            self._current_thread].__getattribute__(attribute_name)

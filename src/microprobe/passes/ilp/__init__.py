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
""":mod:`microprobe.passes.ilp` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import itertools
import random
import re

# Third party modules

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
    'ConstantDependencyDistancePass',
    'AverageDependencyDistancePass',
    'RandomDependencyDistancePass',
]

# Functions


# Classes
class ConstantDependencyDistancePass(microprobe.passes.Pass):
    """ConstantDependencyDistancePass pass.

    """

    def __init__(self, dep):
        """

        :param dep:

        """
        super(ConstantDependencyDistancePass, self).__init__()
        self._dep = dep

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_dependency_distance(self._dep)

        return []


class AverageDependencyDistancePass(microprobe.passes.Pass):
    """AverageDependencyDistancePass pass.

    """

    def __init__(self, dep):
        """

        :param dep:

        """
        super(AverageDependencyDistancePass, self).__init__()
        self._func = microprobe.utils.distrib.discrete_average(dep)

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_dependency_distance(self._func())

        return []


class RandomDependencyDistancePass(microprobe.passes.Pass):
    """RandomDependencyDistancePass pass.

    """

    def __init__(self, maxdep):
        """

        :param maxdep:

        """
        super(RandomDependencyDistancePass, self).__init__()
        self._max = maxdep
        self._func = random.randint

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_dependency_distance(self._func(0, self._max))

        return []

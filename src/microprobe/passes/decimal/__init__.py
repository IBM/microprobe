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
""":mod:`microprobe.passes.decimal` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules

# Third party modules

# Own modules
import microprobe.passes
from microprobe.code.address import MemoryValue

# Local modules


# Constants
__all__ = ['InitializeMemoryDecimalPass']

# Functions


# Classes
class InitializeMemoryDecimalPass(microprobe.passes.Pass):
    """ """

    def __init__(self, value=0):
        """

        :param value:  (Default value = 0)

        """
        super(InitializeMemoryDecimalPass, self).__init__()
        self._value = value
        self._description = "Initialize all the memory location accessed by "\
                            "decimal floating point operations to value: '%s'"\
                            "." % (self._value)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        addresses_set = []

        context = building_block.context

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                # if not instr.hfp_exponent_overflow_exception:
                #    continue

                if not instr.decimal:
                    continue

                for memoperand in instr.memory_operands():

                    if memoperand.address is None:
                        continue

                    if memoperand.address in addresses_set:
                        continue

                    if memoperand.is_load:

                        # Set a correct value in that address
                        assert memoperand.length > 0

                        # Step4: store the content to the target
                        instrs = target.store_decimal(
                            memoperand.address, memoperand.length, self._value,
                            context
                        )

                        context.set_memory_value(
                            MemoryValue(
                                memoperand.address, self._value,
                                memoperand.length
                            )
                        )

                        addresses_set.append(memoperand.address)
                        building_block.add_init(instrs)

    def check(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        raise NotImplementedError

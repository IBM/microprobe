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
""":mod:`microprobe.passes.dat` module

"""

# Futures
from __future__ import print_function

# Built-in modules

# Third party modules

# Own modules
from __future__ import absolute_import
from microprobe.code.address import InstructionAddress
from microprobe.passes import Pass
from microprobe.utils.logger import get_logger

# Local modules

# Constants
LOG = get_logger(__name__)
__all__ = ["InitializeDATPass", "TranslateAddressPass"]

# Functions


# Classes
class InitializeDATPass(Pass):

    def __init__(self, **kwargs):
        """
        """

        super(InitializeDATPass, self).__init__()

        self._description = "Initialize the Dynamic Address Translation" +\
            " mechanism of the target and register it to the current context"

        self._args = kwargs

    def __call__(self, building_block, target):

        building_block.context.set_dat(target.get_dat(**self._args))


class TranslateAddressPass(Pass):

    def __init__(self):
        """
        """

        super(TranslateAddressPass, self).__init__()
        self._description = "Translate instruction addresses to real addresses"

    def __call__(self, building_block, dummy_target):

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                building_block.context.dat.update_dat(**instr.decorators)

                address = instr.address.copy()
                if address.base_address == "code":
                    raw_address = building_block.context.code_segment +\
                        address.displacement
                else:
                    raise NotImplementedError

                trans_address = building_block.context.dat.translate(
                    raw_address
                )
                new_address = InstructionAddress(
                    base_address="abs",
                    displacement=trans_address
                )
                instr.set_address(new_address)

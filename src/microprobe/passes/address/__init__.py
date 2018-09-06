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
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import instruction_set_def_properties
from microprobe.code.var import Variable
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeUncheckableEnvironmentWarning
from microprobe.target.isa.instruction import InstructionType
from microprobe.utils.asm import interpret_asm
from microprobe.utils.distrib import generate_weighted_profile, \
    weighted_choice
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict, closest_divisor

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = [
    'UpdateInstructionAddressesPass',
]

# Functions


# Classes
class UpdateInstructionAddressesPass(microprobe.passes.Pass):
    """INS_ComputerAddresses pass.

    """

    def __init__(self, force=False):
        """ """
        super(UpdateInstructionAddressesPass, self).__init__()

        self._force = force
        self._description = "Compute addresses. (Force: %s)" % force

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        caddress = InstructionAddress(base_address="code", displacement=0)

        # TODO: this is a hack, should not be done here. Once we implement
        # a proper code generation back-end, this will be fixed
        caddress += target.wrapper.init_main_pad()

        for instr in building_block.init:
            instr.set_address(caddress.copy())
            caddress += instr.architecture_type.format.length

        # TODO: this is a hack, should not be done here. Once we implement
        # a proper code generation back-end, this will be fixed
        caddress += target.wrapper.init_loop_pad()

        prev_bbl = None
        for bbl in building_block.cfg.bbls:

            if prev_bbl is not None:

                LOG.debug(prev_bbl.address)
                LOG.debug(prev_bbl.displacement)
                LOG.debug(bbl.address)
                LOG.debug(bbl.displacement)

                if bbl.displacement > 0 and prev_bbl.displacement > 0:
                    # Relative displacement
                    bbl.set_address(
                        prev_bbl.address + (
                            bbl.displacement - prev_bbl.displacement
                        )
                    )
                else:
                    bbl.set_address(caddress + bbl.displacement)
            else:
                bbl.set_address(caddress + bbl.displacement)

            if caddress > bbl.address:
                raise MicroprobeCodeGenerationError("Overlapping BBLs?")

            caddress = bbl.address

            for instr in bbl.instrs:

                if instr.address is None or self._force:
                    instr.set_address(caddress.copy())
                    caddress += instr.architecture_type.format.length
                else:
                    caddress = instr.address + \
                        instr.architecture_type.format.length

            prev_bbl = bbl

        for instr in building_block.fini:
            instr.set_address(caddress.copy())
            caddress += instr.architecture_type.format.length

        # daddress = Address(base_address="data",
        #                   displacement=0)

        # for variable in building_block.registered_global_vars():
        #     LOG.debug(variable.address)
        #     daddress_var = daddress + variable.get_displacement()
        #     variable.set_address(daddress_var.copy())

        return []

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        pass_ok = True
        caddress = InstructionAddress(base_address="code", displacement=0)

        for instr in building_block.init:
            pass_ok = pass_ok and caddress == instr.address
            caddress += instr.architecture_type.format.length

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                pass_ok = pass_ok and caddress == instr.address
                caddress += instr.architecture_type.format.length

        for instr in building_block.fini:
            pass_ok = pass_ok and caddress == instr.address
            caddress += instr.architecture_type.format.length

        # daddress = Address(base_address="data",
        #                   displacement=0)

        # for variable in building_block.registered_global_vars():
        #    daddress += variable.get_displacement()
        #    pass_ok = variable.address == daddress

        return pass_ok

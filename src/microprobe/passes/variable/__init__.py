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
""":mod:`microprobe.passes.variable` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules

# Third party modules

# Own modules
import microprobe.code.var
import microprobe.passes
from microprobe.code.address import Address
from microprobe.utils.logger import get_logger
from microprobe.exceptions import MicroprobeCodeGenerationError

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = ['DeclareVariablesPass']


# Functions


# Classes
class DeclareVariablesPass(microprobe.passes.Pass):
    """ """

    def __init__(self, variables, code_init=False):
        """

        :param variables:

        """
        super(DeclareVariablesPass, self).__init__()

        self._variables = []
        self._code_init = code_init

        for name, vartype, elems, address, align, init_value in variables:

            kwargs = {}
            if align is not None:
                kwargs["align"] = align
            if address is not None:
                address = Address(base_address="data", displacement=address)
                kwargs["address"] = address
            if init_value is not None:
                kwargs["value"] = init_value

            if elems > 1:
                var = microprobe.code.var.VariableArray(
                    name, vartype, elems, **kwargs
                )
            else:
                var = microprobe.code.var.VariableSingle(
                    name, vartype, **kwargs
                )

            self._variables.append(var)

        self._description = "Declaring variables: %s" % [
            str(var) for var in self._variables
        ]

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param dummy_target:

        """

        for var in self._variables:
            if (var.address is not None and
                    not building_block.context.symbolic):
                # This is an absolute address that we need to modify
                # to be relative to the data segment

                var.set_address(
                    var.address - building_block.context.data_segment
                )

            LOG.debug("Declaring: %s", var)
            building_block.register_var(var, building_block.context)

        if not self._code_init:
            return

        context = building_block.context
        instrs = []

        for var in self._variables:
            values = var.value
            if var.array():
                typesize = var.size // var.elems
                elems = var.elems
                if not isinstance(var.value, list):
                    values = [var.value] * elems
            else:
                typesize = var.size
                elems = 1
                if not isinstance(var.value, list):
                    values = [var.value] * elems

            assert len(values) == elems

            vreg = target.scratch_registers[0]
            iaddress = var.address.copy()
            for value in values:
                instrs += target.set_register(vreg, value, context)
                context.set_register_value(
                    vreg, value
                )
                try:
                    instrs += target.store_integer(
                        vreg, iaddress, typesize * 8, context
                    )
                except MicroprobeCodeGenerationError:
                    areg = target.scratch_registers[1]
                    instrs += target.set_register_to_address(
                            areg,
                            iaddress,
                            context,
                        )
                    context.set_register_value(
                        areg, iaddress
                    )
                    instrs += target.store_integer(
                        vreg, iaddress, typesize * 8, context
                    )

                iaddress += typesize

        building_block.add_init(instrs)


class UpdateVariableAddressesPass(microprobe.passes.Pass):
    """ """

    def __init__(self):
        """
        """
        self._description = "Update Variable addreses"

    def __call__(self, building_block, target):
        """
        """

        ivars = [var for var in building_block.registered_global_vars()
                 if var.address is None or var.address.base_address != "data"]
        context = building_block.context

        maxdispl = None
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                if instr.address is None:
                    continue
                caddress = instr.address
                if caddress.base_address != "code":
                    continue
                if maxdispl is None:
                    maxdispl = caddress.displacement
                elif maxdispl < caddress.displacement:
                    maxdispl = caddress.displacement

        code_region = (context.code_segment, ((maxdispl // 0x100) + 1) * 0x100)

        for var in ivars:
            ranges = sorted([code_region] +
                            [(var.address.displacement, var.size)
                             for var in building_block.registered_global_vars()
                             if var.address is not None
                             and var.address.base_address == "data"],
                            key=lambda x: x[0])

            align = var.align
            if align is None:
                align = 1

            if len(ranges) == 1:
                var.set_address(
                    Address(
                        base_address="data",
                        displacement=(
                            ((ranges[0][0] + ranges[0][1]) // align) + 1
                            ) * align
                        )
                )
                continue

            for idx in range(0, len(ranges)-1):
                mrange = ranges[idx]
                ndisp = (((mrange[0] + mrange[1]) // align) + 1) * align
                if ndisp + var.size >= ranges[idx+1][0]:
                    continue
                var.set_address(
                   Address(
                       base_address="data",
                       displacement=ndisp
                       )
                )
                break

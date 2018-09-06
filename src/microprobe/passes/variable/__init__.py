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

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = ['DeclareVariablesPass']

# Functions


# Classes
class DeclareVariablesPass(microprobe.passes.Pass):
    """ """

    def __init__(self, variables):
        """

        :param variables:

        """
        super(DeclareVariablesPass, self).__init__()

        self._variables = []

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

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for var in self._variables:
            if (
                var.address is not None and not building_block.context.symbolic
            ):
                # This is an absolute address that we need to modify
                # to be relative to the data segment

                var.set_address(
                    var.address - building_block.context.data_segment
                )

            LOG.debug("Declaring: %s", var)
            building_block.register_var(var, building_block.context)

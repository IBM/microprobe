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
""":mod:`microprobe.passes.float` module

"""

# Futures
from __future__ import absolute_import

# Own modules
import microprobe.code.var
import microprobe.passes
from microprobe.code.address import Address, MemoryValue
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.ieee import ieee_float_to_int64
from microprobe.utils.logger import get_logger

# Constants
LOG = get_logger(__name__)
__all__ = ["InitializeMemoryFloatPass"]

# Functions


# Classes
class InitializeMemoryFloatPass(microprobe.passes.Pass):
    """ """

    def __init__(self, value=0):
        """

        :param value:  (Default value = 0)

        """
        super().__init__()
        self._var = microprobe.code.var.VariableSingle(
            "FP_INITVAL", "double", value=f"{value:.20f}"
        )
        self._varaddress = Address(base_address=self._var)

        self._value = value
        self._memvalue = MemoryValue(self._varaddress, value, 8)
        self._description = (
            "Initialize all the memory location accessed by"
            f" binary floating point operations to value: '{value}'."
        )

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        variable_to_declare = False
        addresses_set = []
        # context = building_block.context
        context = target.wrapper.context()

        if building_block.context.register_has_value(0):
            reg = building_block.context.registers_get_value(0)[0]
            context.set_register_value(reg, 0)

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                # if not instr.hfp_exponent_overflow_exception:
                #    continue

                is_float = False
                for operand in instr.operands():
                    if operand.type.float and operand.is_input:
                        is_float = True

                if not is_float:
                    continue

                for memoperand in instr.memory_operands():
                    if memoperand.address is None:
                        continue

                    if memoperand.address in addresses_set:
                        continue

                    if not memoperand.is_load:
                        continue

                    addresses_set.append(memoperand.address)

        addresses_set = sorted(addresses_set)

        for address in addresses_set:
            if variable_to_declare is False:
                variable_to_declare = True
                reg2 = target.scratch_registers[0]

                instrs = target.set_register(
                    reg2, ieee_float_to_int64(self._value), context
                )

                for instr in instrs:
                    instr.add_comment("Initialize reg to float value")

                building_block.add_init(instrs)

                context.set_register_value(
                    reg2, ieee_float_to_int64(self._value)
                )

                reg1 = target.scratch_registers[1]

                instrs = target.set_register_to_address(reg1, address, context)
                context.set_register_value(reg1, address)

                building_block.add_init(instrs)

            try:
                instrs = target.store_integer(reg2, address, 64, context)

            except MicroprobeCodeGenerationError:
                instrs = target.set_register_to_address(reg1, address, context)
                context.set_register_value(reg1, address)

                building_block.add_init(instrs)

                instrs = target.store_integer(reg2, address, 64, context)

            context.set_memory_value(MemoryValue(address, self._value, 8))

            for instr in instrs:
                instr.add_comment(f"Initialize memory float: {address}")

            building_block.add_init(instrs)

            LOG.debug("Instruction: %s: %s", instr.address, instr)
            LOG.debug("Address: %s", address)

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        pass_ok = True
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                is_float = False

                for operand in instr.operands():
                    if operand.type.float:
                        is_float = True

                if not is_float:
                    continue

                for memoperand in instr.memory_operands():
                    if memoperand.address is None:
                        continue

                    if not memoperand.is_load:
                        continue

                    LOG.debug("Checking memory value: %s", memoperand.address)

                    memory_value = building_block.context.get_memory_value(
                        memoperand.address
                    )

                    if memory_value is None:
                        LOG.debug("Instruction: %s: %s", instr.address, instr)
                        LOG.debug(
                            "Memory value not present: %s", memoperand.address
                        )
                        return False

                    if memory_value.address != memoperand.address:
                        LOG.debug(
                            "%s != %s",
                            memory_value.address,
                            memoperand.address,
                        )
                        return False

                    if memory_value.length != 8:
                        LOG.debug("Invalid length: %s", memory_value.length)
                        return False

                    if memory_value.value != self._value:
                        LOG.debug(
                            "Invalid value: %d != %d",
                            memory_value.value,
                            self._value,
                        )
                        return False

        return pass_ok

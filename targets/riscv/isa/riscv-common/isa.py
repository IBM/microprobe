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
"""
Docstring
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os

# Own modules
from microprobe.code.address import Address
from microprobe.code.var import Variable, VariableArray
from microprobe.target.isa import GenericISA
from microprobe.utils.logger import get_logger

# Constants
LOG = get_logger(__name__)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# Functions


# Classes
class RISCVISA(GenericISA):

    def __init__(self, name, descr, ins, regs, comparators, generators):
        super(RISCVISA, self).__init__(name, descr, ins, regs, comparators,
                                       generators)
        self._scratch_registers += [self.registers["X31"],
                                    self.registers["F7"]]
        self._control_registers += [reg for reg in self.registers.values()
                                    if reg.type.name == "rm"]

    def set_register(self, register, value, context):

        LOG.debug("Setting register: %s to value %d",
                  register.name, value)

        instrs = []

        current_value = context.get_register_value(register)
        if context.register_has_value(value):
            present_reg = context.registers_get_value(value)[0]

            if present_reg.type.name != register.type.name:
                present_reg = None

        else:
            present_reg = None

        if register.type.name == "freg":

            if present_reg is not None:

                instr = self.new_instruction("FSGNJ.S_V0")
                instr.set_operands([register, present_reg, present_reg])
                instrs.append(instr)

            else:

                instrs += self.set_register(self._scratch_registers[0], value,
                                            context)

                instr = self.new_instruction("FCVT.S.L_V0")
                instr.set_operands([self._scratch_registers[0], register])
                instrs.append(instr)

        elif register.type.name == "ireg":

            value_highest = int((value & 0xFFFFF00000000000) >> 44)
            value_high = int((value & 0x00000FFF00000000) >> 32)
            value_low = int((value & 0x00000000FFFFF000) >> 12)
            value_lowest = int((value & 0x0000000000000FFF))

            if value == 0:

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([0, register, self.registers["X0"]])
                instrs.append(addi)

            elif present_reg is not None:

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([register, present_reg, 0])
                instrs.append(addi)

            elif register == self._scratch_registers[0]:

                if (value < -2147483648 or value >= 2147483647):

                    lui = self.new_instruction("LUI_V0")
                    lui.set_operands([value_highest, register])
                    instrs.append(lui)
                    addiw = self.new_instruction("ADDIW_V0")
                    addiw.set_operands([value_high, register, register])
                    instrs.append(addiw)

                    slli = self.new_instruction("SLLI_V0")
                    slli.set_operands([8, register, register])
                    instrs.append(slli)
                    nvalue = int((value & 0x00000000FF000000) >> 24)
                    addi = self.new_instruction("ADDI_V0")
                    addi.set_operands([nvalue, register, register])
                    instrs.append(addi)

                    slli = self.new_instruction("SLLI_V0")
                    slli.set_operands([8, register, register])
                    instrs.append(slli)
                    nvalue = int((value & 0x0000000000FF0000) >> 16)
                    addi = self.new_instruction("ADDI_V0")
                    addi.set_operands([nvalue, register, register])
                    instrs.append(addi)

                    slli = self.new_instruction("SLLI_V0")
                    slli.set_operands([8, register, register])
                    instrs.append(slli)
                    nvalue = int((value & 0x000000000000FF00) >> 8)
                    addi = self.new_instruction("ADDI_V0")
                    addi.set_operands([nvalue, register, register])
                    instrs.append(addi)

                    slli = self.new_instruction("SLLI_V0")
                    slli.set_operands([8, register, register])
                    instrs.append(slli)
                    nvalue = int((value & 0x00000000000000FF))
                    addi = self.new_instruction("ADDI_V0")
                    addi.set_operands([nvalue, register, register])
                    instrs.append(addi)

                else:

                    if value_lowest > 2047:
                        value_low = value_low + 1
                        value_lowest = value - (value_low << 12)

                    lui = self.new_instruction("LUI_V0")
                    lui.set_operands([value_low, register])

                    addiw = self.new_instruction("ADDIW_V0")
                    addiw.set_operands([value_lowest, register, register])
                    instrs.append(lui)
                    instrs.append(addiw)

            elif (value < -2147483648 or value >= 2147483647):

                instrs.extend(self.set_register(register,
                                                (value >> 32),
                                                context))

                instrs.extend(self.set_register(self._scratch_registers[0],
                                                (value & 0x00000000FFFFFFFF),
                                                context))

                slli = self.new_instruction("SLLI_V0")
                slli.set_operands([32, register, register])
                instrs.append(slli)

                and_inst = self.new_instruction("AND_V0")
                and_inst.set_operands(
                    [register, register, self._scratch_registers[0]])
                instrs.append(and_inst)

            elif (current_value is not None and
                  abs(value - current_value) < 2 * 12):

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([register, value - current_value])
                instrs.append(addi)

            elif (value < -2147483648 or value >= 2147483647):

                instrs.extend(self.set_register(register,
                                                (value >> 32),
                                                context))

                instrs.extend(self.set_register(self._scratch_registers[0],
                                                (value & 0x00000000FFFFFFFF),
                                                context))

                slli = self.new_instruction("SLLI_V0")
                slli.set_operands([32, register, register])
                instrs.append(slli)

                and_inst = self.new_instruction("AND_V0")
                and_inst.set_operands(
                    [register, register, self._scratch_registers[0]])
                instrs.append(and_inst)

            elif (current_value is not None and
                  abs(value - current_value) < 2 * 12):

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([register, value - current_value])
                instrs.append(addi)

            else:

                if value_lowest > 2047:
                    value_low = value_low + 1
                    value_lowest = value - (value_low << 12)

                lui = self.new_instruction("LUI_V0")
                lui.set_operands([value_low, register])
                addiw = self.new_instruction("ADDIW_V0")
                addiw.set_operands([value_lowest, register, register])
                instrs.append(lui)
                instrs.append(addiw)

        else:
            LOG.debug("Register: %s set to value %d",
                      register.name, value)
            raise NotImplementedError

        if len(instrs) > 0:
            return instrs

        return super(RISCVISA, self).set_register(register, value, context)

    def set_register_to_address(self,
                                register,
                                address,
                                context,
                                force_absolute=False,
                                force_relative=False
                                ):

        instrs = []

        LOG.debug("Begin setting '%s' to address '%s'", register, address)

        if isinstance(address.base_address, Variable):

            LOG.debug("Base address is a Variable: %s", address.base_address)
            closest = context.get_closest_address_value(address)

            if context.register_has_value(address):

                present_reg = context.registers_get_value(address)[0]
                displacement = 0
                LOG.debug("Address already in register '%s'", present_reg)

            elif closest is not None:

                present_reg, taddress = closest
                displacement = address.displacement - taddress.displacement
                LOG.debug("Closest value '%s' found in '%s'",
                          taddress,
                          present_reg)
                LOG.debug("Displacement needed: %s", displacement)

            elif context.register_has_value(
                    Address(base_address=address.base_address)):

                present_reg = context.registers_get_value(
                    Address(base_address=address.base_address))[0]
                displacement = address.displacement
                LOG.debug("Base address '%s' found in '%s'",
                          taddress,
                          present_reg)
                LOG.debug("Displacement needed: %s", displacement)

            else:

                present_reg = None
                displacement = None

            LOG.debug("Present_reg: %s", present_reg)
            LOG.debug("Displacement: %s", displacement)

            if present_reg is not None:

                if displacement != 0 and abs(displacement) < (2 ** 11):

                    addi_ins = self.new_instruction("ADDI_V0")
                    addi_ins.set_operands([displacement, present_reg,
                                           register])
                    instrs.append(addi_ins)

                    LOG.debug("Computing directly from context (short)")

                    return instrs

                if present_reg != register:
                    or_ins = self.new_instruction("OR_V0")
                    or_ins.set_operands([register, present_reg, present_reg])
                    instrs.append(or_ins)

                if displacement != 0:
                    instrs += self.add_to_register(register, displacement)

                LOG.debug("Computing directly from context (long)")

                return instrs

        if context.symbolic and not force_absolute and not force_relative:

            # TODO: This should be a call to the environment object because
            # the implementation depends on the environment

            # Base address can be an instruction label (str) or
            # a Variable instance
            basename = address.base_address
            if not isinstance(address.base_address, str):
                basename = address.base_address.name

            lui_ins = self.new_instruction("LUI_V0")
            lui_ins.operands()[1].set_value(register)
            lui_ins.operands()[0].set_value(
                "%%hi(%s)" % basename,
                check=False
            )

            instrs.append(lui_ins)

            addi_ins = self.new_instruction("ADDI_V0")
            addi_ins.operands()[1].set_value(register)
            addi_ins.operands()[2].set_value(register)
            addi_ins.operands()[0].set_value(
                "%%lo(%s)" % basename,
                check=False
            )
            instrs.append(addi_ins)

            if address.displacement != 0:
                instrs += self.add_to_register(register, address.displacement)

            LOG.debug("End Loading symbolic reference")

            return instrs

        raise NotImplementedError

    def load(self, register, address, context):

        raise NotImplementedError

    def load_float(self, register, address, context):

        ldi = self.new_instruction("FLD_V0")
        ldi.operands()[0].set_value(register)
        ldi.memory_operands()[0].set_address(address, context)
        return [ldi]

    def store_float(self, register, address, context):

        std = self.new_instruction("FSD_V0")
        std.operands()[0].set_value(register)
        std.memory_operands()[0].set_address(address, context)
        return [std]

    def store_integer(self, register, address, length, context):

        if length == 64:
            stg = self.new_instruction("SD_V0")
            stg.operands()[0].set_value(register)
            stg.memory_operands()[0].set_address(address, context)
            return [stg]
        elif length == 32:
            stg = self.new_instruction("SW_V0")
            stg.operands()[0].set_value(register)
            stg.memory_operands()[0].set_address(address, context)
            return [stg]
        else:
            raise NotImplementedError

    def set_register_bits(self, dummy_register, dummy_value, dummy_mask,
                          dummy_shift, dummy_context):

        raise NotImplementedError

    def store_decimal(
            self,
            dummy_address,
            dummy_length,
            dummy_value,
            dummy_context):

        raise NotImplementedError

    @property
    def program_counter(self):
        raise NotImplementedError

    def branch_unconditional_relative(self, source, target):

        LOG.debug("Source: %s", source)
        LOG.debug("Target: %s", target)

        raise NotImplementedError

    def add_to_register(self, register, value):

        instrs = []
        if register.type.name == "ireg" and isinstance(value, int):
            if abs(value) < 0x7FF:
                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([register, value])
                instrs.append(addi)
            else:
                raise NotImplementedError
        else:
            raise NotImplementedError

        return instrs

    def compare_and_branch(self, val1, val2, cond, target, context):

        raise NotImplementedError

    def nop(self):
        instr = self.new_instruction("ADDI_V0")
        instr.set_operands([0,
                            self.target.registers['X0'],
                            self.target.registers['X0']])
        return instr

    def negate_register(self, dummy_register, dummy_context):

        raise NotImplementedError

    @property
    def context_var(self):
        if self._context_var is None:
            self._context_var = VariableArray("%s_context_var" % self._name,
                                              "uint8_t", 600)
        return self._context_var

    def set_context(self, variable=None, tmpl_path=None):
        """ """
        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(
            RISCVISA,
            self).set_context(
            variable=variable,
            tmpl_path=tmpl_path)

    def get_context(self, variable=None, tmpl_path=None):
        """ """

        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(
            RISCVISA,
            self).get_context(
            variable=variable,
            tmpl_path=tmpl_path)

    def normalize_asm(self, mnemonic, operands):
        """ """

        if mnemonic == "FENCE":
            new_operands = []
            for operand in operands:
                value = 0
                if 'I' in operand:
                    value += 8
                if 'O' in operand:
                    value += 4
                if 'R' in operand:
                    value += 2
                if 'W' in operand:
                    value += 1
                new_operands.append(str(value))
            return mnemonic, new_operands

        return mnemonic, operands

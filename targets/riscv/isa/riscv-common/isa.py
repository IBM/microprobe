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
"""
Docstring
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os

# This party modules
import six

# Own modules
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import Instruction
from microprobe.code.var import Variable, VariableArray
from microprobe.target.isa import GenericISA
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import twocs_to_int, int_to_twocs
from microprobe.exceptions import MicroprobeCodeGenerationError

# Constants
LOG = get_logger(__name__)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_RISCV_PCREL_LABEL = 0

# Functions


# Classes
class RISCVISA(GenericISA):

    def __init__(self, name, descr, path, ins, regs, comparators, generators):
        super(RISCVISA, self).__init__(name, descr, path, ins, regs,
                                       comparators,
                                       generators)
        self._scratch_registers += [self.registers["X31"],
                                    self.registers["F7"]]
        self._control_registers += [reg for reg in self.registers.values()
                                    if reg.type.name == "rm"]
        self._control_registers += [reg for reg in self.registers.values()
                                    if reg.type.name == "SPR"]

    def set_register(self, register, value, context, opt=False):

        LOG.debug("Setting register: %s to value %d",
                  register.name, value)

        instrs = []

        current_value = context.get_register_value(register)
        closest_value = context.get_closest_value(value)

        if value == 0:
            present_reg = self.registers["X0"]

            if present_reg.type.name != register.type.name:
                present_reg = None

        elif context.register_has_value(value):
            present_reg = context.registers_get_value(value)[0]

            if present_reg.type.name != register.type.name:
                present_reg = None

        else:
            present_reg = None

        if register.type.name == "freg":

            LOG.debug("FP register")

            if present_reg is not None:

                LOG.debug("Value already present")

                instr = self.new_instruction("FSGNJ.S_V0")
                instr.set_operands([register, present_reg, present_reg])
                instrs.append(instr)

            else:

                LOG.debug("Setting value to scratch and "
                          "then move to FP register")

                instrs += self.set_register(self._scratch_registers[0], value,
                                            context)

                instr = self.new_instruction("FMV.D.X_V0")
                instr.set_operands([self._scratch_registers[0], register])
                instrs.append(instr)

        elif register.type.name == "ireg":

            LOG.debug("Integer register")

            if value == 0:

                LOG.debug("Zero value")

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([0, self.registers["X0"], register])
                instrs.append(addi)

            elif present_reg is not None:

                LOG.debug("Value already present")

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([0, present_reg, register])
                instrs.append(addi)

            elif (closest_value is not None and
                  abs(value - closest_value[1]) < (2 ** 12)):

                addi = self.new_instruction("ADDI_V0")
                addi.set_operands(
                    [value - closest_value[1], closest_value[0], register]
                )
                instrs.append(addi)

            else:

                if value <= 0:
                    value = int_to_twocs(value, 64)

                register = self._scratch_registers[0]

                value_highest = int((value & 0xFFFFF00000000000) >> 44)
                value_high = int((value & 0x00000FFF00000000) >> 32)
                value_low = int((value & 0x00000000FFFFF000) >> 12)
                value_lowest = int((value & 0x0000000000000FFF))

                if register == self._scratch_registers[0] and \
                   (value_highest != 0 or value_high != 0):

                    binstr = "{0:>064b}".format(value)
                    size = 11

                    sidx = binstr.find('1')
                    fidx = min(sidx+size, 64)

                    val = int(binstr[sidx:fidx], 2)
                    if val != 0:
                        addi = self.new_instruction("ADDI_V0")
                        addi.set_operands(
                            [val, self.registers["X0"], register]
                        )
                        instrs.append(addi)

                    sidx2 = binstr.find('1', fidx)
                    fidx2 = min(sidx2+size, 64)

                    tshift = fidx2

                    while fidx2-fidx > 0:
                        slli = self.new_instruction("SLLI_V0")
                        slli.set_operands([fidx2-fidx, register, register])
                        instrs.append(slli)

                        tshift = fidx2-fidx - tshift

                        val = int(binstr[sidx2:fidx2], 2)
                        if val != 0:
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands([val, register, register])
                            instrs.append(addi)

                        sidx = sidx2
                        fidx = fidx2
                        sidx2 = binstr.find('1', fidx)
                        fidx2 = min(sidx2+size, 64)

                    if fidx < 64:
                        slli = self.new_instruction("SLLI_V0")
                        slli.set_operands([64-fidx, register, register])
                        instrs.append(slli)

                    LOG.debug(
                        "Register: %s set to value %d", register.name, value
                    )

                    return instrs

                if value_highest != 0:
                    lui = self.new_instruction("LUI_V0")
                    lui.set_operands([value_highest, register])
                    instrs.append(lui)

                if value_highest == 0 and value_high != 0:
                    if value_high > 2047:
                        addi = self.new_instruction("ADDI_V0")
                        addi.set_operands(
                            [2047, self.registers["X0"], register]
                        )
                        instrs.append(addi)
                        cvalue = value_high
                        while (cvalue > 2047):
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands([2047, register, register])
                            instrs.append(addi)
                            cvalue = cvalue - 2047
                        addi = self.new_instruction("ADDI_V0")
                        addi.set_operands([cvalue, register, register])
                        instrs.append(addi)
                    else:
                        addi = self.new_instruction("ADDI_V0")
                        addi.set_operands(
                            [value_high, self.registers["X0"], register]
                        )
                        instrs.append(addi)

                elif value_highest != 0 and value_high != 0:
                    if value_high > 2047:
                        cvalue = value_high
                        while (cvalue > 2047):
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands([2047, register, register])
                            instrs.append(addi)
                            cvalue = cvalue - 2047
                        addi = self.new_instruction("ADDI_V0")
                        addi.set_operands([cvalue, register, register])
                        instrs.append(addi)
                    else:
                        addi = self.new_instruction("ADDI_V0")
                        addi.set_operands([value_high, register, register])
                        instrs.append(addi)

                if value_highest != 0 or value_high != 0:
                    slli = self.new_instruction("SLLI_V0")
                    slli.set_operands([32, register, register])
                    instrs.append(slli)

                if value_highest == 0 or value_high == 0:

                    if value_low != 0:
                        lui = self.new_instruction("LUI_V0")
                        lui.set_operands([value_low, register])
                        instrs.append(lui)

                    if value_low == 0 and value_lowest != 0:
                        if value_lowest > 2047:
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands(
                                [2047, self.registers["X0"], register]
                            )
                            instrs.append(addi)
                            cvalue = value_lowest
                            while (cvalue > 2047):
                                addi = self.new_instruction("ADDI_V0")
                                addi.set_operands([2047, register, register])
                                instrs.append(addi)
                                cvalue = cvalue - 2047
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands([cvalue, register, register])
                            instrs.append(addi)
                        else:
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands(
                                [value_lowest, self.registers["X0"], register]
                            )
                            instrs.append(addi)
                    elif value_low != 0 and value_lowest != 0:
                        if value_lowest > 2047:
                            cvalue = value_lowest
                            while (cvalue > 2047):
                                addi = self.new_instruction("ADDI_V0")
                                addi.set_operands([2047, register, register])
                                instrs.append(addi)
                                cvalue = cvalue - 2047
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands([cvalue, register, register])
                            instrs.append(addi)
                        else:
                            addi = self.new_instruction("ADDI_V0")
                            addi.set_operands(
                                [value_lowest, register, register]
                            )
                            instrs.append(addi)
                else:
                    instrs.extend(
                        self.set_register(
                            self._scratch_registers[0],
                            (value & 0x00000000FFFFFFFF),
                            context
                        )
                    )
                    add_inst = self.new_instruction("ADD_V0")
                    add_inst.set_operands(
                        [register, self._scratch_registers[0], register])
                    instrs.append(add_inst)

                LOG.debug("Register: %s set to value %d",
                          register.name, value)

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

        option_displacement = None
        option_label = None

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

                    option_displacement = instrs
                    instrs = []

                if present_reg != register and option_displacement is None:
                    or_ins = self.new_instruction("OR_V0")
                    or_ins.set_operands([present_reg, present_reg, register])
                    instrs.append(or_ins)

                if displacement != 0 and option_displacement is None:
                    instrs += self.add_to_register(register, displacement)

                LOG.debug("Computing directly from context (long)")
                if option_displacement is None:
                    option_displacement = instrs
                    instrs = []

        if context.symbolic and not force_absolute and not force_relative:

            instrs = []

            # TODO: This should be a call to the environment object because
            # the implementation depends on the environment

            # Base address can be an instruction label (str) or
            # a Variable instance
            basename = address.base_address
            basedisp = ""
            if not isinstance(address.base_address, str):
                basename = address.base_address.name
                if address.displacement >= 0:
                    basedisp = "+0x%016X" % address.displacement
                else:
                    basedisp = "-0x%016X" % abs(address.displacement)

            global _RISCV_PCREL_LABEL
            _RISCV_PCREL_LABEL += 1
            lnum = _RISCV_PCREL_LABEL

            auipc_ins = self.new_instruction("AUIPC_V0")
            auipc_ins.operands()[1].set_value(register)
            auipc_ins.operands()[0].set_value(
                "%%pcrel_hi(%s)" % basename + basedisp,
                check=False
            )
            auipc_ins.set_label(
                "%s_pcrel_%d" % (basename, lnum)
            )

            instrs.append(auipc_ins)

            addi_ins = self.new_instruction("ADDI_V0")
            addi_ins.operands()[1].set_value(register)
            addi_ins.operands()[2].set_value(register)
            addi_ins.operands()[0].set_value(
                "%%pcrel_lo(%s_pcrel_%d)" % (basename, lnum),
                check=False
            )
            instrs.append(addi_ins)

            # if address.displacement != 0:
            #     instrs += self.add_to_register(register,
            #     address.displacement)

            LOG.debug("End Loading symbolic reference")

            option_label = instrs

        if option_label is None and option_displacement is None:
            raise NotImplementedError
        elif option_label is None:
            return option_displacement
        elif option_displacement is None:
            return option_label
        if len(option_label) <= len(option_displacement):
            return option_label
        else:
            return option_displacement

    def load(self, register, address, context):

        ldi = self.new_instruction("LD_V0")
        ldi.operands()[2].set_value(register)
        ldi.memory_operands()[0].set_address(address, context)
        return [ldi]

    def load_float(self, register, address, context):

        ldi = self.new_instruction("FLD_V0")
        ldi.operands()[2].set_value(register)
        ldi.memory_operands()[0].set_address(address, context)
        return [ldi]

    def store_float(self, register, address, context):

        std = self.new_instruction("FSD_V0")
        std.operands()[2].set_value(register)
        std.memory_operands()[0].set_address(address, context)
        return [std]

    def store_integer(self, register, address, length, context):

        if length == 64:
            stg = self.new_instruction("SD_V0")
            stg.operands()[2].set_value(register)
            stg.memory_operands()[0].set_address(address, context)
            return [stg]
        elif length == 32:
            stg = self.new_instruction("SW_V0")
            stg.operands()[2].set_value(register)
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

        if isinstance(target, InstructionAddress):
            target_address = target
        elif isinstance(target, Instruction):
            target_address = target.address
        else:
            print(("Target:", target))
            raise NotImplementedError

        if target.base_address != source.base_address:
            # Assume symbolic generation
            instruction = self.new_instruction("JAL_V0")
            source_address = source
            instruction.set_address(source_address)
            instruction.operands()[1].set_value(self.target.registers['X0'])
            instruction.memory_operands()[0].set_address(target_address, None)
            return instruction

        elif isinstance(source, InstructionAddress):
            source_address = source

            relative_offset = target_address - source_address

            instruction = self.new_instruction("JAL_V0")
            instruction.set_address(source_address)
            instruction.operands()[1].set_value(self.target.registers['X0'])

            LOG.debug("Source address: %s", source_address)
            LOG.debug("Target address: %s", target_address)
            LOG.debug("Relative offset: %s", relative_offset)

        elif isinstance(source, Instruction):
            source_address = source.address
            relative_offset = target_address - source_address
            instruction = source
        else:
            print(("Source:", source))
            raise NotImplementedError

        for operand in instruction.operands():
            if not operand.type.address_relative:
                continue

            operand.set_value(relative_offset)

        return instruction

    def add_to_register(self, register, value):

        instrs = []
        if register.type.name == "ireg" and isinstance(value,
                                                       six.integer_types):

            if value > 0:
                while(value) > 0x7FF:
                    addi = self.new_instruction("ADDI_V0")
                    addi.set_operands([0x7FF, register, register])
                    instrs.append(addi)
                    value = value - 0x7FF
            elif value < 0:
                while(value) < -0x7FF:
                    addi = self.new_instruction("ADDI_V0")
                    addi.set_operands([-0x7FF, register, register])
                    instrs.append(addi)
                    value = value + 0x7FF

            if abs(value) != 0:
                addi = self.new_instruction("ADDI_V0")
                addi.set_operands([value, register, register])
                instrs.append(addi)
        else:
            raise NotImplementedError

        return instrs

    def compare_and_branch(self, val1, val2, cond, target, context):

        assert cond in ["<", ">", "!=", "=", ">=", "<="]
        instrs = []

        # put all values into registers
        if isinstance(val1, int) and isinstance(val1, six.integer_types):
            raise NotImplementedError
        elif isinstance(val1, six.integer_types):
            instrs += self.set_register(
                self.scratch_registers[0], val1, context
            )
            val1 = self.scratch_registers[0]
        elif isinstance(val2, six.integer_types):
            instrs += self.set_register(
                self.scratch_registers[0], val2, context
            )
            val2 = self.scratch_registers[0]

        if isinstance(target, str):
            target = InstructionAddress(base_address=target)

        if cond == ">":
            cond = "<"
            val1, val2 = val2, val1
        if cond == "<=":
            cond = ">="
            val1, val2 = val2, val1

        if cond == "=":
            bc_ins = self.new_instruction("BEQ_V0")
        elif cond == "!=":
            bc_ins = self.new_instruction("BNE_V0")
        elif cond == "<":
            bc_ins = self.new_instruction("BLT_V0")
        elif cond == ">=":
            bc_ins = self.new_instruction("BGE_V0")
        else:
            raise NotImplementedError

        bc_ins.set_operands([target, val2, val1, 0])
        instrs.append(bc_ins)
        return instrs

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
        elif mnemonic == "C.JR" or mnemonic == "C.JALR":
            operands.append('X0')
            return mnemonic, operands
        else:
            # Remove the implicit stack pointer operand from all instructions
            new_operands = [op for op in operands if op != "SP"]

            return mnemonic, new_operands

    def randomize_register(self, register, seed=None):

        instrs = []

        ins = self.new_instruction("MUL_V0")
        ins.set_operands([register, register, register])
        instrs.append(ins)

        if seed is not None:
            ins = self.new_instruction("ADD_V0")
            ins.set_operands([seed, register, register])
            instrs.append(ins)

        ins = self.new_instruction("SRLI_V0")
        ins.set_operands([32, register, self._scratch_registers[0]])
        instrs.append(ins)

        ins = self.new_instruction("SLLI_V0")
        ins.set_operands([32, register, register])
        instrs.append(ins)

        ins = self.new_instruction("OR_V0")
        ins.set_operands([self._scratch_registers[0], register, register])
        instrs.append(ins)

        return instrs

    def get_register_for_address_arithmetic(self, context):
        """

        :param context:

        """
        reg = [
            reg
            for reg in self._address_registers
            if reg not in context.reserved_registers
            and int(reg.codification) >= 8 and int(reg.codification) <= 15
        ]

        reg += [
            reg
            for reg in self._address_registers
            if reg not in context.reserved_registers
            and int(reg.codification) < 8 and int(reg.codification) > 15
        ]

        if len(reg) == 0:
            raise MicroprobeCodeGenerationError(
                "No free registers available. "
                "Change your policy."
            )

        return reg[0]

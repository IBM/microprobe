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
from __future__ import absolute_import, division, print_function

# Built-in modules
import os

# This party modules
import six

# Own modules
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import Instruction
from microprobe.code.var import Variable, VariableArray
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.target.isa import GenericISA
from microprobe.target.isa.register import Register
from microprobe.utils.logger import get_logger

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
__all__ = ["PowerISA"]
LOG = get_logger(__name__)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# Functions


# Classes
class PowerISA(GenericISA):

    def __init__(self, name, descr, path, ins, regs, comparators, generators):
        super(PowerISA, self).__init__(name, descr, path, ins, regs,
                                       comparators,
                                       generators)
        self._scratch_registers += [self.registers["GPR11"],
                                    self.registers["GPR12"],
                                    self.registers["FPR28"],
                                    self.registers["FPR29"],
                                    self.registers["VSR28"],
                                    self.registers["VSR29"],
                                    self.registers["CR4"],
                                    # self.registers["VR28"],
                                    # self.registers["VR29"],
                                    # self.registers["VSR60"],
                                    # self.registers["VSR61"],
                                    ]
        self._control_registers += [reg for reg in self.registers.values()
                                    if reg.type.name == "SPR"] + \
                                   [reg for reg in self.registers.values()
                                    if reg.type.name == "SPR32"] + \
                                   [self.registers["FPSCR"],
                                    self.registers["MSR"],
                                    self.registers["VSCR"]]

        # self._control_registers += [reg for reg in self.registers.values()
        #                            if reg.type.name == "CR"]

    def set_register(self, register, value, context, opt=True):

        LOG.debug("Begin setting '%s' to value '%s'", register, value)
        instrs = []

        current_value = context.get_register_value(register)

        force_reset = False
        if isinstance(current_value, Address):
            force_reset = True

        closest_register = context.get_register_closest_value(register)

        if closest_register is not None:
            closest_value = context.get_register_value(closest_register)
        else:
            closest_value = None

        if context.register_has_value(value):
            present_reg = context.registers_get_value(value)[0]

            if present_reg.type.name != register.type.name:
                present_reg = None

        else:
            present_reg = None

        if register.type.name == "FPR":

            if present_reg is not None:

                fmr_ins = self.new_instruction("FMR_V0")
                fmr_ins.set_operands([register, present_reg])
                instrs.append(fmr_ins)

            else:

                instrs += self.set_register(self.scratch_registers[0],
                                            value,
                                            context)

                if not context.register_has_value(self.scratch_var.address):

                    instrs += self.set_register_to_address(
                        self.scratch_registers[1],
                        self.scratch_var.address,
                        context)
                    ldstore_reg = self._scratch_registers[1]

                else:

                    ldstore_reg = context.registers_get_value(
                        self.scratch_var.address)[0]

                std_ins = self.new_instruction("STD_V0")
                std_ins.set_operands([self.scratch_registers[0],
                                      ldstore_reg,
                                      0])
                instrs.append(std_ins)

                ld_ins = self.new_instruction("LFD_V0")
                ld_ins.set_operands([register, ldstore_reg, 0])
                instrs.append(ld_ins)

        elif register.type.name == "GPR":

            value_highest = int((value & 0xFFFF000000000000) >> 48)
            value_higher = int((value & 0x0000FFFF00000000) >> 32)
            value_high = int((value & 0x00000000FFFF0000) >> 16)
            value_low = int((value & 0x000000000000FFFF))

            if present_reg is not None and present_reg == register:
                # The value is already in the register
                return []
            elif value >= -32768 and value <= 32767 and opt:

                li_ins = self.new_instruction("ADDI_V1")
                li_ins.set_operands([register, 0, value])
                instrs.append(li_ins)

            elif present_reg is not None and opt:

                or_ins = self.new_instruction("OR_V0")
                or_ins.set_operands([present_reg, register, present_reg])
                instrs.append(or_ins)

            elif (not force_reset and current_value is not None and
                  abs(value - current_value) <= 32767 and opt):

                addi_ins = self.new_instruction("ADDI_V0")
                addi_ins.set_operands([register, register,
                                       value - current_value])
                instrs.append(addi_ins)

            elif (closest_value is not None and
                  abs(value - closest_value) <= 32767 and opt):

                addi_ins = self.new_instruction("ADDI_V0")
                addi_ins.set_operands([register, closest_register,
                                       value - closest_value])
                instrs.append(addi_ins)

            elif value >= -2147483648 and value <= 2147483647 and opt:

                if value_high > 32767:
                    # Negative
                    value_high = (2**16 - value_high) * -1

                lis_ins = self.new_instruction("ADDIS_V1")
                lis_ins.set_operands([register, 0, value_high])
                instrs.append(lis_ins)

                ori_ins = self.new_instruction("ORI_V0")
                ori_ins.set_operands([register, register, value_low])
                instrs.append(ori_ins)

            else:

                if value_highest > 32767:
                    # Negative
                    value_highest = (2**16 - value_highest) * -1

                lis_ins = self.new_instruction("ADDIS_V1")
                lis_ins.set_operands([register, 0, value_highest])
                instrs.append(lis_ins)

                ori_ins = self.new_instruction("ORI_V0")
                ori_ins.set_operands([register, register, value_higher])
                instrs.append(ori_ins)

                rldicr_ins = self.new_instruction("RLDICR_V0")
                rldicr_ins.set_operands([register, register, 32, 31])
                instrs.append(rldicr_ins)

                oris_ins = self.new_instruction("ORIS_V0")
                oris_ins.set_operands([register, register, value_high])
                instrs.append(oris_ins)

                ori_ins = self.new_instruction("ORI_V0")
                ori_ins.set_operands([register, register, value_low])
                instrs.append(ori_ins)

        elif register.type.name == "CR":

            if value > 15 and value < 0:
                LOG.warning("User trying to set a CR register with an invalid "
                            "value (%d) ", str(value))

            value_4bits = int((value & 0x000000000000000F))

            instrs += self.set_register(self.scratch_registers[0],
                                        value_4bits,
                                        context)

            fxm_mask = int("".join(
                list(reversed("{0:08b}".format(2 ** int(
                    register.representation))))), 2)

            mtocrf_ins = self.new_instruction("MTOCRF_V0")
            mtocrf_ins.set_operands([self.scratch_registers[0], fxm_mask])
            instrs.append(mtocrf_ins)

        elif register.type.name == "VR" or register.type.name == "VSR":

            if present_reg is not None:

                if register.type.name == "VR":

                    vor_ins = self.new_instruction("VOR_V0")
                    vor_ins.set_operands([register, present_reg, present_reg])
                    instrs.append(vor_ins)

                else:

                    xxlor_ins = self.new_instruction("XXLOR_V0")
                    xxlor_ins.set_operands([register, present_reg,
                                            present_reg])
                    instrs.append(xxlor_ins)

            else:

                if not context.register_has_value(self.scratch_var.address):
                    if self.scratch_var.address is None and context.symbolic:
                        # Assume symbolic
                        instrs += self.set_register_to_address(
                            self.scratch_registers[1],
                            Address(base_address=self.scratch_var.name),
                            context)
                    else:
                        instrs += self.set_register_to_address(
                            self.scratch_registers[1],
                            self.scratch_var.address,
                            context)

                if len(str(value).split("_")) == 2:

                    # Value format: <value>_<bit_size>
                    item_value = int(str(value).split("_")[0], base=0)
                    item_size = int(str(value).split("_")[1], base=10)
                    item_format_str = "%%0%dx" % (item_size // 4)
                    value = int((item_format_str %
                                 item_value) * (128 // item_size), 16)

                elif len(str(value).split("_")) == 1:
                    pass
                else:
                    raise NotImplementedError("Unknown value format")

                value_high = int((value & 0x0000000000000000FFFFFFFFFFFFFFFF))
                value_low = int((value &
                                 0xFFFFFFFFFFFFFFFF0000000000000000) >> 64)

                instrs += self.set_register(self.scratch_registers[0],
                                            value_high,
                                            context)

                std_ins = self.new_instruction("STD_V0")
                std_ins.set_operands([self.scratch_registers[0],
                                      self.scratch_registers[1],
                                      8])
                instrs.append(std_ins)

                instrs += self.set_register(self.scratch_registers[0],
                                            value_low,
                                            context)

                std_ins = self.new_instruction("STD_V0")
                std_ins.set_operands([self.scratch_registers[0],
                                      self.scratch_registers[1],
                                      0])
                instrs.append(std_ins)

                if register.type.name == "VR":

                    lvx_ins = self.new_instruction("LVX_V1")
                    lvx_ins.set_operands([register,
                                          self.registers["GPR0"],
                                          self.scratch_registers[1]])
                    instrs.append(lvx_ins)

                else:

                    # TODO: make sure we use the version where GPR0 is zero
                    lxvd2x_ins = self.new_instruction("LXVD2X_V1")
                    lxvd2x_ins.set_operands([register,
                                             self.registers["GPR0"],
                                             self.scratch_registers[1]])
                    instrs.append(lxvd2x_ins)

        elif register.type.name in ["SPR", "SPR32"]:

            instrs += self.set_register(self.scratch_registers[0],
                                        value,
                                        context)

            # Skip code generation for register that are
            # not architected
            if register.representation == 'N/A':
                return []

            if register.type.name in ["SPR"]:
                mtspr = self.new_instruction("MTSPR_V0")
            else:
                mtspr = self.new_instruction("MTSPR_V2")
            mtspr.set_operands([self.scratch_registers[0], register])
            instrs.append(mtspr)

        if len(instrs) > 0:
            return instrs

        return super(PowerISA, self).set_register(register, value, context)

    def negate_register(self, register, dummy_context):

        instrs = []

        if register.type.name == "FPR":
            # FPRs map to VSRs
            register_name = "VSR%s" % register.representation
            register = self.registers[register_name]

        if register.type.name == "GPR":
            instr = self.new_instruction("NOR_V0")
            instr.set_operands([register, register, register])
            instrs.append(instr)
        elif register.type.name == "CR":
            raise NotImplementedError
        elif register.type.name == "VSR":
            instr = self.new_instruction("XXLNOR_V0")
            instr.set_operands([register, register, register])
            instrs.append(instr)
        elif register.type.name == "VR":
            instr = self.new_instruction("XXLNOR_V0")
            reg = int(register.representation)
            register = self.registers["VSR%d" % (reg + 32)]
            instr.set_operands([register, register, register])
        elif register.type.name == "SPR":
            raise NotImplementedError

        return instrs

    def set_register_to_address(self, register, address, context,
                                force_absolute=False,
                                force_relative=False):
        instrs = []

        assert address is not None

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

                if displacement != 0 and abs(displacement) < (2 ** 15):

                    addi_ins = self.new_instruction("ADDI_V0")
                    addi_ins.set_operands([register, present_reg,
                                           displacement])
                    instrs.append(addi_ins)

                    LOG.debug("Computing directly from context (short)")

                    return instrs

                if present_reg != register:
                    or_ins = self.new_instruction("OR_V0")
                    or_ins.set_operands([present_reg, register, present_reg])
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

            lis_ins = self.new_instruction("ADDIS_V1")
            lis_ins.operands()[0].set_value(register)
            lis_ins.operands()[1].set_value(0)
            lis_ins.operands()[2].set_value(
                "%s@highest" % basename,
                check=False
            )

            instrs.append(lis_ins)

            ori_ins = self.new_instruction("ORI_V0")
            ori_ins.operands()[0].set_value(register)
            ori_ins.operands()[1].set_value(register)
            ori_ins.operands()[2].set_value(
                "%s@higher" % basename,
                check=False
            )
            instrs.append(ori_ins)

            rldicr_ins = self.new_instruction("RLDICR_V0")
            rldicr_ins.set_operands([register, register, 32, 31])
            instrs.append(rldicr_ins)

            oris_ins = self.new_instruction("ORIS_V0")
            oris_ins.operands()[0].set_value(register)
            oris_ins.operands()[1].set_value(register)
            oris_ins.operands()[2].set_value(
                "%s@h" % basename,
                check=False
            )
            instrs.append(oris_ins)

            ori_ins = self.new_instruction("ORI_V0")
            ori_ins.operands()[0].set_value(register)
            ori_ins.operands()[1].set_value(register)
            ori_ins.operands()[2].set_value(
                "%s@l" % basename,
                check=False
            )
            instrs.append(ori_ins)

            if address.displacement != 0:
                instrs += self.add_to_register(register, address.displacement)

            LOG.debug("End Loading symbolic reference")

            return instrs

        LOG.debug("Context not symbolic")

        base_address = address.base_address
        displacement = address.displacement

        LOG.debug("Base_address: %s", base_address)
        LOG.debug("Displacement: %s", displacement)

        if isinstance(base_address, Variable):
            LOG.debug("Get absolute address")
            displacement += base_address.address.displacement
            base_address = base_address.address.base_address

        LOG.debug("Base_address 2: %s", base_address)
        LOG.debug("Displacement 2: %s", displacement)

        if isinstance(base_address, str):

            if base_address == "data":
                base_address = Address(base_address=base_address)
            elif base_address == "code":
                base_address = InstructionAddress(
                    base_address=base_address)

        source_register = None
        if context.register_has_value(base_address):
            source_register = context.registers_get_value(base_address)[0]
        else:

            for reg, value in context.register_values.items():
                if not isinstance(value, Address):
                    continue

                if (Address(base_address=value.base_address) ==
                        base_address.base_address):

                    source_register = reg
                    displacement += base_address.displacement
                    base_address = Address(
                        base_address=base_address.base_address)
                    break

                if value.base_address == base_address.base_address:
                    source_register = reg
                    displacement += base_address.displacement
                    base_address = Address(
                        base_address=base_address.base_address)
                    break

        if source_register is None or displacement >= (2 ** 31):
            # Not source register found
            if base_address.base_address == "data":
                value = context.data_segment
            elif base_address.base_address == "code":
                value = context.code_segment
            else:
                LOG.debug(context.dump())
                raise MicroprobeCodeGenerationError(
                    "Unable to generate "
                    "the base address: '%s'"
                    " for target address: '%s'."
                    % (base_address, address)
                )

            if abs(displacement) >= (2 ** 31):
                value = value + displacement
                displacement = 0

            instrs += self.set_register(register, value, context)

        if source_register is not None and source_register != register:
            or_ins = self.new_instruction("OR_V0")
            or_ins.set_operands([source_register, register, source_register])
            instrs.append(or_ins)

        if displacement != 0:
            instrs += self.add_to_register(register, displacement)

        LOG.debug("End address generation")
        return instrs

    # TODO: change API to support length parameter
    def load(self, register, address, context):

        # TODO: Ensure RA is not zero
        ld_ins = self.new_instruction("LD_V0")
        ld_ins.operands()[0].set_value(register)
        ld_ins.memory_operands()[0].set_address(address, context)
        return [ld_ins]

    # TODO: change API to support single/double precission (length parameter)
    def load_float(self, register, address, context):

        # TODO: Ensure RA is not zero
        lfd_ins = self.new_instruction("LFD_V0")
        lfd_ins.operands()[0].set_value(register)
        lfd_ins.memory_operands()[0].set_address(address, context)
        return [lfd_ins]

    # TODO: change API to support single/double precission (length parameter)
    def store_float(self, register, address, context):

        # TODO: Ensure RA is not zero
        stfd_ins = self.new_instruction("STFD_V0")
        stfd_ins.operands()[0].set_value(register)
        stfd_ins.memory_operands()[0].set_address(address, context)
        return [stfd_ins]

    def store_integer(self, register, address, length, context):

        if length == 64:
            std_ins = self.new_instruction("STD_V0")
            std_ins.operands()[0].set_value(register)
            std_ins.memory_operands()[0].set_address(address, context)
            return [std_ins]
        elif length == 32:
            stw_ins = self.new_instruction("STW_V0")
            stw_ins.operands()[0].set_value(register)
            stw_ins.memory_operands()[0].set_address(address, context)
            return [stw_ins]
        elif length == 16:
            sth_ins = self.new_instruction("STH_V0")
            sth_ins.operands()[0].set_value(register)
            sth_ins.memory_operands()[0].set_address(address, context)
            return [sth_ins]
        elif length == 8:
            stb_ins = self.new_instruction("STB_V0")
            stb_ins.operands()[0].set_value(register)
            stb_ins.memory_operands()[0].set_address(address, context)
            return [stb_ins]
#        elif length == 128:
#            std_ins1 = self.new_instruction("STD_V0")
#            std_ins1.operands()[0].set_value(register)
#            std_ins1.memory_operands()[0].set_address(address, context)
#            std_ins2 = self.new_instruction("STD_V0")
#            std_ins2.operands()[0].set_value(register)
#            std_ins2.memory_operands()[0].set_address(address + 8, context)
#            return [std_ins1, std_ins2]
        elif length == 256:
            std_ins1 = self.new_instruction("STD_V0")
            std_ins1.operands()[0].set_value(register)
            std_ins1.memory_operands()[0].set_address(address, context)
            std_ins2 = self.new_instruction("STD_V0")
            std_ins2.operands()[0].set_value(register)
            std_ins2.memory_operands()[0].set_address(address + 8, context)
            std_ins3 = self.new_instruction("STD_V0")
            std_ins3.operands()[0].set_value(register)
            std_ins3.memory_operands()[0].set_address(address + 16, context)
            std_ins4 = self.new_instruction("STD_V0")
            std_ins4.operands()[0].set_value(register)
            std_ins4.memory_operands()[0].set_address(address + 24, context)
            return [std_ins1, std_ins2, std_ins3, std_ins4]
        else:
            raise NotImplementedError("Request store length: %d" % length)

    def set_register_bits(self, register, value, mask, shift, context):

        raise NotImplementedError

    def store_decimal(self, address, length, value, context):

        instrs = []
        instrs += self.set_register(self.scratch_registers[3], value, context)

        if length == 64:

            dcffix_ins = self.new_instruction("DCFFIX_V0")
            dcffix_ins.set_operands([self.scratch_registers[2],
                                     self.scratch_registers[3]])
            instrs.append(dcffix_ins)
            instrs += self.store_float(self.scratch_registers[2],
                                       address, context)

        elif length == 128:

            dcffixq_ins = self.new_instruction("DCFFIXQ_V0")
            dcffixq_ins.set_operands([self.scratch_registers[2],
                                      self.scratch_registers[3]])
            instrs.append(dcffixq_ins)

            # TODO: This assumes a 64-bit store
            instrs += self.store_float(self.scratch_registers[2],
                                       address, context)
            instrs += self.store_float(self.scratch_registers[3],
                                       address + 8, context)

        else:

            raise NotImplementedError

        return instrs

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
            raise NotImplementedError

        if isinstance(source, InstructionAddress):

            source_address = source
            relative_offset = target_address - source_address

            instruction = self.new_instruction("B_V0")
            instruction.set_address(source_address)

            LOG.debug("Source address: %s", source_address)
            LOG.debug("Target address: %s", target_address)
            LOG.debug("Relative offset: %s", relative_offset)

        elif isinstance(source, Instruction):
            source_address = source.address
            relative_offset = target_address - source_address
            instruction = source
        else:
            raise NotImplementedError

        for operand in instruction.operands():
            if not operand.type.address_relative:
                continue

            operand.set_value(relative_offset)

        return instruction

    def add_to_register(self, register, value):

        instrs = []

        if register.type.name == "GPR" and isinstance(value,
                                                      six.integer_types):

            origreg = None
            if register.name == "GPR0":
                origreg = register
                register = self._scratch_registers[0]
                or_ins = self.new_instruction("OR_V0")
                or_ins.set_operands([origreg, register, origreg])
                instrs.append(or_ins)

            if abs(value) >= (2 ** 31):

                raise NotImplementedError

            if abs(value) >= (2 ** 16):

                shift_value = value // (2 ** 16)

                addis_ins = self.new_instruction("ADDIS_V0")
                addis_ins.set_operands([register, register, shift_value])
                instrs.append(addis_ins)

                value = value - (shift_value * (2 ** 16))

            if abs(value) < (2 ** 15):

                if register.name != "GPR0":
                    addi_ins = self.new_instruction("ADDI_V0")
                    addi_ins.set_operands([register, register, value])
                else:
                    addi_ins = self.new_instruction("ADDI_V1")
                    addi_ins.set_operands([register, 0, value])

                instrs.append(addi_ins)

            else:

                assert abs(value) >= (2**15) and abs(value) < (2**16)
                instrs = self.add_to_register(
                    register, value // 2) + \
                    self.add_to_register(register,
                                         (value // 2) + (value % 2))

            if origreg is not None:
                or_ins = self.new_instruction("OR_V0")
                or_ins.set_operands([register, origreg, register])
                instrs.append(or_ins)

        else:

            raise NotImplementedError

        return instrs

    # TODO: change API to take into account operand length (now 64-bits)
    def compare_and_branch(self, val1, val2, cond, target, context):

        assert cond in ["<", ">", "!=", "=", ">=", "<="]

        instrs = []

        if isinstance(val1, Register) and isinstance(val2, six.integer_types):

            cmpi_ins = self.new_instruction("CMPI_V0")
            cmpi_ins.set_operands([self.scratch_registers[6], 1, val1, val2])
            for reg in cmpi_ins.sets() + cmpi_ins.uses():
                if reg not in cmpi_ins.allowed_regs:
                    cmpi_ins.add_allow_register(reg)
            instrs.append(cmpi_ins)

        elif isinstance(val1, Register) and isinstance(val2, Register):

            assert val1.type.name == val2.type.name

            if val1.type.name == "GPR":

                cmp_ins = self.new_instruction("CMP_V0")
                cmp_ins.set_operands([self.scratch_registers[6], 1,
                                      val1, val2])
                instrs.append(cmp_ins)

            elif val1.type.name == "FPR":

                fcmpu_ins = self.new_instruction("FCMPU_V0")
                fcmpu_ins.set_operands([self.scratch_registers[6],
                                        val1, val2])
                instrs.append(fcmpu_ins)

            else:

                raise NotImplementedError

        else:

            raise NotImplementedError

        # Fix to use BF 4 of the CR register (it is set in the
        # reserved list of registers
        cr_field = 4

        if cond == "<":

            bo_value = 12
            bi_value = (cr_field * 4) + 0

        elif cond == ">=":

            bo_value = 4
            bi_value = (cr_field * 4) + 0

        elif cond == ">":

            bo_value = 12
            bi_value = (cr_field * 4) + 1

        elif cond == "<=":

            bo_value = 4
            bi_value = (cr_field * 4) + 1

        elif cond == "=":

            bo_value = 12
            bi_value = (cr_field * 4) + 2

        elif cond == "!=":

            bo_value = 4
            bi_value = (cr_field * 4) + 2

        else:

            raise NotImplementedError

        bc_ins = self.new_instruction("BC_V0")
        bc_ins.operands()[0].set_value(bo_value)
        bc_ins.operands()[1].set_value(bi_value)

        for operand in bc_ins.memory_operands():

            if operand.is_branch_target:
                taddress = InstructionAddress(base_address=target)
                operand.set_address(taddress, context)
                break

        instrs.append(bc_ins)

        return instrs

    def nop(self):
        instr = self.new_instruction("ORI_V1")
        for operand in instr.operands():
            value = list(operand.type.values())[0]
            operand.set_value(value)
        return instr

    @property
    def context_var(self):
        if self._context_var is None:
            self._context_var = VariableArray("%s_context_var" % self._name,
                                              "uint8_t", 1600)
        return self._context_var

    def set_context(self, variable=None, tmpl_path=None):
        """ """
        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(
            PowerISA,
            self).set_context(
            variable=variable,
            tmpl_path=tmpl_path)

    def get_context(self, variable=None, tmpl_path=None):
        """ """

        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(
            PowerISA,
            self).get_context(
            variable=variable,
            tmpl_path=tmpl_path)

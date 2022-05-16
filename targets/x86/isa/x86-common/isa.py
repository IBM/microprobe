# Copyright 2022 IBM Corporation
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

# Built-in modules
import os

# Third party modules
import six

# Own modules
from microprobe.target.isa import GenericISA
from microprobe.target.isa.register import Register
from microprobe.code.var import Variable, VariableArray
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import Instruction
from microprobe.exceptions import MicroprobeUncheckableEnvironmentWarning, \
    MicroprobeCodeGenerationError
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
LOG = get_logger(__name__)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# Functions


# Classes
class X86ISA(GenericISA):

    def __init__(self, name, descr, path, ins, regs, comparators, generators):
        super(X86ISA, self).__init__(name, descr, path, ins, regs, comparators,
                                     generators)
        self._scratch_registers += []
        self._control_registers += []

    def set_register(self, register, value, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        instrs = []

        current_value = context.get_register_value(register)
        if context.register_has_value(value):
            present_reg = context.registers_get_value(value)[0]

            if present_reg.type.name != register.type.name:
                present_reg = None

        else:
            present_reg = None

        if register.type.name == "FPR":

            if present_reg is not None:

                ldr = self.new_instruction("LDR_V0")
                ldr.set_operands([register, present_reg])
                instrs.append(ldr)

            else:

                instrs += self.set_register(self._scratch_registers[0], value,
                                            context)

                ldgr = self.new_instruction("LDGR_V0")
                ldgr.set_operands([register, self._scratch_registers[0]])
                instrs.append(ldgr)

        elif register.type.name == "GR":

            value_high = int((value & 0xFFFFFFFF00000000) >> 32)
            value_low = int((value & 0x00000000FFFFFFFF))

            # TODO: Look for values within the context that might
            # be used as base for a AGHIK instruction

            if present_reg is not None:

                if register == present_reg:
                    lgr = self.new_instruction("LGR_V0")
                else:
                    lgr = self.new_instruction("LGR_V1")

                lgr.set_operands([register, present_reg])
                instrs.append(lgr)

            elif (value_high == 0 and value_low >= -2147483648 and
                  value_low <= 2147483647):

                lgfi = self.new_instruction("LGFI_V0")
                lgfi.set_operands([register, value_low])
                instrs.append(lgfi)

            elif (current_value is not None and
                  abs(value - current_value) < 0x7FFFFFFF):

                agfi = self.new_instruction("AGFI_V0")
                agfi.set_operands([register, value - current_value])
                instrs.append(agfi)

            else:

                iihf = self.new_instruction("IIHF_V0")
                iihf.set_operands([register, value_high])
                iilf = self.new_instruction("IILF_V0")
                iilf.set_operands([register, value_low])
                instrs.append(iihf)
                instrs.append(iilf)

        if len(instrs) > 0:
            return instrs

        return super(X86ISA, self).set_register(register, value, context)

    def set_register_to_address(self, register, address, context,
                                force_absolute=False,
                                dummy_force_relative=False):
        instrs = []
        assert address is not None

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        # check context first
        if isinstance(address.base_address, Variable):

            closest = context.get_closest_address_value(address)
            if closest is not None:

                present_reg, taddress = closest
                displacement = address.displacement - taddress.displacement

            elif context.register_has_value(address):

                present_reg = context.registers_get_value(address)[0]
                displacement = 0

            elif context.register_has_value(
                    Address(base_address=address.base_address)):

                present_reg = context.registers_get_value(
                    Address(base_address=address.base_address))[0]
                displacement = address.displacement

            else:
                present_reg = None
                displacement = None

            if present_reg is not None:

                if displacement != 0 and abs(displacement) < 2 ** 15:
                    aghik = self.new_instruction("AGHIK_V0")
                    aghik.set_operands([register, present_reg, displacement])
                    instrs.append(aghik)
                    return instrs

                lgr = self.new_instruction(lgr_load)
                lgr.set_operands([register, present_reg])
                instrs.append(lgr)

                if displacement != 0:

                    agfi = self.new_instruction("AGFI_V0")
                    agfi.set_operands([register, displacement])
                    instrs.append(agfi)

                return instrs

        if ((isinstance(address, InstructionAddress) or
                (context.data_segment is not None and
                 context.code_segment is not None) or context.symbolic) and
                not force_absolute):

            # if I've to point to the instruction stream I can do it
            # relatively
            larl = self.new_instruction("LARL_V0")
            larl.set_operands([register, address])
            instrs.append(larl)
        else:
            # I'm pointing to some data. Do I know the data region so that
            # I can do a relative load ?

            # Check what we have in context (different options)

            base_address = address.base_address
            displacement = address.displacement

            # make sure that we are playing with addresses
            if isinstance(base_address, Variable):
                base_address = base_address.address
                displacement = base_address.displacement + displacement
                base_address = base_address.base_address

            if isinstance(base_address, str):
                if base_address == "data":
                    base_address = Address(base_address=base_address)
                elif base_address == "code":
                    base_address = InstructionAddress(
                        base_address=base_address
                    )

            assert isinstance(base_address, Address)

            source_register = None
            if context.register_has_value(base_address):
                # perfect, we got it

                source_register = context.registers_get_value(base_address)[0]

            else:
                # look if we can generate it from the context
                for reg, value in context.register_values.iteritems():
                    if not isinstance(value, Address):
                        continue

                    # print reg, value.base_address, base_address.base_address

                    # is an address
                    if (Address(base_address=value.base_address) ==
                            base_address.base_address):
                        source_register = reg
                        displacement += base_address.displacement
                        base_address = Address(
                            base_address=base_address.base_address
                        )
                        break  # the first one is ok

                    # is a symbol (string)
                    if value.base_address == base_address.base_address:
                        source_register = reg
                        displacement += base_address.displacement
                        base_address = Address(
                            base_address=base_address.base_address
                        )
                        break  # the first one is ok

            if source_register is None:
                raise MicroprobeCodeGenerationError(
                    "Unable to generate the base address: '%s'"
                    " for target address: '%s'." % (base_address, address))

            lai = self.new_instruction("LA_V6")
            lai.set_operands(
                [register, self.registers["GR0"], source_register, 0])
            instrs.append(lai)

            if displacement != 0:
                agfi = self.target.new_instruction("AGFI_V0")
                agfi.set_operands([register, displacement])
                instrs.append(agfi)

        return instrs

    def load_float(self, register, address, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        ldi = self.new_instruction("LD_V0")
        ldi.operands()[0].set_value(register)
        ldi.memory_operands()[0].set_address(address, context)
        return [ldi]

    def store_float(self, register, address, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        std = self.new_instruction("STD_V0")
        std.operands()[0].set_value(register)
        std.memory_operands()[0].set_address(address, context)
        return [std]

    def store_integer(self, register, address, length, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        if length == 64:
            stg = self.new_instruction("STG_V0")
            stg.operands()[0].set_value(register)
            stg.memory_operands()[0].set_address(address, context)
            return [stg]
        elif length == 32:
            stg = self.new_instruction("STY_V0")
            stg.operands()[0].set_value(register)
            stg.memory_operands()[0].set_address(address, context)
            return [stg]
        else:
            raise NotImplementedError

    def set_register_bits(self, register, dummy_value, mask,
                          dummy_shift, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        instructions = []
        mask_inv = int("1" * register.type.size, 2) ^ mask

        if (register.type.name == "CR" and
                self.target.environment.problem_state):
            raise MicroprobeUncheckableEnvironmentWarning(
                "Unable to set CR registers in problem state environment"
            )

        elif (register.type.name == "CR" and
                not self.target.environment.problem_state):

            stctg = self.new_instruction("STCTG_V0")
            stctg.operands()[0].set_value(register)
            stctg.operands()[1].set_value(register)

            try:
                stctg.memory_operands()[0].set_address(
                    self.scratch_var.address,
                    context
                )
            except MicroprobeCodeGenerationError:

                address_register = self.get_register_for_address_arithmetic(
                    context
                )

                instructions += self.set_register_to_address(
                    address_register,
                    self.scratch_var.address,
                    context
                )

                context.set_register_value(
                    address_register,
                    self.scratch_var.address
                )

                stctg.memory_operands()[0].set_address(
                    self.scratch_var.address,
                    context
                )

            instructions.append(stctg)

            instructions += self.set_register(self._scratch_registers[0],
                                              mask_inv, context)

            lang = self.new_instruction("LANG_V0")
            lang.operands()[0].set_value(self._scratch_registers[0])
            lang.operands()[1].set_value(self._scratch_registers[0])
            lang.memory_operands()[0].set_address(self.scratch_var.address,
                                                  context)
            instructions.append(lang)

            instructions += self.set_register(self._scratch_registers[0],
                                              mask, context)

            laog = self.new_instruction("LAOG_V0")
            laog.operands()[0].set_value(self._scratch_registers[0])
            laog.operands()[1].set_value(self._scratch_registers[0])
            laog.memory_operands()[0].set_address(self.scratch_var.address,
                                                  context)
            instructions.append(laog)

            lctlg = self.new_instruction("LCTLG_V0")
            lctlg.operands()[0].set_value(register)
            lctlg.operands()[1].set_value(register)
            lctlg.memory_operands()[0].set_address(self.scratch_var.address,
                                                   context)
            instructions.append(lctlg)

            context.unset_register(address_register)

        elif register.type.name == "GR":

            instructions += self.set_register(self._scratch_registers[0],
                                              mask_inv, context)
            nr = self.new_instruction("NR_V0")
            nr.operands()[0].set_value(register)
            nr.operands()[1].set_value(self._scratch_registers[0])
            instructions.append(nr)

        else:

            raise NotImplementedError(
                "Set register bits for %s type registers not implemented" %
                register.type.name)

        return instructions

    def store_decimal(self, address, length, value, context):

        assert length > 0

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        if value >= 0:
            sign_code = "1100"
        else:
            sign_code = "1101"

        digits = str(int(value))
        decimal = sign_code

        for digit in digits:
            digit = bin(int(digit))[2:]
            while len(digit) < 4:
                digit = "0" + digit
            decimal = digit + decimal

        assert len(decimal) % 4 == 0

        if len(decimal) % 8 == 4:
            decimal = "0000" + decimal

        assert len(decimal) % 8 == 0

        if len(decimal) / 8 > length:
            decimal = decimal[:-4]

        if len(decimal) / 8 > length:
            print(decimal, value, length)
            raise NotImplementedError

        while len(decimal) / 8 < length:
            decimal = "00000000" + decimal

        assert len(decimal) % 8 == 0

        instructions = []

        reg_length = 64
        decimal_digits = [decimal[i:i + reg_length]
                          for i in range(0, len(decimal), reg_length)]

        for idx, segment in enumerate(decimal_digits):
            value = int(segment, 2)
            instructions += self.set_register(self._scratch_registers[0],
                                              value,
                                              context)

            instructions += self.store_integer(
                self._scratch_registers[0],
                address + (idx * 8),
                64,
                context
            )

        return instructions

    @property
    def program_counter(self):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        return self.registers['PSW']

    def branch_unconditional_relative(self, source, target):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        LOG.debug("Source: %s", source)
        LOG.debug("Target: %s", target)

        if isinstance(target, InstructionAddress):
            target_address = target
        elif isinstance(target, Instruction):
            target_address = target.address
        else:
            print("Target:", target)
            raise NotImplementedError

        if isinstance(source, InstructionAddress):

            source_address = source
            relative_offset = target_address - source_address

            if abs(relative_offset) < 32768:
                instruction = self.new_instruction("BRC_V1")
            elif abs(relative_offset) > 65535:
                instruction = self.new_instruction("BRCL_V3")
            else:
                instruction = self.new_instruction("BRCL_V2")

            instruction.set_address(source_address)

            LOG.debug("Source address: %s", source_address)
            LOG.debug("Target address: %s", target_address)
            LOG.debug("Relative offset: %s", relative_offset)

        elif isinstance(source, Instruction):
            source_address = source.address
            relative_offset = target_address - source_address
            instruction = source
        else:
            print("Source:", source)
            raise NotImplementedError

        for operand in instruction.operands():
            if not operand.type.address_relative:
                assert len(operand.type.values()) == 1
                operand.set_value(operand.type.values()[0])
            else:
                operand.set_value(relative_offset)

        return instruction

    def add_to_register(self, register, value):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        instrs = []
        if register.type.name == "GR" and isinstance(value, six.integer_types):
            if value < 0x7FFFFFFF:
                agfi = self.new_instruction("AGFI_V0")
                agfi.set_operands([register, value])
                instrs.append(agfi)
            else:
                raise NotImplementedError
        else:
            raise NotImplementedError

        return instrs

    def compare_and_branch(self, val1, val2, cond, target, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        conddict = {"<": [">", 4],
                    ">": ["<", 2],
                    "!=": ["!=", 6],
                    "=": ["=", 8],
                    ">=": ["<=", 10],
                    "<=": [">=", 12]
                    }

        assert cond in conddict.keys()

        instrs = []

        if isinstance(val1, six.integer_types) and isinstance(val2, Register):
            val1, val2 = val2, val1
            cond = conddict[cond][0]

        if isinstance(val1, Register) and isinstance(val2, six.integer_types):

            LOG.debug("Compare/Branch register immediate")

            # Compare first
            cgrl = self.new_instruction("CGFI_V0")
            cgrl.set_operands([val1, val2])

            instrs.append(cgrl)

            # TODO: assuming a short offset always
            # if abs(relative_offset) > 32768:
            #    instruction = self.new_instruction("BRCL_V3")
            # else:
            brcl = self.new_instruction("BRCL_V0")

            for operand in brcl.memory_operands():

                if operand.is_branch_target:
                    taddress = InstructionAddress(base_address=target)
                    operand.set_address(taddress, context)
                    break

            brcl.operands()[0].set_value(conddict[cond][1])
            instrs.append(brcl)

        else:
            raise NotImplementedError

        return instrs

    def nop(self):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

        instr = self.new_instruction("BCR_V4")
        instr.set_operands([0, self.target.registers['GR0']])
        return instr

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
            X86ISA,
            self).set_context(
            variable=variable,
            tmpl_path=tmpl_path)

    def get_context(self, variable=None, tmpl_path=None):
        """ """

        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(
            X86ISA,
            self).get_context(
            variable=variable,
            tmpl_path=tmpl_path)

    def load(self, register, address, context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.


    def negate_register(self, dummy_register, dummy_context):

        raise NotImplementedError("Function not ported to x86")
        # TODO: Code below is from another back-end. Use it as reference.

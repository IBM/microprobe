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
""":mod:`microprobe.code.context` module

"""

# Futures
from __future__ import absolute_import, print_function, annotations

# Built-in modules
from typing import TYPE_CHECKING, Tuple, Dict, List

# Third party modules

# Own modules
from microprobe.code.address import Address, InstructionAddress
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict, smart_copy_dict
from microprobe.utils.typeguard_decorator import typeguard_testsuite

# Type hinting
if TYPE_CHECKING:
    from microprobe.target.isa.register import Register
    from microprobe.code.address import MemoryValue
    from microprobe.target.isa.dat import DynamicAddressTranslation

# Constants
LOG = get_logger(__name__)
__all__ = ["Context"]

# Functions


# Classes
@typeguard_testsuite
class Context(object):  # pylint: disable=too-many-public-methods
    """Class to represent the execution context (e.g. register values, etc ...
    on each benchmark building block)


    """

    def __init__(self,
                 default_context: Context | None = None,
                 code_segment: int | None = None,
                 data_segment: int | None = None,
                 symbolic: bool = True,
                 absolute: bool = False):
        """

        :param default_context:  (Default value = None)
        :param code_segment:  (Default value = None)
        :param data_segment:  (Default value = None)
        :param symbolic:  (Default value = True)

        """

        self._reserved_registers: Dict[str, Register] = RejectingDict()

        self._register_values: Dict[Register,
                                    int | float | Address | str | None] = {}
        self._value_registers: Dict[int | float | Address | str,
                                    List[Register]] = {}
        self._memory_values: Dict[Address, MemoryValue] = {}
        self._value_memorys: Dict[MemoryValue, List[MemoryValue]] = {}

        self._data_segment = data_segment
        self._code_segment = code_segment
        self._symbolic = symbolic
        self._fabsolute = absolute

        self._dat: DynamicAddressTranslation | None = None

        if default_context is not None:
            self = default_context.copy()

    def copy(self):
        """Returns a copy of the current context."""

        newcontext = Context()

        # pylint: disable=protected-access
        newcontext._reserved_registers = smart_copy_dict(
            self._reserved_registers)
        newcontext._register_values = smart_copy_dict(self._register_values)
        newcontext._value_registers = smart_copy_dict(self._value_registers)
        newcontext._memory_values = smart_copy_dict(self._memory_values)
        newcontext._value_memorys = smart_copy_dict(self._value_memorys)

        if self._dat is not None:
            newcontext.set_dat(self._dat.copy())

        newcontext.set_code_segment(self.code_segment)
        newcontext.set_data_segment(self.data_segment)
        newcontext.set_symbolic(self.symbolic)
        newcontext.set_absolute(self.force_absolute)

        return newcontext

    def add_reserved_registers(self, rregs: List[Register]):
        """Add the provided registers into the reserved register list.

        :param rregs: Registers to reserve
        :type rregs: :class:`~.list` of :class:`~.Register`

        """

        for reg in rregs:
            self._reserved_registers[reg.name] = reg

    def remove_reserved_registers(self, rregs: List[Register]):
        """Remove the provided registers from the reserved register list.

        :param rregs: Registers to un-reserve
        :type rregs: :class:`~.list` of :class:`~.Register`

        """

        for reg in rregs:
            del self._reserved_registers[reg.name]

    def set_register_value(self, register: Register,
                           value: int | float | Address | str):
        """Set the provided register to the specified value.

        :param register: Register to set
        :type register: :class:`~.Register`
        :param value: Value to assign
        :type value: :class:`~.int`, :class:`~.float`, :class:`~.long`,
             :class:`~.Address` or :class:`~.str`

        """

        LOG.debug("Setting %s to %s", register.name, value)

        assert isinstance(
            value,
            tuple(
                [int] +
                [float, Address, InstructionAddress, str])), type(value)

        if isinstance(value, str):
            assert len(value.split("_")) == 2

        if self.get_register_value(register) is not None:
            self.unset_register(register)

        self._register_values[register] = value

        if value in self._value_registers:
            if register not in self._value_registers[value]:
                self._value_registers[value].append(register)
        else:
            self._value_registers[value] = [register]

        # assert self.get_register_value(register) == value
        # assert value in self._value_registers.keys()
        # assert self._register_values[register] == value

    def get_closest_value(self, value):
        """Returns the closest value to the given value.

        Returns the closest value to the given value. If there are
        not values registered, `None` is returned.

        :param value: value to look for
        :type value: :class:`~.int`, :class:`~.float`, :class:`~.long`,
             :class:`~.Address` or :class:`~.str`

        """

        possible_regs = []

        for reg, val in self._register_values.items():

            if not isinstance(val, type(value)):
                continue

            possible_regs.append((reg, val))

        possible_regs = sorted(possible_regs, key=lambda x: abs(x[1] - value))
        if possible_regs:
            return possible_regs[0]

        return None

    def get_closest_address_value(self, address: Address):
        """Returns the closest address to the given address.

        Returns the closest address to the given address. If there are
        not addresses registered, `None` is returned.

        :param address: Address to look for
        :type address: :class:`~.Address`

        """

        possible_regs: List[Tuple["Register", Address]] = []

        for reg, value in self._register_values.items():

            if not isinstance(value, Address):
                continue

            if Address(base_address=value.base_address) == \
                    Address(base_address=address.base_address):
                possible_regs.append((reg, value))

        possible_regs = sorted(
            possible_regs,
            key=lambda x: abs(x[1].displacement - address.displacement))
        if possible_regs:
            return possible_regs[0]

        return None

    def get_register_closest_value(self, value):
        """Returns the register with the closest value to the given value.

        Returns the register with the closest value to the given value.
        If there are not values registered, `None` is returned.
        Address values are ignored.

        :param value: Value to look for
        :type value: :class:`~.int`, :class:`~.float`, :class:`~.long`,
             :class:`~.Address` or :class:`~.str`

        """

        possible_regs = []

        for reg, reg_value in self._register_values.items():

            if isinstance(value, Address):
                continue

            if not isinstance(reg_value, type(value)):
                continue

            if isinstance(reg_value, str):
                # Type hinting needs some help with this one :)
                assert isinstance(value, str)
                if reg_value.split("_")[1] != value.split(" ")[1]:
                    continue

            possible_regs.append((reg, reg_value))

        if not isinstance(value, str):
            possible_regs = sorted(possible_regs, key=lambda x: abs(x - value))
        else:
            possible_regs = sorted(
                possible_regs,
                key=lambda x: abs(
                    int(x.split("_")[0]) - int(value.split("_")[0])))

        if possible_regs:
            return possible_regs[0]

        return None

    def get_register_value(self, register: Register):
        """Returns the register value. `None` if not found.

        :param register: Register to get its value
        :type register: :class:`~.Register`

        """

        value = self._register_values.get(register, None)
        if value is not None:
            assert value in self._value_registers.keys()

        return value

    def get_registername_value(self, register_name: str):
        """Returns the register value. `None` if not found.

        :param register: Register name to get its value
        :type register: :class:`~.str`
        :param register_name:

        """
        assert isinstance(register_name, str)

        register_names = [reg.name for reg in self._register_values]
        if register_name not in register_names:
            return None

        register = [
            reg for reg in self._register_values if reg.name == register_name
        ][0]

        return self._register_values.get(register, None)

    def unset_registers(self, registers: List[Register]):
        """Removes the values from registers.

        :param registers: List of registers
        :type registers: :class:`~.list` of :class:`~.Register`

        """
        for reg in registers:
            self.unset_register(reg)

    def unset_register(self, register):
        """Remove the value from a register.

        :param register: Registers
        :type register: :class:`~.Register`

        """

        assert self._register_values[register] is not None

        value = self._register_values[register]
        self._value_registers[value].remove(register)

        if not self._value_registers[value]:
            del self._value_registers[value]

        self._register_values[register] = None

    def set_memory_value(self, mem_value: MemoryValue):
        """Sets a memory value.

        :param mem_value: Memory value to set.
        :type mem_value: :class:`~.MemoryValue`

        """

        LOG.debug("Start set memory value: %s", mem_value)

        self.unset_memory(mem_value.address, mem_value.length)
        self._memory_values[mem_value.address] = mem_value

        if mem_value.value in self._memory_values:

            if mem_value not in self._value_memorys[mem_value.value]:

                self._value_memorys[mem_value.value].append(mem_value)
                LOG.debug("Values inv %s: %s", mem_value.value,
                          self._value_memorys[mem_value.value])

            else:
                LOG.debug("Already in inv dictionary")

        else:

            self._value_memorys[mem_value.value] = [mem_value]
            LOG.debug("Values inv %s: %s", mem_value.value, [mem_value])

        assert self._memory_values[mem_value.address] == mem_value
        assert mem_value in self._value_memorys[mem_value.value]

        LOG.debug("End set memory value: %s", mem_value)

    def get_memory_value(self, address: Address):
        """Gets a memory value.

        :param address: Address to look for
        :type address: :class:`~.Address`

        """

        if address in self._memory_values:
            return self._memory_values[address]

        return None

    def unset_memory(self, address: Address, length: int):
        """Unsets a memory region.

        :param address: Start address of the region
        :type address: :class:`~.Address`
        :param length: Length in bytes of the region
        :type length: :class:`~.int`

        """

        LOG.debug("Start unset address: %s (length: %s)", address, length)

        possible_addresses = [
            addr for addr in self._memory_values
            if addr.base_address == address.base_address
        ]

        # LOG.debug("Possible addresses: %s", possible_addresses)

        for paddr in possible_addresses:

            diff = paddr - address
            diff2 = address - paddr
            length2 = self._memory_values[paddr].length

            if ((diff >= 0 and diff < length)
                    or (diff2 >= 0 and diff2 < length2)):

                LOG.debug("Address overlap: %s", paddr)
                mem_value = self._memory_values.pop(paddr)

                LOG.debug("Memory value: %s", mem_value)

                if mem_value in self._value_memorys[mem_value.value]:
                    self._value_memorys[mem_value.value].remove(mem_value)

        LOG.debug("Finish unset address: %s (length: %s)", address, length)

    def register_has_value(self, value: int | float | Address | str):
        """Returns if a value is in a register.

        :param value: Value to look for
        :type value: :class:`~.bool`

        """
        return value in list([
            elem for elem in self._value_registers.keys()
            if type(elem) is type(value)
        ])

    def registers_get_value(self, value: int | float | Address | str):
        """Gets a list of registers containing the specified value.

        :param value: Value to look for
        :type value: :class:`~.int` or :class:`~.float` or :class:`~.Address`

        """

        keyl = [key for key in self._value_registers if key == value]

        if len(keyl) != 1:
            assert keyl == 1

        return self._value_registers[keyl[0]]

    @property
    def register_values(self):
        """Dictionary of register, value pairs (:class:`~.dict`)"""
        return self._register_values

    @property
    def reserved_registers(self):
        """List of reserved registers (:class:`~.list`)"""
        return list(self._reserved_registers.values())

    @property
    def data_segment(self):
        """Address starting the data segment (::class:`~.int`)"""
        return self._data_segment

    def set_data_segment(self, value: int | None):
        """Sets the data segment start address.

        :param value: Start address.
        :type value: ::class:`~.int`

        """
        self._data_segment = value

    @property
    def dat(self):
        """DAT object (:class:`~.DynamicAddressTranslation`"""
        return self._dat

    def set_dat(self, dat: DynamicAddressTranslation):
        """Sets the dynamic address translation object.

        :param dat: DAT object.
        :type dat: :class:`~.DynamicAddressTranslation`

        """
        self._dat = dat

    @property
    def code_segment(self):
        """Address starting the code segment (::class:`~.int`)"""
        return self._code_segment

    def set_code_segment(self, value: int | None):
        """Sets the code segment start address.

        :param value: Start address.
        :type value: :class:`~.int`

        """
        self._code_segment = value

    @property
    def symbolic(self):
        """Boolean indicating if the context allows symbol labels

        Boolean indicating if the context allows symbol labels
        (:class:`~.bool`)
        """
        return self._symbolic

    def set_symbolic(self, value: bool):
        """Sets the symbolic property.

        :param value: Boolean indicating if the context allows symbol labels
        :type value: :class:`~.bool`

        """
        self._symbolic = value

    @property
    def force_absolute(self):
        """Boolean indicating if absolute addresses are needed.

        Boolean indicating if absolute addresses are needed
        (:class:`~.bool`)
        """
        return self._fabsolute

    def set_absolute(self, value: bool):
        """Sets the force_absolute property.

        :param value: Boolean indicating if absolute addresses are needed
        :type value: :class:`~.bool`

        """
        self._fabsolute = value

    # def _validate(self):
    #     for register in self._register_values:
    #        value = self._register_values[register]
    #        if value is not None:
    #            assert register in self._value_registers[value]

    def dump(self):
        """Return a dump of the current context status.

        Return a dump of the current context status. Very useful for pass
        debugging purposes.


        """

        mstr: List[str] = []
        mstr.append("-" * 80)
        mstr.append("Context status:")
        mstr.append("Reserved Registers:")

        for key, value in sorted(self._reserved_registers.items()):
            mstr.append("Idx:\t%s\tValue:\t%s" % (key, value))

        mstr.append("Registers values:")
        for key, value in sorted(self._register_values.items()):
            mstr.append("Idx:\t%s\tRaw Value:\t%s" % (key, value))

        mstr.append("Registers values inverted:")
        for key, value in sorted([(str(k), str(v))
                                  for k, v in self._value_registers.items()]):
            mstr.append("Idx:\t%s\tValue:\t%s" % (key, value))

        mstr.append("Memory values:")
        for key, value in sorted(self._memory_values.items()):
            mstr.append("Idx:\t%s\tRaw Value:\t%s" % (key, value))

        mstr.append("Memory values inverted:")
        for key, value in sorted(self._value_memorys.items()):
            mstr.append("Idx:\t%s\tValue:\t%s" % (key, value))

        mstr.append("Code segment: %s" % self._code_segment)
        mstr.append("Data segment: %s" % self._data_segment)
        mstr.append("Symbolic context: %s" % self._symbolic)

        mstr.append("-" * 80)

        return "\n".join(mstr)

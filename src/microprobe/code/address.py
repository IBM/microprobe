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
""":mod:`microprobe.code.address` module

"""

# Futures
from __future__ import absolute_import, print_function

# Third party modules
import six

# Own modules
from microprobe.code.var import Variable
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["MemoryValue", "Address", "InstructionAddress"]

# Functions


# Classes
class Address(object):
    """Class to represent an address."""

    _cmp_attributes = ["_base_address", "_displacement"]

    def __init__(self, base_address=None, displacement=0):
        """

        :param base_address:  (Default value = None)
        :param displacement:  (Default value = 0)

        """

        self._base_address = base_address
        self._displacement = displacement

        if isinstance(base_address, self.__class__):
            self._displacement += base_address.displacement
            self._base_address = base_address.base_address

        if self._base_address is not None:
            assert isinstance(self._base_address,
                              tuple(list(six.string_types) + [Variable]))

    @property
    def base_address(self):
        """Base address of the address (:class:`~.str`)"""
        return self._base_address

    @property
    def displacement(self):
        """Displacement of the address (:class:`~.int`)"""
        return self._displacement

    def check_alignment(self, align):
        """Check if the address is aligned to align"""
        return self._displacement % align == 0

    def copy(self):
        """Returns a copy of the address."""
        return self.__class__(
            base_address=self.base_address,
            displacement=self.displacement
        )

    def __add__(self, other):
        """

        :param other:

        """

        if isinstance(other, self.__class__):

            if self.base_address != other.base_address:
                raise MicroprobeCodeGenerationError(
                    "I can not add '%s' "
                    "and '%s'" % (self, other)
                )

            return self.__class__(
                self.base_address, self.displacement + other.displacement
            )

        elif isinstance(other, int):

            return self.__class__(self.base_address, self.displacement + other)

        else:
            raise NotImplementedError

    def _check_cmp(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError(
                "%s != %s" % (
                    other.__class__, self.__class__
                )
            )

    def __eq__(self, other):
        """x.__eq__(y) <==> x==y"""

        if not isinstance(other, self.__class__):
            return False

        for attr in self._cmp_attributes:
            if not getattr(self, attr) == getattr(other, attr):
                return False
        return True

    def __ne__(self, other):
        """x.__ne__(y) <==> x!=y"""

        if not isinstance(other, self.__class__):
            return False

        for attr in self._cmp_attributes:
            if not getattr(self, attr) == getattr(other, attr):
                return True
        return False

    def __lt__(self, other):
        """x.__lt__(y) <==> x<y"""

        if not isinstance(other, self.__class__):
            return False

        for attr in self._cmp_attributes:
            if getattr(self, attr) < getattr(other, attr):
                return True
            elif getattr(self, attr) > getattr(other, attr):
                return False
        return False

    def __gt__(self, other):
        """x.__gt__(y) <==> x>y"""

        if not isinstance(other, self.__class__):
            return False

        for attr in self._cmp_attributes:
            if getattr(self, attr) > getattr(other, attr):
                return True
            elif getattr(self, attr) < getattr(other, attr):
                return False
        return False

    def __le__(self, other):
        """x.__le__(y) <==> x<=y"""

        if not isinstance(other, self.__class__):
            return False

        for attr in self._cmp_attributes:
            if getattr(self, attr) <= getattr(other, attr):
                continue
            else:
                return False
        return True

    def __ge__(self, other):
        """x.__ge__(y) <==> x>=y"""

        if not isinstance(other, self.__class__):
            return False

        for attr in self._cmp_attributes:
            if getattr(self, attr) >= getattr(other, attr):
                continue
            else:
                return False
        return True

    def __hash__(self):
        """ """

        return hash(str(self))

    def __iadd__(self, other):
        """

        :param other:

        """

        if isinstance(other, self.__class__):

            if self.base_address != other.base_address:
                raise MicroprobeCodeGenerationError(
                    "I can not add '%s'"
                    " and '%s'" % (
                        self, other
                    )
                )

            return self.__class__(
                self.base_address, self.displacement + other.displacement
            )

        elif isinstance(other, int):

            return self.__class__(self.base_address, self.displacement + other)

        else:
            raise NotImplementedError

    def __mod__(self, other):
        """

        :param other:

        """

        if isinstance(other, self.__class__):

            if self.base_address != other.base_address:
                raise MicroprobeCodeGenerationError(
                    "I can not compute the "
                    "module '%s' and '%s'" % (self, other)
                )

            return self.__class__(
                self.base_address, self.displacement + other.displacement
            )

        elif isinstance(other, int):

            if isinstance(self._base_address, int):
                return (self._base_address + self.displacement) % other

            return self.displacement % other

        else:
            raise NotImplementedError

    def __radd__(self, other):
        """

        :param other:

        """

        if isinstance(other, self.__class__):

            if self.base_address != other.base_address:
                raise MicroprobeCodeGenerationError(
                    "I can not add '%s' and "
                    "'%s'" % (self, other)
                )

            return self.__class__(
                self.base_address, self.displacement + other.displacement
            )

        elif isinstance(other, int):
            return self.__class__(self.base_address, self.displacement + other)

        else:
            raise NotImplementedError

    def __repr__(self):
        """ """

        return "%s(%s+0x%016x)" % (
            self.__class__.__name__, self.base_address, self.displacement
        )

    def __rsub__(self, other):
        """

        :param other:

        """

        if isinstance(other, (Address, InstructionAddress)):

            if self.base_address != other.base_address:
                raise MicroprobeCodeGenerationError(
                    "I can not sub '%s' "
                    "and '%s'" % (self, other)
                )

            return other.displacement - self.displacement

        elif isinstance(other, int):
            return self.__class__(self.base_address, self.displacement - other)

        else:
            print(self.__class__, other.__class__)
            raise NotImplementedError

    def __str__(self):
        """ """

        return "%s(%s+0x%016x)" % (
            self.__class__.__name__, self.base_address, self.displacement
        )

    def __sub__(self, other):
        """

        :param other:

        """

        if isinstance(other, self.__class__):

            if self.base_address != other.base_address:
                raise MicroprobeCodeGenerationError(
                    "I can not sub '%s' "
                    "and '%s'" % (self, other)
                )

            return self.displacement - other.displacement

        elif isinstance(other, int):
            return self.__class__(self.base_address, self.displacement - other)

        else:
            LOG.critical(self, other)
            raise NotImplementedError


class InstructionAddress(Address):
    """Class to represent an instruction address."""

    def __init__(self, base_address=None, displacement=0, instruction=None):
        """

        :param base_address:  (Default value = None)
        :param displacement:  (Default value = 0)
        :param instruction:  (Default value = None)

        """
        super(InstructionAddress, self).__init__(
            base_address=base_address,
            displacement=displacement
        )
        self._instruction = instruction

    @property
    def target_instruction(self):
        """Target instruction (:class:`~.Instruction`)"""
        return self._instruction

    def set_target_instruction(self, instruction):
        """Sets the instruction to which this address is pointing.

        :param instruction: Target instruction
        :type instruction: :class:`~.Instruction`

        """

        self._instruction = instruction

    def __add__(self, other):
        """

        :param other:

        """
        self._instruction = None
        return super(InstructionAddress, self).__add__(other)

    def __iadd__(self, other):
        """

        :param other:

        """
        self._instruction = None
        return super(InstructionAddress, self).__iadd__(other)

    def __mod__(self, other):
        """

        :param other:

        """
        self._instruction = None
        return super(InstructionAddress, self).__mod__(other)

    def __radd__(self, other):
        """

        :param other:

        """
        self._instruction = None
        return super(InstructionAddress, self).__radd__(other)

    def __rsub__(self, other):
        """

        :param other:

        """
        self._instruction = None
        return super(InstructionAddress, self).__rsub__(other)

    def __sub__(self, other):
        """

        :param other:

        """
        self._instruction = None
        return super(InstructionAddress, self).__sub__(other)


class MemoryValue(object):
    """Class to represent a value in memory."""

    _cmp_attributes = ['address', 'value', 'length']

    def __init__(self, address, value, length):
        """

        :param address:
        :param value:
        :param length:

        """
        self._address = address
        self._value = value
        self._length = length

    @property
    def address(self):
        """Address of the memory value

        Address of the memory value (:class:`~.Address`)
        """
        return self._address

    @property
    def length(self):
        """Length of the memory value (:class:`~.int`)"""
        return self._length

    @property
    def value(self):
        """Actual memory value (:class:`~.int`)"""
        return self._value

    def _check_cmp(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError(
                "%s != %s" % (
                    other.__class__, self.__class__
                )
            )

    def __eq__(self, other):
        """x.__eq__(y) <==> x==y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            if not getattr(self, attr) == getattr(other, attr):
                return False
        return True

    def __ne__(self, other):
        """x.__ne__(y) <==> x!=y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            if not getattr(self, attr) == getattr(other, attr):
                return True
        return False

    def __lt__(self, other):
        """x.__lt__(y) <==> x<y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            if getattr(self, attr) < getattr(other, attr):
                return True
            elif getattr(self, attr) > getattr(other, attr):
                return False
        return False

    def __gt__(self, other):
        """x.__gt__(y) <==> x>y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            if getattr(self, attr) > getattr(other, attr):
                return True
            elif getattr(self, attr) < getattr(other, attr):
                return False
        return False

    def __le__(self, other):
        """x.__le__(y) <==> x<=y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            if getattr(self, attr) <= getattr(other, attr):
                continue
            else:
                return False
        return True

    def __ge__(self, other):
        """x.__ge__(y) <==> x>=y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            if getattr(self, attr) >= getattr(other, attr):
                continue
            else:
                return False
        return True

    def __repr__(self):
        """ """
        return "%s(%s, Value:%s, Length:%d)" % (
            self.__class__.__name__, self._address,
            hex(self._value), self._length
        )

    def __str__(self):
        """ """
        return "%s(%s, Value:%s, Length:%d)" % (
            self.__class__.__name__, self._address,
            hex(self._value), self._length
        )

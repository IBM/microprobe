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
""":mod:`microprobe.code.var` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import abc
import math

# Third party modules
import six

# Own modules
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.logger import get_logger


# Constants
__all__ = ["Variable", "VariableSingle", "VariableArray"]
LOG = get_logger(__name__)

VAR_TYPE_LEN_DICT = {}
VAR_TYPE_LEN_DICT["char"] = 1
VAR_TYPE_LEN_DICT["signed char"] = 1
VAR_TYPE_LEN_DICT["unsigned char"] = 1
VAR_TYPE_LEN_DICT["short"] = 2
VAR_TYPE_LEN_DICT["short int"] = 2
VAR_TYPE_LEN_DICT["signed short"] = 2
VAR_TYPE_LEN_DICT["signed short int"] = 2
VAR_TYPE_LEN_DICT["unsigned short"] = 2
VAR_TYPE_LEN_DICT["unsigned short int"] = 2
VAR_TYPE_LEN_DICT["int"] = 4
VAR_TYPE_LEN_DICT["signed"] = 4
VAR_TYPE_LEN_DICT["signed int"] = 4
VAR_TYPE_LEN_DICT["unsigned"] = 4
VAR_TYPE_LEN_DICT["unsigned int"] = 4
VAR_TYPE_LEN_DICT["long"] = 8
VAR_TYPE_LEN_DICT["long int"] = 8
VAR_TYPE_LEN_DICT["signed long"] = 8
VAR_TYPE_LEN_DICT["signed long int"] = 8
VAR_TYPE_LEN_DICT["unsigned long"] = 8
VAR_TYPE_LEN_DICT["unsigned long int"] = 8
VAR_TYPE_LEN_DICT["long long"] = 8
VAR_TYPE_LEN_DICT["long long int"] = 8
VAR_TYPE_LEN_DICT["signed long long"] = 8
VAR_TYPE_LEN_DICT["signed long long int"] = 8
VAR_TYPE_LEN_DICT["float"] = 8
VAR_TYPE_LEN_DICT["double"] = 8
VAR_TYPE_LEN_DICT["long double"] = 8
VAR_TYPE_LEN_DICT["int8_t"] = 1
VAR_TYPE_LEN_DICT["int_least8_t"] = 1
VAR_TYPE_LEN_DICT["int_fast8_t"] = 1
VAR_TYPE_LEN_DICT["uint8_t"] = 1
VAR_TYPE_LEN_DICT["uint_least8_t"] = 1
VAR_TYPE_LEN_DICT["uint_fast8_t"] = 1
VAR_TYPE_LEN_DICT["int16_t"] = 2
VAR_TYPE_LEN_DICT["int_least16_t"] = 2
VAR_TYPE_LEN_DICT["int_fast16_t"] = 2
VAR_TYPE_LEN_DICT["uint16_t"] = 2
VAR_TYPE_LEN_DICT["uint_least16_t"] = 2
VAR_TYPE_LEN_DICT["uint_fast16_t"] = 2
VAR_TYPE_LEN_DICT["int32_t"] = 4
VAR_TYPE_LEN_DICT["int_least32_t"] = 4
VAR_TYPE_LEN_DICT["int_fast32_t"] = 4
VAR_TYPE_LEN_DICT["uint32_t"] = 4
VAR_TYPE_LEN_DICT["uint_least32_t"] = 4
VAR_TYPE_LEN_DICT["uint_fast32_t"] = 4
VAR_TYPE_LEN_DICT["int64_t"] = 8
VAR_TYPE_LEN_DICT["int_least64_t"] = 8
VAR_TYPE_LEN_DICT["int_fast64_t"] = 8
VAR_TYPE_LEN_DICT["uint64_t"] = 8
VAR_TYPE_LEN_DICT["uint_least64_t"] = 8
VAR_TYPE_LEN_DICT["uint_fast64_t"] = 8

# Functions


# Classes
class Variable(six.with_metaclass(abc.ABCMeta, object)):
    """ """

    _cmp_attributes = []

    def __init__(self):
        """ """
        self._address = None

    @abc.abstractproperty
    def type(self):
        """Variable type (:class:`~.str`)."""
        raise NotImplementedError

    @abc.abstractproperty
    def name(self):
        """Variable name (:class:`~.str`)."""
        raise NotImplementedError

    @abc.abstractmethod
    def array(self):
        """Return if the variable is an array.

        :rtype: :class:`~.bool`
        """
        raise NotImplementedError

    @abc.abstractproperty
    def size(self):
        """Variable size in bytes (::class:`~.int`)."""
        raise NotImplementedError

    @abc.abstractproperty
    def value(self):
        """Variable value."""
        raise NotImplementedError

    @abc.abstractproperty
    def align(self):
        """Variable alignment (:class:`~.int`)."""
        raise NotImplementedError

    def set_address(self, address):
        """Set variable address.

        :param address: Address of the variable.
        """
        self._address = address

    @property
    def address(self):
        """Variable address (:class:`~.Address`)."""
        return self._address

    @abc.abstractproperty
    def __str__(self):
        """ """
        raise NotImplementedError

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


class VariableSingle(Variable):
    """ """

    _cmp_attributes = ["name", "type", "size"]

    def __init__(self, name, vartype, align=1, value=None, address=None):
        """

        :param name:
        :param vartype:
        :param align:  (Default value = 16)
        :param value:  (Default value = None)

        """
        super(VariableSingle, self).__init__()
        self._name = name
        self._type = vartype.lower()
        self._align = align
        self._value = value
        self._address = address

        if align is not None:
            if align <= 0:
                raise MicroprobeCodeGenerationError(
                    "Alignment should be > 0 in definition of "
                    "variable: '%s'" % name)
            val = math.log(align, 2)
            if val != int(val):
                raise MicroprobeCodeGenerationError(
                    "Alignment should be power of 2 in definition of "
                    "variable: '%s'" % name)

    @property
    def type(self):
        """Variable type (:class:`~.str`)."""
        return self._type

    @property
    def name(self):
        """Variable name (:class:`~.str`)."""
        return self._name

    def array(self):
        """Return if the variable is an array.

        :rtype: :class:`~.bool`
        """
        return False

    @property
    def value(self):
        """Variable value."""
        return self._value

    @property
    def size(self):
        """Variable size in bytes (::class:`~.int`)."""

        if self._type in VAR_TYPE_LEN_DICT:
            return VAR_TYPE_LEN_DICT[self._type]
        elif "*" in self._type:
            # TODO: Assuming a 64 bits address size
            return 8
        else:
            raise MicroprobeCodeGenerationError(
                "Unable to compute the size of type '%s' in definition "
                "of variable '%s'" % (self._type, self._name))

    @property
    def align(self):
        """Variable alignment (:class:`~.int`)."""
        return self._align

    def __str__(self):
        """ """
        return "(%s) %s" % (self.type, self.name)


class VariableArray(Variable):
    """ """

    _cmp_attributes = ["name", "type", "size"]

    def __init__(self,
                 name,
                 vartype,
                 size,
                 align=None,
                 value=None,
                 address=None):
        """

        :param name:
        :param vartype:
        :param size:
        :param align:  (Default value = 16)
        :param value:  (Default value = None)

        """
        super(VariableArray, self).__init__()
        self._name = name
        self._type = vartype.lower()
        self._align = align
        self._value = value
        self._address = address
        self._elems = size

        if self._elems < 1:
            raise MicroprobeCodeGenerationError(
                "Array size should be greater than 0 in definition of "
                "variable: '%s'" % name)

        if align == 0:
            align = None

        if align is not None:
            val = math.log(align, 2)
            if val != int(val):
                raise MicroprobeCodeGenerationError(
                    "Alignment should be power of 2 in definition of "
                    "variable: '%s'" % name)

        if align is not None and address is not None:
            if not address.check_alignment(align):
                raise MicroprobeCodeGenerationError(
                    "Alignment requirements do not match address in definition"
                    " of variable: '%s'" % name)

    @property
    def type(self):
        """Variable type (:class:`~.str`)."""
        return self._type

    @property
    def name(self):
        """Variable name (:class:`~.str`)."""
        return self._name

    @property
    def value(self):
        """Variable value."""
        return self._value

    def array(self):
        """Return if the variable is an array.

        :rtype: :class:`~.bool`
        """
        return True

    @property
    def size(self):
        """Variable size in bytes (::class:`~.int`)."""

        if self._type in VAR_TYPE_LEN_DICT:
            return VAR_TYPE_LEN_DICT[self._type] * self._elems
        elif "*" in self._type:
            # TODO: Assuming a 64 bits address size
            return 8 * self._elems
        else:
            raise MicroprobeCodeGenerationError(
                "Unable to compute the size of type '%s' in definition "
                "of variable '%s'" % (self._type, self._name))

    @property
    def align(self):
        """Variable alignment (:class:`~.int`)."""
        return self._align

    @property
    def elems(self):
        """Number of elements in the variable array (:class:`~.int`)."""
        return self._elems

    def __str__(self):
        """ """
        return "(%s) %s[%s]" % (self.type, self.name, self._elems)

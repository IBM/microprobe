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
""":mod:`microprobe.target.isa.register_type` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc
import os

# Third party modules
import six

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.utils.logger import get_logger
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "register_type.yaml"
)
LOG = get_logger(__name__)
__all__ = ["import_definition", "RegisterType", "GenericRegisterType"]

# Functions


def import_definition(cls, filenames, dummy):
    """

    :param filenames:
    :param dummy:

    """

    LOG.debug("Start")
    regts = {}
    regts_duplicated = {}

    for filename in filenames:
        regt_data = read_yaml(filename, SCHEMA)

        for elem in regt_data:
            name = elem["Name"]
            size = elem["Size"]
            descr = elem.get("Description", "No description")
            u4aa = elem.get("AddressArithmetic", False)
            u4fa = elem.get("FloatArithmetic", False)
            u4va = elem.get("VectorArithmetic", False)
            regt = cls(name, descr, size, u4aa, u4fa, u4va)

            key = tuple([size, u4aa, u4fa, u4va])

            if key in regts_duplicated:
                LOG.warning(
                    "Similar definition of register types: '%s' and"
                    " '%s'. Check if definition needed.", name,
                    regts_duplicated[key]
                )
            else:
                regts_duplicated[key] = name

            LOG.debug(regt)

            if name in regts:
                raise MicroprobeArchitectureDefinitionError(
                    "Duplicated "
                    "definition of register type '%s' "
                    "found in '%s'" % (name, filename)
                )

            regts[name] = regt

    LOG.debug("End")
    return regts


# Classes
class RegisterType(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract base class to represent a Register Type"""

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def name(self):
        """Register type name (:class:`~.str`)"""
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """Register type name (:class:`~.str`)"""
        raise NotImplementedError

    @abc.abstractproperty
    def size(self):
        """Register size in bits (::class:`~.int`)"""
        raise NotImplementedError

    @abc.abstractproperty
    def used_for_address_arithmetic(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def used_for_float_arithmetic(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def used_for_vector_arithmetic(self):
        """ """
        raise NotImplementedError

    def __str__(self):
        """x.__str__() <==> str(x)"""
        return "%8s: %s (bit size: %d)" % (
            self.name, self.description, self.size
        )

    @abc.abstractmethod
    def __hash__(self):
        """ """
        raise NotImplementedError


class GenericRegisterType(RegisterType):
    """A class to represent a register type. Each register type is identified
    by its *type*, its *size* in bits and also its *semantic* properites (e.g.
    if they are used for address arithmetic, or for floating point cumpations,
    etc.) .

    :param rtype: Register type name
    :type rtype: :class:`~.str`
    :param rdescr: Register type description
    :type rdescr: :class:`~.str`
    :param rsize: Register size in bits
    :type rsize: :class:`~.int`

    """

    _cmp_attributes = [
        "name",
        "description",
        "size",
        "used_for_address_arithmetic",
        "used_for_float_arithmetic",
        "used_for_vector_arithmetic"]

    def __init__(self, rtype, rdescr, rsize, u4aa, u4fa, u4va):
        """

        :param rtype:
        :param rdescr:
        :param rsize:
        :param u4aa:
        :param u4fa:
        :param u4va:

        """
        super(GenericRegisterType, self).__init__()
        self._rtype = rtype
        self._rdescr = rdescr
        self._rsize = rsize
        self._used_for_address_arithmetic = u4aa
        self._used_for_float_arithmetic = u4fa
        self._used_for_vector_arithmetic = u4va
        self._hash = hash(
            (
                self.name, self.description, self.size,
                self.used_for_address_arithmetic,
                self.used_for_float_arithmetic, self.used_for_vector_arithmetic
            )
        )

    @property
    def name(self):
        """Register type name (:class:`~.str`)"""
        return self._rtype

    @property
    def description(self):
        """Register type description (:class:`~.str`)"""
        return self._rdescr

    @property
    def size(self):
        """Register type size in bits (::class:`~.int`)"""
        return self._rsize

    @property
    def used_for_address_arithmetic(self):
        """ """
        return self._used_for_address_arithmetic

    @property
    def used_for_float_arithmetic(self):
        """ """
        return self._used_for_float_arithmetic

    @property
    def used_for_vector_arithmetic(self):
        """ """
        return self._used_for_vector_arithmetic

    def __hash__(self):
        """ """
        return self._hash

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

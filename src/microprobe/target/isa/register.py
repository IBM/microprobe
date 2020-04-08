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
""":mod:`microprobe.target.isa.register` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc
import os

# Third party modules
import six
from six.moves import range

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Pickable
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "register.yaml"
)

LOG = get_logger(__name__)
__all__ = ["import_definition", "Register", "GenericRegister"]


# Functions
def import_definition(cls, filenames, regtypes):
    """

    :param filenames:
    :param regtypes:

    """

    LOG.debug("Start")
    regs = {}

    for filename in filenames:
        reg_data = read_yaml(filename, SCHEMA)

        if reg_data is None:
            continue

        for elem in reg_data:
            name = elem["Name"]
            descr = elem.get("Description", "No description")
            rtype = elem["Type"]
            rrepr = elem["Representation"]
            rcodi = elem.get("Codification", elem["Representation"])
            repeat = elem.get("Repeat", None)
            rfrom = 0
            rto = 0
            replace = "0"

            if rtype not in regtypes:
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown register type in definition of "
                    "register '%s' in file '%s'" % (name, filename)
                )

            if repeat:
                rfrom = repeat["From"]
                replace = "%s" % rfrom
                rto = repeat["To"]

            for index in range(rfrom, rto + 1):
                cname = name.replace(replace, "%d" % index)
                cdescr = descr.replace(replace, "%d" % index)
                crepr = rrepr.replace(replace, "%d" % index)
                ccodi = rcodi.replace(replace, "%d" % index)

                ctype = regtypes[rtype]

                regt = cls(cname, cdescr, ctype, crepr, ccodi)

                if cname in regs:
                    raise MicroprobeArchitectureDefinitionError(
                        "Duplicated register definition of '%s' found"
                        " in '%s'" % (cname, filename)
                    )

                LOG.debug(regt)
                regs[cname] = regt

    LOG.debug("End")
    return regs


# Classes
class Register(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract class to represent an architecture register."""

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def type(self):
        """Register type (:class:`~.RegisterType` instance)."""
        raise NotImplementedError

    @abc.abstractproperty
    def name(self):
        """Register name (:class:`~.str` instance)."""
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """Register description (:class:`~.str` instance)."""
        raise NotImplementedError

    @abc.abstractmethod
    def representation(self):
        """Return the assembly representation of this register."""
        raise NotImplementedError

    @abc.abstractmethod
    def codification(self):
        """Return the assembly representation of this register."""
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """Return the string representation of this register."""
        raise NotImplementedError

    @abc.abstractmethod
    def __repr__(self):
        """Return the string representation of this register."""
        raise NotImplementedError

    @abc.abstractmethod
    def __hash__(self):
        """ """
        raise NotImplementedError


class GenericRegister(Register, Pickable):
    """A Generic architected register"""

    _cmp_attributes = ["type", "representation", "name"]

    def __init__(self, name, descr, rtype, rrepr, rcodi):
        """

        :param name:
        :param descr:
        :param rtype:
        :param rrepr:

        """
        super(GenericRegister, self).__init__()
        self._rtype = rtype
        self._name = name
        self._descr = descr
        self._rrepr = rrepr
        self._rcodi = rcodi
        self._hash = hash(
            (
                self.name, self.description, self.representation, self.type
            )
        )

    @property
    def type(self):
        """ """
        return self._rtype

    @property
    def name(self):
        """ """
        return self._name

    @property
    def description(self):
        """ """
        return self._rtype

    @property
    def representation(self):
        """ """
        return str(self._rrepr)

    @property
    def codification(self):
        """ """
        return str(self._rcodi)

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

        if not isinstance(other, self.__class__):
            return False

        self._check_cmp(other)
        for attr in self._cmp_attributes:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)

            if (attr == "representation" and self_val.isdigit()
                    and other_val.isdigit()):
                self_val = int(self_val)
                other_val = int(other_val)

            if self_val != other_val:
                return False

        return True

    def __ne__(self, other):
        """x.__ne__(y) <==> x!=y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)

            if (attr == "representation" and self_val.isdigit()
                    and other_val.isdigit()):
                self_val = int(self_val)
                other_val = int(other_val)

            if self_val != other_val:
                return True

        return False

    def __lt__(self, other):
        """x.__lt__(y) <==> x<y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)

            if (attr == "representation" and self_val.isdigit()
                    and other_val.isdigit()):
                self_val = int(self_val)
                other_val = int(other_val)

            if self_val < other_val:
                return True
            elif self_val > other_val:
                return False

        return False

    def __gt__(self, other):
        """x.__gt__(y) <==> x>y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)

            if (attr == "representation" and self_val.isdigit()
                    and other_val.isdigit()):
                self_val = int(self_val)
                other_val = int(other_val)

            if self_val > other_val:
                return True
            elif self_val < other_val:
                return False

        return False

    def __le__(self, other):
        """x.__le__(y) <==> x<=y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)

            if (attr == "representation" and self_val.isdigit()
                    and other_val.isdigit()):
                self_val = int(self_val)
                other_val = int(other_val)

            if self_val > other_val:
                return False

        return True

    def __ge__(self, other):
        """x.__ge__(y) <==> x>=y"""
        self._check_cmp(other)
        for attr in self._cmp_attributes:
            self_val = getattr(self, attr)
            other_val = getattr(other, attr)

            if (attr == "representation" and self_val.isdigit()
                    and other_val.isdigit()):
                self_val = int(self_val)
                other_val = int(other_val)

            if not self_val < other_val:
                return False

        return True

    def __str__(self):
        """ """
        return "%8s : %s (Type: %s)" % (
            self._name, self._descr, self._rtype.name
        )

    def __repr__(self):
        """ """
        return "%s('%s')" % (self.__class__.__name__, self.name)

    def __getattr__(self, name):
        """If attribute not found, check if register type implements it

        :param name:

        """
        try:
            return self._rtype.__getattribute__(name)
        except AttributeError:
            raise AttributeError(
                "'%s' object has no attribute '%s'" %
                (self.__class__.__name__, name)
            )

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
""":mod:`microprobe.target.isa.instruction_field` module

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
    os.path.dirname(os.path.abspath(__file__)), "schemas",
    "instruction_field.yaml"
)

LOG = get_logger(__name__)
__all__ = ["import_definition", "InstructionField", "GenericInstructionField"]


# Functions
def import_definition(cls, filenames, operands):
    """

    :param filenames:
    :param operands:

    """

    LOG.debug("Start")
    ifields = {}
    ifields_duplicated = {}

    for filename in filenames:
        ifield_data = read_yaml(filename, SCHEMA)

        if ifield_data is None:
            continue

        for elem in ifield_data:
            name = elem["Name"]
            descr = elem.get("Description", "No description")
            size = elem["Size"]
            show = elem.get("Show", False)
            fio = elem.get("IO", "?")
            operand_def = elem.get("Operand", "Zero")

            key = tuple([size, show, fio, operand_def])

            if key in ifields_duplicated:
                LOG.warning(
                    "Similar definition of instruction field: '%s' and"
                    " '%s'. Check if definition needed.", name,
                    ifields_duplicated[key]
                )
            else:
                ifields_duplicated[key] = name

            try:
                operand = operands[operand_def]
            except KeyError:
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown operand "
                    "defined in instruction"
                    " field '%s' in '%s'." % (name, filename)
                )
            ifield = cls(name, descr, size, show, fio, operand)

            if name in ifields:
                raise MicroprobeArchitectureDefinitionError(
                    "Duplicated "
                    "definition "
                    "of instruction field"
                    " '%s' found in '%s'" % (name, filename)
                )

            LOG.debug(ifield)
            ifields[name] = ifield

    LOG.debug("End")
    return ifields


# Classes
class InstructionField(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract class to represent an instruction field"""

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def name(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def size(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def default_show(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def default_io(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def default_operand(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """ """
        raise NotImplementedError


class GenericInstructionField(InstructionField):
    """Instruction field generic class.

    :param fname: Field name.
    :type fname: :class:`~.str`
    :param fsize: Field size in bits.
    :type fsize: :class:`~.int`
    :param fshow: Assembly show flag.
    :type fshow: :class:`~.bool`
    :param fio: Input/Output flag.
    :type fio: :class:`~.str`
    :param foperand: Field operand.
    :type foperand: :class:`~.Operand` instance

    """

    _valid_fio_values = ['I', 'O', 'IO', '?']

    def __init__(self, fname, descr, fsize, fshow, fio, foperand):
        """

        :param fname:
        :param descr:
        :param fsize:
        :param fshow:
        :param fio:
        :param foperand:

        """
        super(GenericInstructionField, self).__init__()

        self._fname = fname
        self._fdescr = descr
        self._fsize = fsize
        self._fshow = fshow
        self._fio = fio
        self._foperand = foperand

        if fio not in self._valid_fio_values:
            raise MicroprobeArchitectureDefinitionError(
                "Invalid default IO "
                "definition for field "
                "%s" % fname
            )

    @property
    def name(self):
        """ """
        return self._fname

    @property
    def description(self):
        """ """
        return self._fdescr

    @property
    def size(self):
        """ """
        return self._fsize

    @property
    def default_show(self):
        """ """
        return self._fshow

    @property
    def default_operand(self):
        """ """
        return self._foperand

    @property
    def default_io(self):
        """ """
        return self._fio

    def __str__(self):
        """ """
        return "%10s : %s" % (self.name, self.description)

    def __repr__(self):
        """ """
        return "%s('%s')" % (self.__class__.__name__, self.name)

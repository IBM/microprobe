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
""":mod:`microprobe.target.uarch.element_type` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc
import os

# Third party modules
import six

# Own modules
from microprobe.property import PropertyHolder, import_properties
from microprobe.utils.logger import get_logger
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "element_type.yaml"
)

LOG = get_logger(__name__)
__all__ = [
    "import_definition", "MicroarchitectureElementType",
    "GenericMicroarchitectureElementType"
]


# Functions
def import_definition(cls, filenames, dummy):
    """

    :param cls:
    :type cls:
    :param filenames:
    :type filenames:
    :param dummy:
    :type dummy:
    """

    LOG.info("Start importing element type definitions")

    element_types = {}

    for filename in filenames:
        element_type_data = read_yaml(filename, SCHEMA)

        if element_type_data is None:
            continue

        for elem in element_type_data:
            name = elem["Name"]
            descr = elem.get("Description", "No description")

            element_type = cls(name, descr)
            element_types[name] = element_type

            LOG.debug(element_type)

    for filename in filenames:
        import_properties(filename, element_types)

    LOG.info("End importing element type definitions")
    return element_types


# Classes
class MicroarchitectureElementType(
    six.with_metaclass(
        abc.ABCMeta,
        PropertyHolder)):
    """Abstract class to represent a microarchitecture element type."""

    @abc.abstractmethod
    def __init__(self):
        """Create a microarchitecture element type.

        :return: MicroarchitectureElementType instance
        :rtype: :class:`~.MicroarchitectureElementType`
        """
        pass

    @abc.abstractproperty
    def name(self):
        """Microarchitecture element type name (:class:`~.str`)."""
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """Microarchitecture element type description (:class:`~.str`)."""
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """Return the string representation of this element type
        (:class:`~.str`)."""
        raise NotImplementedError


class GenericMicroarchitectureElementType(
    six.with_metaclass(
        abc.ABCMeta,
        MicroarchitectureElementType)):
    """Class to represent a generic microarchitecture element type."""

    def __init__(self, name, description):
        """Create a generic microarchitecture element type.

        :param name: Microarchitecture element type name
        :type name: :class:`~.str`
        :param description: Microarchitecture element type description
        :type description: :class:`~.str`
        :return: GenericMicroarchitectureElementType instance
        :rtype: :class:`~.GenericMicroarchitectureElementType`
        """
        super(GenericMicroarchitectureElementType, self).__init__()
        self._name = name
        self._description = description

    @property
    def name(self):
        """Microarchitecture element type name (:class:`~.str`)."""
        return self._name

    @property
    def description(self):
        """Microarchitecture element type description (:class:`~.str`)."""
        return self._description

    def __str__(self):
        """Return the string representation of this element type
        (:class:`~.str`)."""
        return "%s('%s','%s')" % (
            self.__class__.__name__, self.name, self.description
        )

    def __lt__(self, other):

        assert isinstance(other, MicroarchitectureElementType)

        name_cmp = self.name != other.name
        if name_cmp:
            return self.name < other.name

        return self.description < other.description

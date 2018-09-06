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
""":mod:`microprobe.target.uarch.element` module

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
from microprobe.property import PropertyHolder, import_properties
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "element.yaml"
)

LOG = get_logger(__name__)
__all__ = [
    "import_definition", "MicroarchitectureElement",
    "GenericMicroarchitectureElement"
]


# Functions
def import_definition(cls, filenames, element_types):
    """ """
    LOG.debug("Start importing microarchitecture elements")

    elements = RejectingDict()
    elements_subelements = RejectingDict()

    for filename in filenames:
        element_data = read_yaml(filename, SCHEMA)

        if element_data is None:
            continue

        for elem in element_data:
            name = elem["Name"]
            parent = elem.get("Parent", None)
            subelements = elem.get("Subelements", [])
            repeat = elem.get("Repeat", None)
            rfrom = 0
            rto = 0
            replace = "0"

            try:
                elem_type = element_types[elem["Type"]]
            except KeyError:
                raise MicroprobeArchitectureDefinitionError(
                    "Unknown "
                    "microarchitecture element type in "
                    "microarchitecture element definition "
                    " '%s' found in '%s'" % (name, filename)
                )
            descr = elem.get("Description", elem_type.description)

            if repeat:
                rfrom = repeat["From"]
                replace = "%s" % rfrom
                rto = repeat["To"]

            for index in range(rfrom, rto + 1):
                cname = name.replace(replace, "%d" % index)
                cdescr = descr.replace(replace, "%d" % index)
                element = cls(cname, cdescr, elem_type)

                try:
                    elements[cname] = element
                    elements_subelements[cname] = subelements
                except ValueError:
                    raise MicroprobeArchitectureDefinitionError(
                        "Duplicated microarchitecture element "
                        "definition '%s' found in '%s'" % (name, filename)
                    )

            LOG.debug(element)

    for filename in filenames:
        import_properties(filename, elements)

    for elem, subelements in elements_subelements.items():
        try:
            subelements_instances = [elements[item] for item in subelements]
        except KeyError as exc:
            raise MicroprobeArchitectureDefinitionError(
                "Undefined sub-element '%s' in element "
                "definition '%s'. Check following "
                "files: %s" % (exc, elem, filenames)
            )

        elements[elem].set_subelements(subelements_instances)

    element_list = list(elements.values())
    fixing_hierarchy = True

    LOG.info("Start building element hierarchy...")
    fix_pass = 0
    while fixing_hierarchy:
        fix_pass += 1
        LOG.debug("Start building element hierarchy... pass %d", fix_pass)
        fixing_hierarchy = False
        for element in element_list:
            parents = [
                item for item in element_list if element in item.subelements
            ]

            if len(parents) > 1:
                # needs duplication

                LOG.debug("Element %s has %d parents", element, len(parents))

                for parent in sorted(parents):
                    LOG.debug("Duplicating for parent: %s", parent)
                    # Create a new copy
                    new_element = cls(
                        element.name, element.description, element.type
                    )
                    new_element.set_subelements(element.subelements)
                    element_list.append(new_element)

                    # Update parent to point to the new copy
                    new_subelements = parent.subelements
                    new_subelements.remove(element)
                    new_subelements.append(new_element)
                    parent.set_subelements(new_subelements)
                    fixing_hierarchy = True

                element_list.remove(element)

    LOG.info("Finish building element hierarchy")

    # Check correctness of the structure and set parents
    LOG.info("Checking element hierarchy...")
    top_element = None
    for element in element_list:
        parents = [
            item for item in element_list if element in item.subelements
        ]

        if len(parents) > 1:
            raise MicroprobeArchitectureDefinitionError(
                "Wrong hierarchy of microarchitecture "
                "elements. The definition of element"
                " '%s' has multiple parents: '%s'." % (
                    element, [str(elem) for elem in parents]
                )
            )
        elif len(parents) == 0:
            if top_element is not None:
                raise MicroprobeArchitectureDefinitionError(
                    "Wrong hierarchy of microarchitecture "
                    "elements. There are at least two top "
                    "elements: '%s' and '%s'. Define a single "
                    "parent element for all the hierarchy." %
                    (element, top_element)
                )
            top_element = element
        else:
            element.set_parent_element(parents[0])

    if top_element is None:
        raise MicroprobeArchitectureDefinitionError(
            "Wrong hierarchy of microarchitecture "
            "elements. There is not a top element."
            " Define a single parent element for all "
            "the hierarchy."
        )

    LOG.info("Element hierarchy correct")

    elem_dict = dict(
        [
            (element.full_name, element) for element in element_list
        ]
    )

    for filename in filenames:
        import_properties(filename, elem_dict)

    LOG.info("End importing elements")
    return elem_dict


# Classes
class MicroarchitectureElement(
    six.with_metaclass(
        abc.ABCMeta,
        PropertyHolder)):
    """ """

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def name(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def full_name(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def type(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def depth(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def subelements(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def set_subelements(self, subelements):
        """

        :param subelements:

        """
        raise NotImplementedError

    @abc.abstractproperty
    def parent(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def parents(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def set_parent_element(self, parent):
        """

        :param parent:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def closest_common_element(self, element):
        """

        :param element:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """Return the string representation of this element"""
        raise NotImplementedError


class GenericMicroarchitectureElement(MicroarchitectureElement):
    """ """

    _cmp_attributes = ["depth", "type", "full_name", "name", "description"]

    def __init__(self, name, descr, mtype):
        """

        :param name:
        :param descr:
        :param mtype:

        """
        super(GenericMicroarchitectureElement, self).__init__()
        self._name = name
        self._descr = descr
        self._type = mtype

        self._parent = None
        self._subelements = {}

    @property
    def name(self):
        """ """
        return self._name

    @property
    def full_name(self):
        """ """
        if self._parent is None:
            return self._name
        return "%s_%s" % (self._name, self.parent.full_name)

    @property
    def parents(self):
        """ """
        if self._parent is None:
            return []
        return [self.parent] + self.parent.parents

    @property
    def description(self):
        """ """
        return self._descr

    @property
    def type(self):
        """ """
        return self._type

    @property
    def subelements(self):
        """ """
        return list(self._subelements.values())

    @property
    def parent(self):
        """ """
        return self._parent

    @property
    def depth(self):
        """ """
        if self._parent is None:
            return 0
        return 1 + self.parent.depth

    def set_parent_element(self, parent):
        """

        :param parent:

        """
        self._parent = parent
        assert self in parent.subelements

    def set_subelements(self, subelements):
        """

        :param subelements:

        """
        self._subelements = dict(
            [(element.name, element) for element in subelements]
        )

        for subelement in subelements:
            subelement.set_parent_element(self)

    def closest_common_element(self, element):
        """

        :param element:

        """

        own_parents = self.parents
        other_parents = element.parents

        for elem in own_parents:
            if elem in other_parents:
                return elem

        return None

    def __hash__(self):
        """ """
        return hash(
            (
                self.name, self.description,
                self.full_name, self.type, self.depth
            )
        )

    def __str__(self):
        """Return the string representation of this element"""
        return "%s('%s','%s','%s')" % (
            self.__class__.__name__, self.name, self.full_name,
            self.description
        )

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

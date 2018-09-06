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
""":mod:`microprobe.target.uarch` package

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc
import os

# Third party modules

# Own modules
import microprobe.target.uarch.element
import microprobe.target.uarch.element_type
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobeYamlFormatError
from microprobe.property import PropertyHolder, import_properties
from microprobe.target.uarch.cache import cache_hierarchy_from_elements
from microprobe.utils.imp import get_object_from_module, \
    import_cls_definition, import_definition, import_operand_definition
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import findfiles
from microprobe.utils.yaml import read_yaml
import six

# Local modules


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas",
    "microarchitecture.yaml"
)
DEFAULT_UARCH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "default",
    "microarchitecture.yaml"
)
LOG = get_logger(__name__)
__all__ = [
    "import_microarchitecture_definition",
    "find_microarchitecture_definitions", "Microarchitecture",
    "GenericMicroarchitecture", "GenericCPUMicroarchitecture"
]


# Functions
def _read_uarch_extensions(uarchdefs, path):
    """ """

    if "Extends" in uarchdefs[-1]:
        uarchdefval = uarchdefs[-1]["Extends"]
        del uarchdefs[-1]["Extends"]

        if not os.path.isabs(uarchdefval):
            uarchdefval = os.path.join(path, uarchdefval)

        uarchdef = read_yaml(
            os.path.join(
                uarchdefval, "microarchitecture.yaml"
            ), SCHEMA
        )
        uarchdef["Path"] = uarchdefval
        uarchdefs.append(uarchdef)

        _read_uarch_extensions(uarchdefs, uarchdefval)


def _read_yaml_definition(uarchdefs, path):
    """

    :param uarchdefs:
    :param path:

    """

    uarchdef = read_yaml(os.path.join(path, "microarchitecture.yaml"), SCHEMA)
    uarchdef["Path"] = path

    uarchdefs.append(uarchdef)

    _read_uarch_extensions(uarchdefs, path)

    baseuarch = read_yaml(DEFAULT_UARCH, SCHEMA)
    baseuarch["Path"] = DEFAULT_UARCH
    uarchdefs.append(baseuarch)

    complete_uarchdef = {}
    uarchdefs.reverse()

    for uarchdef in uarchdefs:
        for key, val in uarchdef.items():
            if not isinstance(val, dict):
                complete_uarchdef[key] = uarchdef[key]
            else:

                override = val.get("Override", False)

                if key not in complete_uarchdef:
                    complete_uarchdef[key] = {}

                for key2 in val:

                    if key2 in ["YAML", "Modules", "Path"]:
                        if key2 not in complete_uarchdef[key]:
                            complete_uarchdef[key][key2] = []

                        if os.path.isabs(val[key2]):
                            if override:
                                complete_uarchdef[key][key2] = [val[key2]]
                            else:
                                complete_uarchdef[key][key2].append(val[key2])
                        else:
                            if override:
                                complete_uarchdef[key][key2] = [
                                    os.path.join(
                                        uarchdef["Path"], val[key2]
                                    )
                                ]
                            else:
                                complete_uarchdef[key][key2].append(
                                    os.path.join(
                                        uarchdef["Path"], val[key2]
                                    )
                                )
                    elif key2 == "Module":
                        if val[key2].startswith("microprobe"):
                            val[key2] = os.path.join(
                                os.path.dirname(__file__), "..", "..", "..",
                                val[key2]
                            )

                        if os.path.isabs(val[key2]):
                            complete_uarchdef[key][key2] = val[key2]
                        else:
                            complete_uarchdef[key][key2] = os.path.join(
                                uarchdef["Path"], val[key2]
                            )
                    else:
                        complete_uarchdef[key][key2] = val[key2]

    return complete_uarchdef


def import_microarchitecture_definition(path):
    """Imports a Microarchitecture definition given a path

    :param path:

    """

    LOG.info("Start microarchitecture import")
    LOG.debug("Importing definition from '%s'", path)

    if not os.path.isabs(path):
        path = os.path.abspath(path)

    uarchdef = _read_yaml_definition([], path)

    element_types, force = import_definition(
        uarchdef, os.path.join(
            path, "microarchitecture.yaml"
        ), "Element_type", getattr(microprobe.target.uarch, 'element_type'),
        None
    )

    element, force = import_definition(
        uarchdef,
        os.path.join(
            path, "microarchitecture.yaml"
        ),
        "Element",
        getattr(
            microprobe.target.uarch, 'element'
        ),
        element_types,
        force=force
    )

    uarch_cls = get_object_from_module(
        uarchdef["Microarchitecture"]["Class"],
        uarchdef["Microarchitecture"]["Module"]
    )

    uarch = uarch_cls(
        uarchdef["Name"], uarchdef["Description"], element,
        uarchdef["Instruction_properties"]["Path"]
    )

    import_properties(
        os.path.join(path, "microarchitecture.yaml"), {uarchdef["Name"]: uarch}
    )

    LOG.info("Microarchitecture '%s' imported", uarch)
    return uarch


def find_microarchitecture_definitions(paths=None):

    if paths is None:
        paths = []

    paths = paths + MICROPROBE_RC["microarchitecture_paths"] \
        + MICROPROBE_RC["default_paths"]

    results = []
    uarchfiles = findfiles(paths, "^microarchitecture.yaml$")

    if len(uarchfiles) > 0:
        from microprobe.target import Definition

    for uarchfile in uarchfiles:

        try:
            isadef = read_yaml(uarchfile, SCHEMA)
        except MicroprobeYamlFormatError as exc:
            LOG.info("Exception: %s", exc)
            LOG.info("Skipping '%s'", uarchfile)
            continue

        try:
            definition = Definition(
                uarchfile, isadef["Name"], isadef["Description"]
            )
            if (
                definition not in results and
                not definition.name.endswith("common")
            ):
                results.append(definition)

        except TypeError as exc:
            # Skip bad definitions
            LOG.info("Exception: %s", exc)
            LOG.info("Skipping '%s'", uarchfile)
            continue
    return results


# Classes
class Microarchitecture(six.with_metaclass(abc.ABCMeta, PropertyHolder)):
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
    def description(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def elements(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def add_properties_to_isa(self, instructions):
        """

        :param instructions:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def full_report(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def set_target(self, target):
        """

        :param target:

        """
        raise NotImplementedError

    @abc.abstractproperty
    def target(self):
        """ """
        raise NotImplementedError


class GenericMicroarchitecture(Microarchitecture):
    """ """

    def __init__(self, name, descr, elements, instruction_properties_defs):
        """

        :param name:
        :param descr:
        :param elements:
        :param instruction_properties_defs:

        """
        super(GenericMicroarchitecture, self).__init__()
        self._name = name
        self._descr = descr
        self._elements = elements
        self._target = None
        self._instruction_property_defs = instruction_properties_defs

    @property
    def name(self):
        """ """
        return self._name

    @property
    def description(self):
        """ """
        return self._descr

    @property
    def elements(self):
        """ """
        return self._elements

    @property
    def target(self):
        """ """
        return self._target

    def set_target(self, target):
        """

        :param target:

        """
        self._target = target

    def add_properties_to_isa(self, instructions):
        """

        :param instructions:

        """
        for cfile in self._instruction_property_defs:
            import_properties(cfile, instructions)

    def full_report(self):
        """ """
        rstr = "-" * 80 + "\n"
        rstr += "Microarchitecture Name: %s\n" % self.name
        rstr += "Microarchitecture Description: %s\n" % self.name
        rstr += "-" * 80 + "\n"
        rstr += "Element Types:\n"
        for elem in sorted(
            set(
                [
                    elem.type for elem in self.elements.values()
                ]
            )
        ):
            rstr += str(elem) + "\n"
        rstr += "-" * 80 + "\n"
        rstr += "Elements:\n"
        for elem in sorted(self.elements.values()):
            rstr += str(elem) + "\n"
        rstr += "-" * 80 + "\n"
        return rstr

    def __str__(self):
        """ """
        return "%s('%s', '%s')" % (
            self.__class__.__name__, self.name, self.description
        )


class GenericCPUMicroarchitecture(GenericMicroarchitecture):
    """Generic CPU Microarchitecture

    Generic CPU microarchitecture. Assumes a cache hierarchy


    """

    def __init__(self, name, descr, elements, instruction_properties_defs):
        """

        :param name:
        :param descr:
        :param elements:
        :param instruction_properties_defs:

        """
        super(
            GenericCPUMicroarchitecture, self
        ).__init__(
            name, descr, elements, instruction_properties_defs
        )

        self._cache_hierarchy = cache_hierarchy_from_elements(elements)

    @property
    def cache_hierarchy(self):
        """ """
        return self._cache_hierarchy

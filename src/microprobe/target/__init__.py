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
""":mod:`microprobe.target` package

A target is defined by three components. The architecture definition
(see :mod:`~.isa` subpackage), the microarchitecture definition
(see :mod:`~.uarch` subpackage) and the environment definition
(see :mod:`~.env` subpackage). These three elements define the properties
of the target which might be queried during the code generation in order
to drive the code generation.

The main elements of this package are the following:

- :func:`~.import_definition` function provides support for importing target
  definitions.
- :class:`~.Definition` objects encapsulate the required information to be
  able to import architecture, microarchitecture or environment definitions.
- :class:`~.Target` objects are in charge of providing a generic API to query
  all kind of target properties. This is the main object that is used by other
  modules and packages of microprobe to query target information (e.g.
  instructions, registers, functional units, etc.).
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import collections
import copy
import itertools
import os

# Third party modules

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobeDuplicatedValueError, \
    MicroprobeError, MicroprobeImportDefinitionError, \
    MicroprobePolicyError, MicroprobeTargetDefinitionError
from microprobe.target.env import GenericEnvironment, \
    find_env_definitions, import_env_definition
from microprobe.target.isa import find_isa_definitions, import_isa_definition
from microprobe.target.uarch import find_microarchitecture_definitions, \
    import_microarchitecture_definition
from microprobe.utils.imp import get_attr_from_module, get_dict_from_module
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import Pickable, RejectingDict, findfiles

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = [
    "import_definition",
    # "import_policies",
    "Target",
    "Definition"
]


# Functions
def import_definition(definition_tuple):
    """Return the target corresponding the to the given *definition_tuple*.

    Return the target object corresponding the to the given
    *definition_tuple*. The *definition_tuple* is a string of the form
    ``<architecture_name>-<uarch_name>-<environment_name>`` that defines the
    target. This function uses the search paths provided in the configuration
    to look for the definitions to import.

    :param definition_tuple: Target definition string
    :type definition_tuple: :class:`~.str`
    :return: The target object corresponding to the given *definition_tuple*
    :rtype: :class:`~.Target`
    :raise microprobe.exceptions.MicroprobeTargetDefinitionError: if something
        is wrong during the import
    """
    LOG.debug("Start importing definition tuple")

    if isinstance(definition_tuple, str):
        definition_tuple = _parse_definition_tuple(definition_tuple)

    isa_def, uarch_def, env_def = definition_tuple
    isa = import_isa_definition(os.path.dirname(isa_def.filename))
    env = import_env_definition(
        env_def.filename, isa,
        definition_name=env_def.name
    )
    uarch = import_microarchitecture_definition(
        os.path.dirname(uarch_def.filename)
    )

    target = Target(isa, uarch=uarch, env=env)
    LOG.info(
        "Target '%s-%s-%s' imported", isa_def.name, uarch_def.name,
        env_def.name
    )
    LOG.debug("End importing definition tuple")
    return target


def _parse_definition_tuple(definition_tuple):
    """Return the target definitions corresponding to the *definition_tuple*.

    Return the target definitions corresponding to the *definition_tuple*.
    Check the *definition_tuple* format, and for each element (architecture,
    microarchitecture and environment) looks for the if there is a definition
    present in the current defined definition paths. It returns a tuple with
    the three corresponding definitions.

    :param definition_tuple: Target definition string
    :type definition_tuple: :class:`~.str`
    :return: Tuple of target definitions
    :rtype: :func:`tuple` of :class:`~.Definition`
    :raise microprobe.exceptions.MicroprobeTargetDefinitionError: if something
        if the *definition_tuple* format is wrong or if the definition
        specified is not found
    """

    try:
        isa_def, architecture_def, env_def = definition_tuple.split("-")
    except ValueError:
        raise MicroprobeTargetDefinitionError(
            "Invalid format of '%s' target tuple" % definition_tuple
        )

    definitions = find_isa_definitions()
    if isa_def not in [definition.name for definition in definitions]:
        raise MicroprobeTargetDefinitionError(
            "ISA '%s' not available" % isa_def
        )
    else:
        isa_def = [
            definition
            for definition in definitions if definition.name == isa_def
        ][0]

    definitions = find_microarchitecture_definitions()
    if architecture_def not in [definition.name for definition in definitions]:
        raise MicroprobeTargetDefinitionError(
            "Microarchitecture '%s' not available" % architecture_def
        )
    else:
        architecture_def = [
            definition
            for definition in definitions
            if definition.name == architecture_def
        ][0]

    definitions = find_env_definitions()
    if env_def not in [definition.name for definition in definitions]:
        raise MicroprobeTargetDefinitionError(
            "Environment '%s' not available. " % env_def
        )
    else:
        env_def = [
            definition
            for definition in definitions if definition.name == env_def
        ][0]

    return (isa_def, architecture_def, env_def)

# def import_policies(target_name):
#    """Return the dictionary of policies for the *target_name*."""
#
#    paths = MICROPROBE_RC["default_paths"]
#    policies = RejectingDict()
#
#    for policy_file in findfiles(paths, "^.*.py$"):
#
#        LOG.debug("Looking for policies in '%s'", policy_file)
#
#        try:
#
#            name = get_attr_from_module("NAME", policy_file)
#            description = get_attr_from_module("DESCRIPTION", policy_file)
#            targets = get_attr_from_module("SUPPORTED_TARGETS", policy_file)
#            policy = get_attr_from_module("policy", policy_file)
#            extra = get_dict_from_module(policy_file)
#
#            LOG.debug("Policy '%s' found!", name)
#
#            if target_name in targets:
#
#                LOG.debug("Policy '%s' valid!", name)
#                policies[name] = Policy(name, description, policy,
#                                        targets, extra, policy_file)
#
#        except MicroprobeImportDefinitionError:
#            LOG.debug("Not a policy module")
#            continue
#
#        except MicroprobeDuplicatedValueError:
#            raise MicroprobePolicyError(
#                "Policy '%s' in '%s' is duplicated" % (name, policy_file)
#            )
#
#    return policies


# Classes
class Definition(object):
    """Class to represent a target element definition.

    A target element definition could be the definition of the architecture,
    the microarchitecture or the environment. In all three cases a definition
    is composed by the definition name, the filename (where in the file system
    the definition is located) and the description.
    """

    # Class constant used for nice string formmating
    _field1 = 18
    _field2 = 25
    _field3 = 78 - _field1 - _field2
    _fmt_str_ = "Name:'%%%ds', Description:'%%%ds', File:'%%%ds'" % (
        _field1, _field2, _field3
    )
    _cmp_attributes = ["name", "description", "filename"]

    def __init__(self, filename, name, description):
        """Create a Definition object.

        :param filename: Filename where the definition is placed
        :type filename: :class:`~.str`
        :param name: Name of the definition
        :type name: :class:`~.str`
        :param description: Description of the definition
        :type description: :class:`~.str`
        :return: Definition instance
        :rtype: :class:`~.Definition`
        """
        self._file = filename
        self._name = name
        self._description = description

    @property
    def description(self):
        """Description of the definition (:class:`~.str`)."""
        return self._description

    @property
    def filename(self):
        """Filename of the definition (:class:`~.str`)."""
        return self._file

    @property
    def name(self):
        """Name of the definition (:class:`~.str`)."""
        return self._name

    def __str__(self):
        """x.__str__() <==> str(x)."""
        return self._fmt_str_ % (self._name, self._description, self._file)

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
                return True
            else:
                return False
        return False


class Target(Pickable):
    """Class to represent a code generation target.

    A target is defined by the architecture, the microarchitecture
    implementation and the generation environment.
    The Target object provides a common interface to all the
    architecture/microarchitecture/environment specific methods using a
    facade software design pattern.
    Therefore, all the references to target related properties should go
    through this object interface in order to minimize the coupling with the
    other modules (code generation, design space exploration, ...).
    """

    def __init__(self, isa, env=None, uarch=None):
        """Create a Target object.

        :param isa: Architecture (i.e. Instruction Set Architecture)
        :type isa: :class:`~.ISA`
        :param env: Environment (default: None)
        :type env: :class:`~.Environment`
        :param uarch: Microarchitecture (default: None)
        :type uarch: :class:`~.Microarchitecture`
        :return: Target instance
        :rtype: :class:`~.Target`
        """
        self._isa = None
        self._uarch = None
        self._env = None
        self._policies = None
        self._wrapper = None

        self.set_isa(isa)

        if uarch is not None:
            self.set_uarch(uarch)
            self.microarchictecture.add_properties_to_isa(
                self.isa.instructions
            )

        if env is not None:
            self.set_env(env)
        else:
            self.set_env(
                GenericEnvironment(
                    "Default", "Empty environment", self.isa
                )
            )

    @property
    def name(self):
        """Name of the Target (:class:`~.str`)."""
        name = self._isa.name
        if self._uarch is not None:
            name += "-" + self._uarch.name
        if self._env is not None:
            name += "-" + self._env.name
        return name

    @property
    def description(self):
        """Description of the Target (:class:`~.str`)."""
        description = []
        description.append("Target ISA: %s" % self.isa.name)
        description.append("ISA Description: %s" % self.isa.description)
        if self.microarchictecture is not None:
            description.append(
                "Target Micro-architecture: %s" % self.microarchictecture.name
            )
            description.append(
                "Micro-architecture Description: %s" %
                self.microarchictecture.description
            )
        else:
            description.append("Target Micro-architecture: Not defined")
            description.append("Micro-architecture Description: Not defined")
        description.append("Target Environment: %s" % self.environment.name)
        description.append(
            "Environment description: %s" % self.environment.description
        )
        return "\n".join(description)

    @property
    def environment(self):
        """Environment of the Target (:class:`~.Environment`)."""
        return self._env

    @property
    def isa(self):
        """Architecture of the Target (:class:`~.ISA`)."""
        return self._isa

    @property
    def microarchictecture(self):
        """Microarchitecture of the Target (:class:`~.Microarchitecture`)."""
        return self._uarch

    @property
    def reserved_registers(self):
        """Reserved registers of the Target (:class:`~.list` of
        :class:`~.Register`)."""
        return self.environment.environment_reserved_registers + \
            self.isa.scratch_registers

    @property
    def wrapper(self):
        """Wrapper of the Target (:class:`~.Wrapper`)."""
        return self._wrapper

    def full_report(self):
        """Return a long description of the Target.

        :rtype: :class:`~.str`
        """
        rstr = self.isa.full_report() + '\n'
        if self.microarchictecture is not None:
            rstr += self.microarchictecture.full_report() + '\n'
        rstr += self.environment.full_report() + '\n'
        return rstr

    def property_isa_map(self, prop_name):
        """Generate property to isa map.

        Return a dictionary mapping values of the property *prop_name* to
        the list of :class:`~.InstructionType` that have that property value.

        :param prop_name: Property name
        :type prop_name: :class:`~.str`
        :return: Dictionary mapping value properties to instruction types
        :rtype: :class:`~.dict` mapping property values to :class:`~.list` of
                :class:`~.InstructionType`
        :raise microprobe.exceptions.MicroprobeTargetDefinitionError: if the
            property is not found
        """
        prop_map = {}

        for instr in self.isa.instructions.values():

            try:
                value = getattr(instr, prop_name)
            except AttributeError:
                raise MicroprobeTargetDefinitionError(
                    "Property '%s' for instruction not found" % prop_name
                )

            if not isinstance(value, list):
                values = [value]
            else:
                values = value

            for value in values:

                if value not in prop_map:
                    prop_map[value] = []

                prop_map[value].append(instr)

        for key in prop_map:
            prop_map[key] = set(prop_map[key])

        return prop_map

    def set_env(self, env):
        """Set the environment of the Target.

        :param env: Execution environment definition
        :type env: :class:`~.Environment`
        """
        self._env = copy.deepcopy(env)
        self._env.set_target(self)

    def set_isa(self, isa):
        """Set the ISA of the Target.

        :param isa: Architecture (i.e. ISA)
        :type isa: :class:`~.ISA`
        """
        self._isa = copy.deepcopy(isa)
        self._isa.set_target(self)

    def set_uarch(self, uarch):
        """Set the microarchitecture of the Target.

        :param uarch: Microarchitecture
        :type uarch: :class:`~.Microarchitecture`
        """
        self._uarch = uarch
        self._uarch.set_target(self)

    # TODO: remove this interface once the code generation back-end is fixed
    def set_wrapper(self, wrapper):
        """Set the wrapper of the Target.

        :param wrapper: Wrapper
        :type wrapper: :class:`~.Wrapper`
        """
        self._wrapper = wrapper

    def __getattr__(self, name):
        """Facade design pattern implementation.

        This is where we implement the facade design pattern. Whenever an
        attribute is not defined by the Target object itself, it is searched
        if it is defined by one of the three elements composing the target.

        :param name: Attribute name
        :type name: :class:`~.str`
        :return: Attribute value
        :rtype: Type of the value of the attribute requested
        :raise microprobe.exceptions.MicroprobeError: if attribute is defined
            in multiple objects
        :raise AttributeError: if attribute is not found in the class
               or any of the facade classes
        """
        if name in ["description", "name"]:
            return self.__getattribute__(name)

        attrs = []
        if self._isa is not None:
            try:
                attrs.append(self._isa.__getattribute__(name))
            except AttributeError:
                pass

        if self._uarch is not None:
            try:
                attrs.append(self._uarch.__getattribute__(name))
            except AttributeError:
                pass

        if self._env is not None:
            try:
                attrs.append(self._env.__getattribute__(name))
            except AttributeError:
                pass

        if len(attrs) == 1:
            return attrs[0]
        elif len(attrs) > 1:
            if all([isinstance(attr, list) for attr in attrs]):
                return list(itertools.chain.from_iterable(attrs))
            else:
                raise MicroprobeError("Attribute defined in multiple objects")
        else:
            raise AttributeError(
                "'%s' object has no attribute '%s'" %
                (self.__class__.__name__, name)
            )

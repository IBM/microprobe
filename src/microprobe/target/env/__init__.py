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
""":mod:`microprobe.target.env` package

"""

# Futures
from __future__ import absolute_import, annotations

# Built-in modules
import abc
from typing import TYPE_CHECKING, List

# Third party modules

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address
from microprobe.code.context import Context
from microprobe.code.var import VariableArray
from microprobe.exceptions import MicroprobeImportDefinitionError, \
    MicroprobeValueError
from microprobe.property import Property, PropertyHolder
from microprobe.utils.imp import find_subclasses
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import findfiles
from microprobe.utils.typeguard_decorator import typeguard_testsuite

# Local modules

# Type hinting
if TYPE_CHECKING:
    from microprobe.target.isa import ISA
    from microprobe.code.ins import Instruction
    from microprobe.target import Target
    from microprobe.target import Definition
    from microprobe.target.isa.register import Register

# Constants
LOG = get_logger(__name__)

_INIT = True
_ENV_DEFINITIONS = None
__all__ = [
    "import_env_definition", "find_env_definitions", "Environment",
    "GenericEnvironment"
]


# Functions
@typeguard_testsuite
def import_env_definition(module,
                          isa: ISA,
                          definition_name: str | None = None):
    """

    :param module:
    :param isa:
    :param definition_name:  (Default value = None)

    """

    LOG.info("Start Environment import")
    envcls = list(
        find_subclasses(module,
                        GenericEnvironment,
                        extra_import_name=definition_name))

    LOG.debug("Definition name: %s", definition_name)
    LOG.debug("Classes: %s", envcls)

    if definition_name is not None:
        envcls = [cls for cls in envcls if cls.__name__ == definition_name]

    if len(envcls) > 1 and definition_name is None:
        LOG.warning("Multiple environment definitions found and a specific"
                    " name not provided. Taking the first one.")
    elif len(envcls) < 1 and definition_name is None:
        raise MicroprobeImportDefinitionError(
            "No environment definitions found in '%s'" % module)

    elif len(envcls) < 1:
        raise MicroprobeImportDefinitionError(
            "No environment definitions found in '%s' with name"
            " '%s'" % (module, definition_name))

    environment = envcls[0](isa)

    LOG.info("Environment '%s' imported", environment)
    return environment


@typeguard_testsuite
def find_env_definitions(paths: List[str] | None = None):

    LOG.debug("Start find environment definitions")

    global _INIT  # pylint: disable=global-statement
    global _ENV_DEFINITIONS  # pylint: disable=global-statement

    if not _INIT:
        return _ENV_DEFINITIONS

    _INIT = False

    if paths is None:
        paths = []

    paths = paths + MICROPROBE_RC["environment_paths"] \
        + MICROPROBE_RC["default_paths"]

    results: List["Definition"] = []
    files = findfiles(paths, "env/.*.py$", full=True)

    if len(files) > 0:
        from microprobe.target import Definition
        LOG.debug("Files found")

        for modfile in files:
            LOG.debug("Processing file: '%s'", modfile)
            try:
                envclses = list(find_subclasses(modfile, GenericEnvironment))
            except (MicroprobeValueError, TypeError) as exc:
                continue

            LOG.debug("Classes find: '%s'", envclses)
            for envcls in envclses:
                LOG.debug("Trying class: '%s'", envcls)
                try:
                    env = envcls(None)
                    definition = Definition(modfile, env.name, env.description)
                    if definition not in results:
                        results.append(definition)
                except TypeError as exc:
                    # Skip not complete environments
                    LOG.debug("Skipping class '%s'...", envcls)
                    LOG.debug(exc)
                    continue

    LOG.debug("End find environment definitions")
    _ENV_DEFINITIONS = results
    return results


# Classes
@typeguard_testsuite
class Environment(PropertyHolder, metaclass=abc.ABCMeta):
    """ """

    @abc.abstractmethod
    def __init__(self):
        pass

    @property
    @abc.abstractmethod
    def name(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def description(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def isa(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def environment_reserved_registers(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def threads(self):
        raise NotImplementedError

    @abc.abstractmethod
    def set_threads(self, num_threads):
        """

        :param num_threads:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        raise NotImplementedError

    @abc.abstractmethod
    def register_name(self, register):
        """

        :param register:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def full_report(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def default_wrapper(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def stack_pointer(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def stack_direction(self):
        raise NotImplementedError

    @abc.abstractmethod
    def elf_abi(self, stack_size, start_symbol):
        raise NotImplementedError

    @abc.abstractmethod
    def function_call(self, target, return_address_reg=None, long_jump=False):
        raise NotImplementedError

    @abc.abstractmethod
    def function_return(self, return_address_reg=None):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def volatile_registers(self):
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def little_endian(self):
        raise NotImplementedError

    @abc.abstractmethod
    def set_target(self, target: Target):
        """

        :param target:

        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def target(self):
        raise NotImplementedError

    @abc.abstractmethod
    def hook_before_test_instructions(self):
        raise NotImplementedError

    @abc.abstractmethod
    def hook_after_test_instructions(self):
        raise NotImplementedError

    @abc.abstractmethod
    def hook_test_init_instructions(self):
        raise NotImplementedError

    @abc.abstractmethod
    def hook_after_reset_instructions(self):
        raise NotImplementedError

    @abc.abstractmethod
    def hook_test_end_instructions(self):
        raise NotImplementedError


@typeguard_testsuite
class GenericEnvironment(Environment):
    """ """

    _cmp_attributes = ["name", "descr"]

    def __init__(self,
                 name: str,
                 descr: str,
                 isa: ISA,
                 little_endian: bool = False):
        """

        :param name:
        :param descr:
        :param isa:

        """
        super(GenericEnvironment, self).__init__()
        self._name = name
        self._description = descr
        self._isa = isa
        self._reserved_registers: List[Register] = []
        self._threads = 1
        self._target: Target | None = None
        self._default_wrapper = None
        self._little_endian = little_endian
        self.register_property(
            Property(
                "problem_state", "Boolean indicating if the program"
                " is executed in the problem state"
                " (not privilege level)", True))

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def isa(self):
        return self._isa

    @property
    def environment_reserved_registers(self):
        return self._reserved_registers

    @property
    def threads(self):
        return self._threads

    @property
    def target(self):
        return self._target

    def set_target(self, target: Target):
        """

        :param target:

        """
        self._target = target

    def set_threads(self, num_threads: int):
        """

        :param num_threads:

        """
        self._threads = num_threads

    def __str__(self):
        return "Environment '%s': %s" % (self.name, self.description)

    def register_name(self, register: str):
        """

        :param register:

        """
        raise NotImplementedError(
            "Register name translation requested but not implemented. Check"
            " if you are targeting the appropriate environment (%s)" %
            register)

    def full_report(self):
        return str(self)

    @property
    def default_wrapper(self):
        return self._default_wrapper

    def elf_abi(self,
                stack_size: int,
                start_symbol,
                stack_name: str = "microprobe stack",
                stack_alignment: int = 16,
                stack_address: Address | None = None,
                **kwargs):

        stack = VariableArray(stack_name,
                              "uint8_t",
                              stack_size,
                              align=stack_alignment,
                              address=stack_address)

        instructions: List[Instruction] = []
        instructions += self.target.set_register_to_address(
            self.stack_pointer, Address(base_address=stack_name), Context())

        if self.stack_direction == "decrease":
            instructions += self.target.add_to_register(
                self.stack_pointer, stack_size)

        if start_symbol is not None:
            instructions += self.target.function_call(start_symbol)
            instructions += self.target.function_call("ELF_ABI_EXIT")

        instructions[0].set_label("ELF_ABI_START")

        return [stack], instructions

    def function_call(self,
                      target: Target,
                      return_address_reg: Register | None = None,
                      long_jump: bool = False):
        raise NotImplementedError

    def function_return(self, return_address_reg: Register | None = None):
        raise NotImplementedError

    @property
    def volatile_registers(self):
        raise NotImplementedError

    @property
    def stack_pointer(self):
        raise NotImplementedError

    @property
    def stack_direction(self):
        raise NotImplementedError

    @property
    def little_endian(self):
        return self._little_endian

    def _check_cmp(self, other):

        if not isinstance(other, self.__class__):
            raise NotImplementedError("%s != %s" %
                                      (other.__class__, self.__class__))

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

    def hook_before_test_instructions(self):
        return []

    def hook_after_test_instructions(self):
        return [self._target.nop()]

    def hook_test_init_instructions(self):
        return []

    def hook_after_reset_instructions(self):
        return []

    def hook_test_end_instructions(self):
        return []

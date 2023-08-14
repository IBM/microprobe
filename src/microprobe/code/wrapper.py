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
"""
This is the wrapper module documentation
"""
# Futures
from __future__ import absolute_import, annotations

# Built-in modules
import abc
from typing import TYPE_CHECKING, Callable, List

# Own modules
from microprobe.code.context import Context
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.logger import get_logger
from microprobe.utils.typeguard_decorator import typeguard_testsuite

# Type hinting
if TYPE_CHECKING:
    from microprobe.code.benchmark import Benchmark
    from microprobe.code.ins import Instruction
    from microprobe.code.var import Variable
    from microprobe.target import Target
    from microprobe.target.isa.register import Register

# Constants
LOG = get_logger(__name__)
__all__ = ["Wrapper"]

# Functions


# Classes
@typeguard_testsuite
class Wrapper(abc.ABC):
    """
    Abstract class to represent a language wrapper.
    """

    @abc.abstractmethod
    def __init__(self):
        """Initialization abstract method."""
        self._bench = None
        self._target = None
        self._context = Context()
        self._reset_state = False
        self._direct_init_dict = None

    @abc.abstractmethod
    def outputname(self, name: str) -> str:
        """

        :param name:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def headers(self) -> str:
        """ """
        raise NotImplementedError

    # @abc.abstractmethod
    # def declare_option(self, option_flag, var,):
    #    raise NotImplementedError

    @abc.abstractmethod
    def declare_global_var(self, var: Variable) -> str:
        """

        :param var:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def init_global_var(self, var: Variable,
                        value: int | str | Callable[[], int | str]) -> str:
        """

        :param var:
        :param value:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def required_global_vars(self) -> List[Variable]:
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def start_main(self) -> str:
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def post_var(self) -> str:
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def start_loop(self,
                   instr: Instruction,
                   instr_reset: Instruction,
                   aligned: bool = True) -> str:
        """

        :param instr:
        :param instr_reset:
        :param aligned:  (Default value = True)

        """
        raise NotImplementedError

    @abc.abstractmethod
    def wrap_ins(self, instr: Instruction) -> str:
        """

        :param instr:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def end_loop(self, instr: Instruction) -> str:
        """

        :param instr:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def end_main(self) -> str:
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def footer(self) -> str:
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def infinite(self) -> bool:
        """Returns a :class:`~.bool` indicating if the loop is infinite. """
        raise NotImplementedError

    @abc.abstractmethod
    def reserved_registers(self, registers: List[Register],
                           target: Target) -> List[Register]:
        """

        :param registers:
        :param target:

        """
        raise NotImplementedError

    def set_benchmark(self, bench: Benchmark):
        """

        :param bench:

        """
        self._bench = bench

    @property
    def benchmark(self):
        """ """
        return self._bench

    @property
    def reset(self):
        """ """
        return self._reset_state

    def set_target(self, target: Target):
        """

        :param target:

        """
        self._target = target

    @property
    def target(self):
        """ """
        return self._target

    def context(self):
        """ """
        return self._context.copy()

    def init_loop_pad(self):
        """ """
        return 0

    def init_main_pad(self):
        """ """
        return 0

    @property
    def direct_initialization_support(self):
        """ Boolean indicating if the wrapper supports direct initialization.

        Direct initialization refers to the capability of initializing values
        without requiring the execution of instructions. For instance,
        simulation-based format usually allow the specification of the
        initial values of the memory and the registers.
        """
        return False

    def register_direct_init(self, dummy_key, dummy_value):
        """ Initialize *key* with the value *value* """
        if self.direct_initialization_support:
            raise NotImplementedError
        else:
            raise MicroprobeCodeGenerationError(
                "Direct intialization function called but not supported")

    def get_direct_init(self, key, defaultvalue):
        """ Get the *value* for *key* """
        if self.direct_initialization_support:

            if isinstance(key, str):
                keys = self.target.registers.values()
                keys = [lkey for lkey in keys if lkey.name == key]
                if len(keys) != 1:
                    raise MicroprobeCodeGenerationError(
                        "Unable to find the direct initialization value"
                        " name: %s" % key)
                key = keys[0]

            if key in self._direct_init_dict:
                return self._direct_init_dict[key]

            if defaultvalue is not None:
                return defaultvalue

            raise MicroprobeCodeGenerationError(
                "Unable to find the direct initialization value")

        else:
            raise MicroprobeCodeGenerationError(
                "Direct intialization function called but not supported")

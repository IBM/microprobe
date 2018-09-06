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
"""
This is the wrapper module documentation
"""
# Futures
from __future__ import absolute_import

# Built-in modules
import abc

# Third party modules
import six

# Own modules
from microprobe.code.context import Context
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["Wrapper"]

# Functions


# Classes
class Wrapper(six.with_metaclass(abc.ABCMeta, object)):
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

    @abc.abstractmethod
    def outputname(self, name):
        """

        :param name:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def headers(self):
        """ """
        raise NotImplementedError

    # @abc.abstractmethod
    # def declare_option(self, option_flag, var,):
    #    raise NotImplementedError

    @abc.abstractmethod
    def declare_global_var(self, var):
        """

        :param var:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def init_global_var(self, var, value):
        """

        :param var:
        :param value:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def required_global_vars(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def start_main(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def post_var(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def start_loop(self, instr, instr_reset, aligned=True):
        """

        :param instr:
        :param instr_reset:
        :param aligned:  (Default value = True)

        """
        raise NotImplementedError

    @abc.abstractmethod
    def wrap_ins(self, instr):
        """

        :param instr:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def end_loop(self, instr):
        """

        :param instr:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def end_main(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def footer(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def infinite(self):
        """Returns a :class:`~.bool` indicating if the loop is infinite. """
        raise NotImplementedError

    @abc.abstractmethod
    def reserved_registers(self, registers, target):
        """

        :param registers:
        :param target:

        """
        raise NotImplementedError

    def set_benchmark(self, bench):
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

    def set_target(self, target):
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
                "Direct intialization function called but not supported"
            )

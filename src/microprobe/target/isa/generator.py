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
""":mod:`microprobe.target.isa.generator` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc

# Third party modules
import six

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.utils.imp import find_subclasses
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["import_classes_from", "Generator"]


# Functions
def import_classes_from(modules):
    """

    :param modules:

    """

    LOG.info("Start")
    classes = {}

    for module_str in modules:
        for cls in find_subclasses(module_str, Generator):

            name = cls.__name__
            if name in classes:
                raise MicroprobeArchitectureDefinitionError(
                    "Duplicated "
                    "definition"
                    " of Generator '%s' "
                    "in module '%s'", name, module_str
                )

            LOG.info("%s generator imported", name)
            classes[name] = cls

    if len(classes) == 0:
        LOG.warning("No generators imported.")

    LOG.info("End")
    return list(classes.values())


# Classes
class Generator(six.with_metaclass(abc.ABCMeta, object)):
    """ """

    def __init__(self, arch):
        """

        :param arch:

        """
        self._arch = arch

    @abc.abstractmethod
    def check(self, value, fvalue, address=False):
        """

        :param value:
        :param fvalue:
        :param address:  (Default value = False)

        """
        raise NotImplementedError

    @abc.abstractmethod
    def generate(
        self, value,
        fvalue, dummy_reg,
        dummy_instr=None,
        address=False
    ):
        """

        :param value:
        :param fvalue:
        :param dummy_reg:
        :param dummy_instr:  (Default value = None)
        :param address:  (Default value = False)

        """
        assert (value, fvalue) == self.check(value, fvalue, address=address), \
            "Check error: (%s, %s) != %s " % (value, fvalue,
                                              self.check(value,
                                                         fvalue,
                                                         address=address))

    @abc.abstractproperty
    def instr_name(self):
        """ """
        raise NotImplementedError

    @property
    def arch(self):
        """ """
        return self._arch

    def _orig_reg(self, value, reg, instr):
        """

        :param value:
        :param reg:
        :param instr:

        """
        if value in list(self.arch.constants.keys()):
            reg2 = self.arch.constants[value][-1]
            if reg2 != reg:
                instr.add_allow_register(reg2)
                return reg2
        return reg

    @property
    def alias(self):  # pylint: disable=no-self-use
        """ """
        return []

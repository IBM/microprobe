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
""":mod:`microprobe.target.isa.comparator` module

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
__all__ = ["import_classes_from", "Comparator"]


# Functions
def import_classes_from(modules):
    """

    :param modules:

    """

    LOG.info("Start")
    classes = {}

    for module_str in modules:
        for cls in find_subclasses(module_str, Comparator):

            name = cls.__name__
            if name in classes:
                raise MicroprobeArchitectureDefinitionError(
                    "Duplicated "
                    "definition"
                    " of Comparator '%s' "
                    "in module '%s'" % (name, module_str)
                )
            LOG.info("%s comparator imported", name)
            classes[name] = cls

    if len(classes) == 0:
        LOG.warning("No comparators imported.")

    LOG.info("End")
    return list(classes.values())


# Classes
class Comparator(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract class to perform comparisons. :class:`~.Comparator`
    objects are in charge of performing comparisons between values
    while providing an architecture independent and modular interface.
    They are registered in an :class:`~.ISA` object using the
    :meth:`~.ISA.register_value_comparator`.
    Once registered, whenever a comparison is needed to perform a
    given operation, it is possible to check (:meth:`check`) if
    the :class:`~.Comparator` can perform the requested comparison,
    and if so, it can generate (:meth:`generate`) the required
    :class:`~.list` of :class:`~.Instruction` to perform it.

    :param isa: Architecture to operate on.

    """

    def __init__(self, arch):
        """

        :param arch:

        """
        self._arch = arch

    @abc.abstractmethod
    def check(self, reg, value):
        """Checks whether the :class:`~.Register` *reg* instance can
        be compared with the *value*, which can be a ::class:`~.int` or another
        :class:`~.Register`. If is not possible to perform the
        comparison, a `None` value is returned. Otherwise, the
        :class:`~.Register` instance where the result of the
        comparison would be placed is returned.

        :param reg: 1st operand of the comparison.
        :type reg: :class:`~.Register`
        :param value: 2nd operand of the comparison.
        :type value: :class:`~.Register` or ::class:`~.int`

        """
        raise NotImplementedError

    @abc.abstractmethod
    def generate(self, reg, value, helper_instr):
        """Generate the :class:`~.Instruction` to perform
        the comparison. If the required instruction is found within
        the :class:`~.list` of :class:`~.Instruction`
        *helper_instr*, no new instruction is generated and the matching
        instruction operands are set accordingly.

        :param reg: 1st operand of the comparison.
        :type reg: :class:`~.Register`
        :param value: 2nd operand of the comparison.
        :type value: :class:`~.Register` or ::class:`~.int`
        :param helper_instr: List of helper instructions.
        :type helper_instr: :class:`~.list` of :class`~.Instruction`
                    instances.

        """
        raise NotImplementedError

    @abc.abstractproperty
    def instr_name(self):
        """Value comparator name, usually the opcode of the instruction it
        uses (:class:`~.str`).


        """
        raise NotImplementedError

    @property
    def arch(self):
        """Architecture on this :class:`~.Comparator` will work on
        (:class:`~.ISA`).


        """
        return self._arch

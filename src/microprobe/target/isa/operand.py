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
""":mod:`microprobe.target.isa.operand` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import abc
import os
import random

# Third party modules
import six
from six.moves import range

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address
from microprobe.code.var import Variable
from microprobe.exceptions import MicroprobeArchitectureDefinitionError, \
    MicroprobeCodeGenerationError, MicroprobeValueError
from microprobe.target.isa.register import Register
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import OrderedDict, natural_sort
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "operand.yaml"
)

LOG = get_logger(__name__)
__all__ = [
    "import_definition", "OperandDescriptor", "MemoryOperandDescriptor",
    "MemoryOperand", "Operand", "OperandReg", "OperandImmRange",
    "OperandValueSet", "OperandConst", "OperandConstReg",
    "InstructionAddressRelativeOperand"
]


# Functions
def import_definition(filenames, inherits, registers):
    """

    :param filenames:
    :param registers:

    """

    LOG.debug("Start")
    operands = {}
    operands_duplicated = {}
    register_types = tuple([reg.type.name for reg in registers.values()])

    for filename in filenames:
        ope_data = read_yaml(filename, SCHEMA)

        if ope_data is None:
            continue

        for elem in ope_data:

            name = elem["Name"]
            descr = elem.get("Description", "No description")
            override = elem.get("Override", False)
            key = []

            try:

                if "Registers" in elem:

                    regnames = elem["Registers"]

                    if isinstance(regnames, list):

                        if len(regnames) == 1 and \
                                regnames[0] in register_types:
                            regs = [
                                reg
                                for reg in registers.values()
                                if reg.type.name == regnames[0]
                            ]
                        else:
                            regs = [
                                registers[regname]
                                for regname in natural_sort(regnames)
                            ]

                        key.append(tuple(regnames))

                    else:
                        regs = OrderedDict()
                        for regname in natural_sort(regnames):
                            regs[registers[regname]] = []
                            for regname2 in regnames[regname]:
                                regs[registers[regname]].append(
                                    registers[regname2]
                                )

                        key.append(
                            tuple(
                                [
                                    (
                                        k, tuple(v)
                                    ) for k, v in regnames.items()
                                ]
                            )
                        )

                    address_base = elem.get("AddressBase", False)
                    address_index = elem.get("AddressIndex", False)
                    floating_point = elem.get("FloatingPoint", None)
                    vector = elem.get("Vector", None)

                    key.append(address_base)
                    key.append(address_index)
                    key.append(floating_point)
                    key.append(vector)

                    # Filter out Register without
                    # representation (N/A)
                    #
                    # These are pseudo registers used in
                    # simulation/emulation environment.
                    # They are not architected registers.

                    if isinstance(regs, list):
                        regs = [reg for reg in regs
                                if reg.representation != 'N/A']
                    elif isinstance(regs, dict):
                        for elem in regs:
                            regs[elem] = [
                                reg2 for reg2 in regs[elem]
                                if reg2.representation != 'N/A'
                            ]

                    operand = OperandReg(
                        name, descr, regs, address_base, address_index,
                        floating_point, vector
                    )

                elif "Min" in elem and "Max" in elem:

                    minval = elem["Min"]
                    maxval = elem["Max"]
                    step = elem.get("Step", 1)
                    novalues = elem.get("Except", [])
                    address_index = elem.get("AddressIndex", False)
                    shift = elem.get("Shift", 0)
                    add = elem.get("Add", 0)

                    key.append(minval)
                    key.append(maxval)
                    key.append(step)
                    key.append(tuple(novalues))
                    key.append(address_index)
                    key.append(shift)
                    key.append(add)

                    operand = OperandImmRange(
                        name, descr, minval, maxval, step, address_index,
                        shift, novalues, add
                    )

                elif "Values" in elem:

                    values = tuple(elem["Values"])
                    rep = elem.get("Representation", None)
                    key.append(tuple(values))
                    operand = OperandValueSet(name, descr, values, rep)

                elif "Value" in elem:

                    value = elem["Value"]
                    key.append(value)

                    operand = OperandConst(name, descr, value)

                elif "Register" in elem:

                    reg = registers[elem["Register"]]
                    address_base = elem.get("AddressBase", False)
                    address_index = elem.get("AddressIndex", False)
                    floating_point = elem.get("FloatingPoint", False)
                    vector = elem.get("Vector", False)

                    key.append(elem["Register"])
                    key.append(address_base)
                    key.append(address_index)
                    key.append(floating_point)
                    key.append(vector)

                    operand = OperandConstReg(
                        name, descr, reg, address_base, address_index,
                        floating_point, vector
                    )

                elif "Relative" in elem:

                    mindispl = elem["MinDisplacement"]
                    maxdispl = elem["MaxDisplacement"]
                    relative = elem["Relative"]
                    shift = elem.get("Shift", 0)
                    step = elem.get("Step", 1)
                    except_ranges = elem.get("ExceptRange", [])

                    key.append(mindispl)
                    key.append(maxdispl)
                    key.append(shift)
                    key.append(step)
                    key.append(tuple([tuple(elem) for elem in except_ranges]))

                    operand = InstructionAddressRelativeOperand(
                        name, descr, maxdispl, mindispl,
                        shift, except_ranges, relative, step)

                else:
                    raise MicroprobeArchitectureDefinitionError(
                        "Operand definition '%s' in '%s' not supported" %
                        (name, filename)
                    )

                tkey = tuple(key)
                if tkey in operands_duplicated:
                    LOG.warning(
                        "Similar definition of operands: '%s' and"
                        " '%s'. Check if definition needed.", name,
                        operands_duplicated[tkey]
                    )
                else:
                    operands_duplicated[tkey] = name

            except KeyError as exception:

                raise MicroprobeArchitectureDefinitionError(
                    "Definition"
                    " of operand '%s' "
                    "uses an unknown "
                    "register in '%s'"
                    "\nMissing defini"
                    "tion of: %s" % (
                        name, filename, exception
                    )
                )

            if name in operands and not override and filename not in inherits:
                raise MicroprobeArchitectureDefinitionError(
                    "Duplicated definition of operand '%s' found in '%s'" %
                    (name, filename)
                )

            if name in operands:
                LOG.debug("Redefined operand: %s", operand)

            LOG.debug(operand)
            operands[name] = operand

    LOG.debug("End")
    return operands


def _format_integer(operand, value):

    if MICROPROBE_RC['hex_all']:
        if hex(value).endswith("L"):
            return hex(value)[:-1]
        return hex(value)
    elif MICROPROBE_RC['hex_none']:
        return str(value)
    elif MICROPROBE_RC['hex_address']:
        if (operand.address_relative or
                operand.address_immediate or operand.address_absolute):
            if hex(value).endswith("L"):
                return hex(value)[:-1]
            return hex(value)
        else:
            return str(value)
    else:
        raise NotImplementedError


# Classes
class OperandDescriptor(object):
    """Class to represent an operand descriptor.

    """

    def __init__(self, mtype, is_input, is_output):
        """

        :param mtype:
        :param is_input:
        :param is_output:

        """
        self._type = mtype
        self._is_input = is_input
        self._is_output = is_output

    @property
    def type(self):
        """Type of the operand descriptor (:class:`~.Operand`)"""
        return self._type

    @property
    def is_input(self):
        """Is input flag (:class:`~.bool`) """
        return self._is_input

    @property
    def is_output(self):
        """Is output flag (:class:`~.bool`) """
        return self._is_output

    def set_type(self, new_type):
        """

        :param new_type:

        """
        self._type = new_type

    def copy(self):
        """Return a copy of the Operand descriptor.

        :rtype: :class:`~.OperandDescriptor`
        """
        return OperandDescriptor(self.type, self.is_input, self.is_output)

    def __repr__(self):
        """ """
        return "%s(%s, %s, %s)" % (
            self.__class__.__name__, self._type, self._is_input,
            self._is_output
        )


class MemoryOperandDescriptor(object):
    """Class to represent a memory operand descriptor.

    """

    def __init__(self, otype, io, bit_rate):
        """

        :param otype:
        :param io:
        :param bit_rate:

        """
        self._type = otype
        self._is_load = "I" in io
        self._is_store = "O" in io
        self._is_prefetch = "P" in io
        self._is_agen = "agen" in io
        self._is_branch_target = "B" in io
        self._bit_rate = bit_rate
        assert (self.is_load or self.is_store) ^ self.is_agen \
            ^ self.is_prefetch ^ self.is_branch_target

    @property
    def type(self):
        """Memory operand descriptor type (:class:`~.Operand`)"""
        return self._type

    @property
    def is_load(self):
        """Is load flag (:class:`~.bool`) """
        return self._is_load

    @property
    def is_store(self):
        """Is store flag (:class:`~.bool`) """
        return self._is_store

    @property
    def is_agen(self):
        """Is an address generator flag (:class:`~.bool`) """
        return self._is_agen

    @property
    def is_prefetch(self):
        """Is prefech flag (:class:`~.bool`) """
        return self._is_prefetch

    @property
    def is_branch_target(self):
        """Is a branch target (:class:`~.bool`) """
        return self._is_branch_target

    @property
    def bit_rate(self):
        """Memory operand bit rate (::class:`~.int`) """
        return self._bit_rate

    def __str__(self):
        """Return string representation.

        :rtype: :class:`~.str`
        """

        rstr = "%s(%s," % (self.__class__.__name__, self.type)
        if self.is_load:
            rstr = "%sload," % rstr
        if self.is_store:
            rstr = "%sstore," % rstr
        if self.is_prefetch:
            rstr = "%sprefetch," % rstr
        if self.is_agen:
            rstr = "%saddress_generator," % rstr
        if self.is_branch_target:
            rstr = "%sbranch_target," % rstr

        rstr = "%s)" % rstr
        return rstr

    def full_report(self, tabs=0):
        shift = ("\t" * (tabs + 1))
        # rstr = shift + "Type  : \n"
        rstr = self.type.full_report(tabs=tabs) + "\n"
        rstr += shift + "Load  : %s\n" % self.is_load
        rstr += shift + "Store  : %s\n" % self.is_store
        rstr += shift + "Prefetch  : %s\n" % self.is_prefetch
        rstr += shift + "Address generator  : %s\n" % self.is_agen
        rstr += shift + "Branch target  : %s" % self.is_branch_target
        return rstr


class MemoryOperand(object):
    """This represents a machine instruction memory operand. It contains
    the operands, the formula, the


    """

    _cmp_attributes = ["_address", "_length"]

    def __init__(self, address_formula, length_formula):
        """

        :param address_formula:
        :param length_formula:

        """
        self._address = address_formula
        self._length = length_formula

    @property
    def address_operands(self):
        """  """
        return self._address

    @property
    def length_operands(self):
        """ """
        return self._length

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

    def __str__(self):
        """ """
        return "%s(Address: %s, Length: %s)" % (
            self.__class__.__name__, self._address, self._length
        )

    def full_report(self, tabs=0):
        shift = ("\t" * (tabs + 1))
        rstr = shift + \
            "Address : %s\n" % list(self.address_operands.keys())
        rstr += shift + "Length : %s" % list(self.length_operands.keys())
        return rstr


class Operand(six.with_metaclass(abc.ABCMeta, object)):
    """This represents a machine instruction operand"""

    _cmp_attributes = [
        "_name",
        "_descr",
        "_ai",
        "_ab",
        "_aim",
        "_imm",
        "_const",
        "_rel",
        "_rela",
        "_fp",
        "_vector"]

    @abc.abstractmethod
    def __init__(self, name, descr):
        """

        :param name:
        :param descr:

        """
        self._name = name
        self._descr = descr
        self._ai = False
        self._ab = False
        self._aim = False
        self._imm = False
        self._const = False
        self._rel = False
        self._rela = False
        self._fp = False
        self._vector = False

    @property
    def name(self):
        """Operand name (:class:`~.str`)."""
        return self._name

    @property
    def description(self):
        """Operand description (:class:`~.str`)."""
        return self._descr

    @property
    def address_relative(self):
        """Operand is for generating relative addresses (:class:`~.bool`)."""
        return self._rel

    @property
    def address_absolute(self):
        """Operand is for generating absolute addresses (:class:`~.bool`)."""
        return self._rela

    @property
    def address_immediate(self):
        """Operand is an immediate of an address (:class:`~.bool`)."""
        return self._aim

    @property
    def float(self):
        """Operand is float (:class:`~.bool`)."""
        return self._fp

    @property
    def address_base(self):
        """Operand is the base register for an address (:class:`~.bool`)."""
        return self._ab

    @property
    def address_index(self):
        """Operand is the index register for an address (:class:`~.bool`)."""
        return self._ai

    @property
    def immediate(self):
        """Operand is immediate (:class:`~.bool`)."""
        return self._imm

    @property
    def vector(self):
        """Operand is vector (:class:`~.bool`)."""
        return self._vector

    @property
    def constant(self):
        """Operand is constant (:class:`~.bool`)."""
        return self._const

    @abc.abstractmethod
    def copy(self):
        """Return a copy of the operand. """
        raise NotImplementedError

    @abc.abstractmethod
    def values(self):
        """Return the possible value of the operand."""
        raise NotImplementedError

    @abc.abstractmethod
    def random_value(self):
        """Return a random possible value for the operand."""
        raise NotImplementedError

    @abc.abstractmethod
    def representation(self, value):
        """Return the string representation of the operand.

        :param value: value of the operand
        :type value: :class:`~.str`, :class:`~.Register` or
            :class:`int`
        :rtype: :class:`~.str`
        """
        raise NotImplementedError

    @abc.abstractmethod
    def codification(self, value):
        """Return the binary codification of the operand.

        :param value: value of the operand.
        :type value: :class:`~.str`, :class:`~.Register` or
            :class:`int`
        :rtype: :class:`~.str`
        """
        raise NotImplementedError

    @abc.abstractmethod
    def access(self, value):
        """

        :param value:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def set_valid_values(self, values):
        """Sets the set of valid value for the operand.

        :param value: value of the operand.
        :type value: :class:`list` of :class:`~.str`,
            :class:`~.Register` or :class:`int`
        """
        raise NotImplementedError

    @abc.abstractmethod
    def __contains__(self, value):
        """

        :param value:

        """
        raise NotImplementedError

    def check(self, value):
        """Check if a value is valid for the operand.

        :param value: value of the operand.
        :type value: :class:`~.str`, :class:`~.Register` or
            :class:`int`
        :raise microprobe.exceptions.MicroprobeValueError: if
            the value is not allowed for the operand
        """
        if not self.__contains__(value):
            raise MicroprobeValueError(
                "Invalid operand value %s not in %s" % (value,
                                                        list(self.values()))
            )

    def __str__(self):
        """ """
        return "%-8s : %s (%s)" % (
            self.name, self.description, self.__class__.__name__
        )

    def __repr__(self):
        """ """
        return "%s(\"%s\", \"%s\")" % (
            self.__class__.__name__, self.name, self.description
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

        if not isinstance(other, self.__class__):
            return False

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


class OperandReg(Operand):
    """Class to represent a register operand.

    """

    def __init__(
        self, name, descr, regs, address_base, address_index, floating_point,
        vector
    ):
        """

        :param name:
        :param descr:
        :param regs:
        :param address_base:
        :param address_index:
        :param floating_point:
        :param vector:

        """
        super(OperandReg, self).__init__(name, descr)

        if isinstance(regs, list):
            self._regs = OrderedDict()
            for reg in regs:
                self._regs[reg] = [reg]
        else:
            self._regs = regs

        self._ab = address_base
        self._ai = address_index
        self._fp = floating_point
        self._vector = vector

        if self._fp is None:
            self._fp = list(set([reg.type for reg in self._regs]))[
                0].used_for_float_arithmetic

        if self._vector is None:
            self._vector = list(set([reg.type for reg in self._regs]))[
                0].used_for_vector_arithmetic

    def values(self):
        """Return the possible value of the operand.

        :rtype: :class:`list` of :class:`~.Register`
        """
        return list(self._regs.keys())

    def representation(self, value):
        """

        :param value:

        """
        return value.representation

    def codification(self, value):
        """

        :param value:

        """
        return value.codification

    def random_value(self):
        """Return a random possible value for the operand.

        :rtype: :class:`~.Register`
        """
        return list(self._regs.keys())[random.randrange(0, len(self._regs))]

    def access(self, value):
        """

        :param value:

        """
        return self._regs[value]

    def __contains__(self, value):
        """

        :param value:

        """

        if not isinstance(value, Register):
            return False

        return value.name in [reg.name for reg in self.values()]

    def copy(self):
        """ """

        return OperandReg(
            self.name, self.description, self._regs.copy(), self._ab, self._ai,
            self._fp, self._vector
        )

    def set_valid_values(self, values):
        """

        :param values:

        """

        assert len(values) > 0

        for value in self.values():

            if value not in values:
                del self._regs[value]

        assert sorted(self.values()) == sorted(values), \
            "\nValues: %s \nValues(): %s" % (sorted(values),
                                             sorted(self.values()))

        self._const = len(values) == 1


class OperandImmRange(Operand):
    """Class to represent a immediate range operand.

    """

    def __init__(
        self, name, descr, minvalue, maxvalue, step, aim, shift, novalues, add
    ):
        """

        :param name:
        :param descr:
        :param minvalue:
        :param maxvalue:
        :param step:
        :param aim:
        :param shift:
        :param novalues:
        :param add:

        """
        super(OperandImmRange, self).__init__(name, descr)
        self._min = minvalue
        self._max = maxvalue
        self._step = step
        self._aim = aim  # Address Immediate?
        self._shift = shift
        self._imm = True
        self._novalues = novalues
        self._add = add
        self._computed_values = None

    def copy(self):
        """ """
        return OperandImmRange(
            self.name, self.description, self._min, self._max, self._step,
            self._aim, self._shift, self._novalues, self._add
        )

    def values(self):
        """Return the possible value of the operand.

        :rtype: list of ::class:`~.int`
        """
        if self._computed_values is None:
            self._computed_values = [
                elem
                for elem in range(
                    self._min, self._max + 1, self._step
                ) if elem not in self._novalues
            ]
        return self._computed_values

    def set_valid_values(self, values):
        """

        :param values:

        """
        if len(values) == 0:
            raise MicroprobeCodeGenerationError(
                "Setting an operand without any valid value. Please check "
                "the definition files. Previous value: '%s'. New values: '%s'"
                "." % (list(self.values()), values)
            )

        for value in values:
            assert value in list(self.values())

        self._computed_values = values
        self._const = len(values) == 1

    def random_value(self):
        """Return a random possible value for the operand.

        :rtype: ::class:`~.int`
        """
        if self._computed_values is not None:
            return self._computed_values[
                random.randrange(
                    0, len(
                        self._computed_values
                    )
                )
            ]

        value = random.randrange(
            self._min, self._max + 1, self._step
        )

        if value not in self._novalues:
            return value
        else:
            return self.random_value()

    def representation(self, value):
        """

        :param value:

        """
        # Immediate displacements sometimes contain
        # variable names instead of a number
        if isinstance(value, str):
            # print value
            return value

        # return _format_integer(self, (value >> self._shift) + self._add)
        return _format_integer(self, value + self._add)

    def codification(self, value):
        """

        :param value:

        """
        return str(value >> self._shift)

    @property
    def max(self):
        """ """
        return self._max

    @property
    def min(self):
        """ """
        return self._min

    @property
    def step(self):
        """ """
        return self._step

    @property
    def shift(self):
        """ """
        return self._shift

    @property
    def add(self):
        """ """
        return self._add

    def check(self, value):
        """

        :param value:

        """

        if not isinstance(value, six.integer_types):
            raise MicroprobeValueError(
                "Invalid operand value: '%s'. Integer"
                " required and '%s' provided" % (value, type(value))
            )

        # value = value >> self._shift
        if value <= self._max and value >= self._min \
                and (value - self._min) % self._step == 0 \
                and value not in self._novalues:

            return True

        else:

            raise MicroprobeValueError(
                "Invalid operand value: %d (max: %d,"
                " min: %d)" % (
                    value, self._max, self._min
                )
            )

    def access(self, dummy):
        """

        :param dummy:

        """
        return []

    def __contains__(self, value):
        """

        :param value:

        """
        raise NotImplementedError


class OperandValueSet(Operand):
    """Class to represent a value set operand.

    """

    def __init__(self, name, descr, values, rep):
        """

        :param name:
        :param descr:
        :param values:

        """
        super(OperandValueSet, self).__init__(name, descr)
        # TODO: add input value checking
        self._values = values
        self._imm = True
        self._rep = None
        if rep is not None and len(rep) != len(values):
            raise MicroprobeArchitectureDefinitionError(
                "Values and representation of operand definition "
                "'%s' do not have the same length." % name
            )
        if rep is not None:
            self._rep = dict(zip(values, rep))

    def copy(self):
        """ """
        return OperandValueSet(
            self.name,
            self.description,
            self._values,
            self._rep
        )

    def values(self):
        """Return the possible value of the operand.

        :rtype: list of ::class:`~.int`
        """
        return self._values

    def representation(self, value):
        """

        :param value:

        """
        if self._rep is None:
            return _format_integer(self, value)
        return self._rep[value]

    def codification(self, value):
        """

        :param value:

        """
        return str(value)

    def random_value(self):
        """Return a random possible value for the operand.

        :rtype: ::class:`~.int`
        """
        return self._values[random.randrange(0, len(self._values))]

    def access(self, dummy):
        """

        :param dummy:

        """
        return []

    @property
    def shift(self):
        """ """
        return 0

    @property
    def min(self):
        """ """
        return min(self._values)

    def __contains__(self, value):
        """

        :param value:

        """
        return value in list(self.values())

    def set_valid_values(self, values):
        """

        :param values:

        """
        assert len(values) > 0
        for value in values:
            assert value in list(self.values())

        self._values = values
        self._const = len(values) == 1


class OperandConst(Operand):
    """Class to represent a constant operand.

    """

    def __init__(self, name, descr, value, aim=False, arel=False):
        """

        :param name:
        :param descr:
        :param value:

        """
        super(OperandConst, self).__init__(name, descr)
        self._value = value
        self._imm = True
        self._aim = aim
        self._rel = arel
        self._const = True

    def copy(self):
        """ """
        return OperandConst(self.name, self.description, self._value)

    def values(self):
        """Return the possible value of the operand.

        :rtype: list of ::class:`~.int`
        """
        return [self._value]

    def representation(self, value):
        """

        :param value:

        """
        return _format_integer(self, value)

    def codification(self, value):
        """

        :param value:

        """
        return str(value)

    def random_value(self):
        """Return a random possible value for the operand.

        :rtype: ::class:`~.int`
        """
        return self._value

    @property
    def shift(self):
        """ """
        return 0

    @property
    def min(self):
        """ """
        return self._value

    def access(self, dummy):
        """

        :param dummy:

        """
        return []

    def __contains__(self, value):
        """

        :param value:

        """
        return value in list(self.values())

    def set_valid_values(self, values):
        """

        :param values:

        """
        assert len(values) == 1
        for value in values:
            assert value in list(self.values())

        self._value = values[0]


class OperandConstReg(Operand):
    """Class to represent a constant register operand.

    """

    def __init__(
        self, name, descr, reg, address_base, address_index, floating_point,
        vector
    ):
        """

        :param name:
        :param descr:
        :param reg:
        :param address_base:
        :param address_index:
        :param floating_point:
        :param vector:

        """
        super(OperandConstReg, self).__init__(name, descr)
        self._reg = reg
        self._regs = [reg]
        self._const = True

        self._ab = address_base
        self._ai = address_index
        self._fp = floating_point
        self._vector = vector

        if self._fp is None:
            self._fp = list(set([reg.type for reg in self._regs]))[
                0].used_for_float_arithmetic

        if self._vector is None:
            self._vector = list(set([reg.type for reg in self._regs]))[
                0].used_for_float_arithmetic

    def copy(self):
        """ """
        return OperandConstReg(
            self.name, self.description, self._reg, self._ab, self._ai,
            self._fp, self._vector
        )

    def values(self):
        """Return the possible value of the operand.

        :rtype: list of :class:`~.Register`
        """
        return [self._reg]

    def random_value(self):
        """Return a random possible value for the operand.

        :rtype: :class:`~.Register`
        """
        return self._reg

    def representation(self, value):
        """

        :param value:

        """
        return value.representation

    def codification(self, value):
        """

        :param value:

        """
        return value.codification

    def access(self, value):
        """

        :param value:

        """
        return [value]

    def __contains__(self, value):
        """

        :param value:

        """
        if not isinstance(value, Register):
            return False

        return value.name in [reg.name for reg in self.values()]

    def set_valid_values(self, values):
        """

        :param values:

        """
        assert len(values) == 1
        for value in values:
            assert value in list(self.values())

        self._reg = values[0]


class InstructionAddressRelativeOperand(Operand):
    """Class to represent a relative instruction address operand.

    Relative instruction address operands are used for immediates operands
    used to compute relative distance between the current instruction
    and the target. Examples are : branch relative, or load address relative.
    """

    def __init__(
            self,
            name,
            descr,
            maxdispl,
            mindispl,
            shift,
            except_range,
            relative,
            step):
        """Create a InstructionAddressRelativeOperand object.

        :param name: Operand name
        :type name: :class:`~.str`
        :param descr: Operand description
        :type descr: :class:`~.str`
        :param maxdispl: Maximum displacement allowed
        :type maxdispl: ::class:`~.int`
        :param mindispl: Minimum displacement allowed
        :type mindispl: ::class:`~.int`
        :param shift: Number of shifted bits
        :type shift: ::class:`~.int`
        :param except_range: list of forbidden ranges for displacement. Ranges
            are represented using (lower_bound, upper_bound)
        :type except_range: :class:`~.list` of \
            :func:`tuple` with :class:`~.int`
        :rtype: :class:`~.InstructionAddressRelativeOperand`

        """
        super(InstructionAddressRelativeOperand, self).__init__(name, descr)
        self._maxdispl = maxdispl
        self._mindispl = mindispl
        self._rel = relative
        self._rela = not relative
        self._shift = shift
        self._except = except_range
        self._step = step

    def copy(self):
        """ """
        return InstructionAddressRelativeOperand(
            self.name, self.description, self._maxdispl, self._mindispl,
            self._shift, self._except, self._rel, self._step
        )

    def values(self):
        """Return the possible value of the operand.

        :rtype: list of ::class:`~.int`
        """
        return [self._mindispl << self._shift]

    def random_value(self):
        """Return a random possible value for the operand.

        :rtype: ::class:`~.int`
        """
        value = random.randrange(self._mindispl, self._maxdispl) << self._shift

        if value <= (self._maxdispl << self._shift) and \
           value >= (self._mindispl << self._shift) and \
           not self._in_except_ranges(value) and \
           value % self._step == 0:
            return value
        else:
            return self.random_value()

        return value

    def representation(self, value):
        """

        :param value:

        """
        assert isinstance(value, tuple(list(six.integer_types) + [Address]))
        if isinstance(value, six.integer_types):
            # print(value, self._shift)
            # assert value % (self._shift + 1) == 0
            return _format_integer(self, value)
        else:
            base_address = value.base_address
            displacement = value.displacement

            if isinstance(base_address, Variable):
                str_value = base_address.name
            elif isinstance(base_address, str):
                str_value = base_address
            else:
                raise MicroprobeCodeGenerationError(
                    "Unable to generate the string representation of '%s'"
                    " with value: '%s'" % (self, value)
                )

            if displacement > 0:
                str_value = "%s+0x%x" % (str_value, displacement)
            elif displacement < 0:
                str_value = "%s-0x%x" % (str_value, abs(displacement))

            return str_value

    def _in_except_ranges(self, value):
        """

        :param value:

        """
        for irange in self._except:
            if value >= (irange[0] << self._shift) \
                    and value <= (irange[1] << self._shift):
                return True
        return False

    def check(self, value):
        """

        :param value:

        """

        if isinstance(value, six.integer_types):
            cvalue = value
        elif isinstance(value, Address):
            # Warning!
            return
        else:
            if not isinstance(value[0], Address) or \
                    not isinstance(value[1], Address):
                raise MicroprobeValueError(
                    "Invalid operand value '%s'."
                    " Any Address?" % (value)
                )
            cvalue = value[0] - value[1]

        if cvalue > (self._maxdispl << self._shift) or \
           cvalue < (self._mindispl << self._shift) or \
           self._in_except_ranges(cvalue) or \
           cvalue % self._step != 0:
            raise MicroprobeValueError(
                "Invalid operand value '%d' "
                "not within the"
                " allowed range (%d, %d) and exceptions"
                " '%s' " % (
                    cvalue, self._mindispl, self._maxdispl, self._except
                )
            )

    def codification(self, value):
        """

        :param value:

        """

        if isinstance(value, six.integer_types):
            return str(value >> self._shift)
        elif isinstance(value, Address):
            raise MicroprobeCodeGenerationError(
                "Unable to codify the"
                " symbolic address: %s ."
                " Consider to add a pass to"
                " translate them to actual "
                "values " % value
            )
        else:
            raise NotImplementedError

    @property
    def shift(self):
        """ """
        return self._shift

    def access(self, dummy):
        """

        :param dummy:

        """
        return []

    def set_valid_values(self, values):
        """

        :param values:

        """
        raise NotImplementedError

    def __contains__(self, value):
        """

        :param value:

        """
        raise NotImplementedError

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
""":mod:`microprobe.target.isa.instruction_format` module

"""

# Futures
from __future__ import absolute_import, division, annotations

# Built-in modules
import abc
import os
from typing import TYPE_CHECKING, List, Tuple

# Third party modules

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError, \
    MicroprobeLookupError
from microprobe.utils.logger import get_logger
from microprobe.utils.typeguard_decorator import typeguard_testsuite
from microprobe.utils.yaml import read_yaml

# Type hinting
if TYPE_CHECKING:
    from microprobe.target.isa.instruction_field import InstructionField

# Constants
SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas",
                      "instruction_format.yaml")
LOG = get_logger(__name__)
__all__ = [
    "import_definition", "InstructionFormat", "GenericInstructionFormat"
]


# Functions
@typeguard_testsuite
def import_definition(cls, filenames, ifields):
    """

    :param filenames:
    :param ifields:

    """

    LOG.debug("Start")
    iformats = {}
    iformats_duplicated = {}

    for filename in filenames:
        iformat_data = read_yaml(filename, SCHEMA)

        if iformat_data is None:
            continue

        for elem in iformat_data:
            name = elem["Name"]
            descr = elem.get("Description", "No description")
            assembly = elem["Assembly"]

            # TODO: Document the convention
            nonzero_fields = [
                field for field in elem["Fields"] if not field.startswith("0_")
            ]

            key = tuple([tuple(elem["Fields"]), assembly])

            if key in iformats_duplicated:
                LOG.warning(
                    "Similar definition of instruction format: '%s' "
                    "and '%s'. Check if definition needed.", name,
                    iformats_duplicated[key])
            else:
                iformats_duplicated[key] = name

            if len(nonzero_fields) != len(set(nonzero_fields)):

                raise MicroprobeArchitectureDefinitionError(
                    f"Definition of instruction format '{name}' found in "
                    f"'{filename}' contains duplicated fields.")

            try:
                fields = [ifields[ifieldname] for ifieldname in elem["Fields"]]
            except KeyError as key:
                raise MicroprobeArchitectureDefinitionError(
                    f"Unknown field {key} definition in instruction format "
                    f"'{name}' found in '{filename}'.")

            iformat = cls(name, descr, fields, assembly)

            if name in iformats:
                raise MicroprobeArchitectureDefinitionError(
                    f"Duplicated definition of instruction format '{name}' "
                    f"found in '{filename}'")
            LOG.debug(iformat)
            iformats[name] = iformat

    LOG.debug("End")
    return iformats


# Classes
@typeguard_testsuite
class InstructionFormat(abc.ABC):
    """Abstract class to represent an instruction format"""

    @abc.abstractmethod
    def __init__(self, fname: str, descr: str):
        """

        :param fname:
        :param descr:

        """
        self._name = fname
        self._descr = descr

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._descr

    @property
    @abc.abstractmethod
    def fields(self) -> List[InstructionField]:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def assembly_format(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_operands(self):
        """Returns a :class:`~.list` of :func:`tuple` of three elements.
        The first is a :class:`~.Operand` object, the second is a
        :class:`~.bool` indicating if the operand is an input operand and the
        third is a :class:`~.bool` indicating if the operand is an output
        operand.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_fields(self) -> List[InstructionField]:
        """Returns a :class:`~.list` of
        the :class:`~.InstructionField`


        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_field(self, fname: str) -> InstructionField:
        """Returns a the :class:`~.InstructionField` with name
        *fname*.

        :param fname:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_field_props(self, fname: str):
        """Returns extra properties of field with name *fname*.

        :param fname: Field name.
        :type fname: :class:`~.str`

        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_findex(self, fname: str):
        """Returns the index of the field *fname* within the instruction format

        :param fname: Field name.
        :type fname: :class:`~.str`

        """
        raise NotImplementedError

    @abc.abstractmethod
    def flip_fields(self, fname1: str, fname2: str):
        """Interchanges the position of the fields with name *fname1* and
        *fname2*.

        :param fname1: Field 1 name.
        :type fname1: :class:`~.str`
        :param fname2: Field 2 name.
        :type fname2: :class:`~.str`.

        """
        raise NotImplementedError

    @abc.abstractmethod
    def set_fields(self, fields: List[InstructionField], reset: bool = True):
        """Sets the fields of the instruction format. If *reset* is *True* the
        properties and the flip records of the fields are removed.

        :param fields: List of fields.
        :type fields: :class:`~.list` of
                      :class:`~.InstructionField`
        :param reset: Flag indicating if a full reset is needed
                      (Default value = True)
        :type reset: :class:`~.bool`
        """
        raise NotImplementedError

    def __str__(self):

        values = "%-10s : %-30s ([" % (self.name, self.description)

        fields = []
        for field in self.fields:
            fmt = "{0:^%d}" % (field.size + (field.size - 4) // 4)
            fields.append(fmt.format(field.name))

        values = "%s%s])" % (values, "|".join(fields))
        return values

    def full_report(self, tabs=0):

        rstr = "\t" * tabs + str(self)
        rstr += "\n"
        rstr += "\t" * tabs + "%-10s : %-30s\n" % ("Assembly",
                                                   self.assembly_format)
        for field in self.fields:
            rstr += "\t" * tabs + \
                "Fieldname  : %s (bitsize: %d)\n" % (field.name, field.size)

        return rstr


@typeguard_testsuite
class GenericInstructionFormat(InstructionFormat):
    """Instruction format generic class."""

    def __init__(self, fname: str, descr: str, fields: List[InstructionField],
                 assembly: str):
        """

        :param fname:
        :param descr:
        :param fields:
        :param assembly:

        """
        super(GenericInstructionFormat, self).__init__(fname, descr)
        self._fname = fname
        self._fields: List[InstructionField] = []
        self._props: List[None] = [
        ]  # TODO: Check if this list of None is needed
        self._flips: List[Tuple[int, int]] = []
        self._length = 0
        self._assembly_format = assembly

        for field in fields:
            self._add_field(field)

        self._compute_length()

    @property
    def fields(self):
        return self._fields

    @property
    def length(self):
        return self._length

    @property
    def assembly_format(self):
        return self._assembly_format

    def get_operands(self):
        """Returns a :class:`~.list` of :func:`tuple` of three elements.
        The first is a :class:`~.Operand` object, the second is a
        :class:`~.bool` indicating if the operand is an input operand and the
        third is a :class:`~.bool` indicating if the operand is an output
        operand.
        """
        return [(field.get_foperand(), field.is_input(), field.is_output())
                for field in self.get_fields() if field.get_fshow()]

    def get_fields(self):
        """Returns a :class:`~.list` of the
        :class:`~.InstructionField`


        """
        return self._fields

    def get_field(self, fname: str):
        """Returns a the :class:`~.InstructionField` with name
        *fname*.

        :param fname:

        """
        field = [
            field for field in self.get_fields() if field.get_fname() == fname
        ]

        if len(field) == 0:
            raise MicroprobeLookupError(
                f"Unable to find a field with name '{fname}'")

        assert len(
            field
        ) == 1, "Field names should be key identifiers." + \
            f" Field '{fname}' is duplicated"

        return field[0]

    def get_field_props(self, fname: str):
        """Returns extra properties of field with name *fname*.

        :param fname: Field name.
        :type fname: :class:`~.str`

        """
        idx = self.get_findex(fname)
        return self._props[idx]

    def get_findex(self, fname: str):
        """Returns the index of the field *fname* within the instruction
        format.

        :param fname: Field name.
        :type fname: :class:`~.str`

        """
        return self.get_fields().index(self.get_field(fname))

    def flip_fields(self, fname1: str, fname2: str):
        """Interchanges the position of the fields with name *fname1* and
        *fname2*.

        :param fname1: Field 1 name.
        :type fname1: :class:`~.str`
        :param fname2: Field 2 name.
        :type fname2: :class:`~.str`.

        """

        idx1 = self.get_findex(fname1)
        idx2 = self.get_findex(fname2)

        fields = self.get_fields()
        tmp_field = fields[idx1]
        fields[idx1] = fields[idx2]
        fields[idx2] = tmp_field
        self.set_fields(fields, reset=False)

        tmp_prop = self._props[idx1]
        self._props[idx1] = self._props[idx2]
        self._props[idx2] = tmp_prop

        self._flips.append((idx1, idx2))

    def set_fields(self, fields: List[InstructionField], reset: bool = True):
        """Sets the fields of the instruction format. If *reset* is *True* the
        properties and the flip records of the fields are removed.

        :param fields: List of fields.
        :type fields: :class:`~.list` of
              :class:`~.InstructionField`
        :param reset: Flag indicating if a full reset is needed
                      (Default value = True)
        :type reset: :class:`~.bool`

        """
        self._fields = fields
        if reset:
            self._props = [None] * len(self.get_fields())
            self._flips = []

        self._compute_length()

    def _add_field(self, field: InstructionField):
        """Adds an field to the instruction format.

        :param field: Instruction field
        :type field: :class:`~.InstructionField`

        """
        self._fields.append(field)
        self._props.append(None)

    def _compute_length(self):

        length = sum([field.size for field in self._fields])
        if length % 8 != 0:

            LOG.error("%s", self)
            LOG.error("\tTotal length: %d", length)

            for field in self._fields:
                LOG.error("\t\t - %s: %d", field.name, field.size)

            raise MicroprobeArchitectureDefinitionError(
                "Instruction format"
                " '%s' length is not multiple of a byte" % self.name)

        self._length = sum([field.size for field in self._fields]) // 8

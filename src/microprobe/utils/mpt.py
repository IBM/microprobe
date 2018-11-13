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
""":mod:`microprobe.utils.mpt` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc
import ast
import io
import os
import re

# Third party modules
import six.moves.configparser
from six.moves import range

# Own modules
from microprobe.code.var import VariableSingle
from microprobe.exceptions import MicroprobeDuplicatedValueError, \
    MicroprobeMPTFormatError, MicroprobeValueError
from microprobe.utils.asm import MicroprobeAsmInstructionDefinition
from microprobe.utils.imp import get_all_subclasses
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RNDFP, RNDINT, \
    OrderedDict, Progress, RejectingOrderedDict, open_generic_fd


# Constants
LOG = get_logger(__name__)
__all__ = [
    "MicroprobeTestVariableDefinition",
    "MicroprobeTestRegisterDefinition",
    "MicroprobeTestMemoryAccessDefinition",
    # "MicroprobeTestRawDefinition",
    "MicroprobeTestDefinition",
    "MicroprobeTestDefinitionDefault",
    "MicroprobeTestDefinitionV0x5",
    "MicroprobeTestParser",
    "MicroprobeTestParserDefault",
    "MicroprobeTestParserV0x5",
    "mpt_configuration_factory",
    "mpt_parser_factory",
    "mpt_shift",
    "variable_to_test_definition"
]


# Functions
def _normalize_variable(definition):

    definition = definition.upper()
    definition = definition.strip()
    definition = definition.replace('\t', ' ')
    definition = re.sub(r'\( +', r'(', definition)
    definition = re.sub(r' +\)', r')', definition)
    definition = re.sub(r' +\(', r'(', definition)
    definition = re.sub(r'\) +', r')', definition)
    definition = re.sub(r'\[ +', r'[ ', definition)
    definition = re.sub(r' +\]', r' ]', definition)
    definition = re.sub(r' +\[', r'[ ', definition)
    definition = re.sub(r'\] +', r' ]', definition)
    definition = re.sub(r',', r', ', definition)
    definition = re.sub(r' +', r' ', definition)
    definition = definition.replace(' NONE,', ' None,')
    definition = definition.replace(' NONE ]', ' None ]')
    definition = re.sub(", [0]+([0-9])", ", \\1", definition)

    return definition


def _parse_raw(name, value):
    name = name.upper()
    value = value.replace("\t", " ")
    return (name, value)


def _parse_literal(name, value):
    name = name.upper()
    value = value.replace("\t", " ")
    return (name, ast.literal_eval(value))


def _parse_value(value):
    value = value.replace("\t", " ")
    value = ast.literal_eval(value)
    return value


def _parse_decorators(contents):
    contents = contents.replace("\t", " ")
    return contents.strip() + ' '


def mpt_configuration_factory(version=None):
    if version is None:
        return MicroprobeTestDefinitionDefault()
    elif version is '0.5':
        return MicroprobeTestDefinitionV0x5()
    else:
        raise MicroprobeValueError(
            "Unknown MPT version '%s' requested" % version
        )


def mpt_parser_factory(version=None):
    if version is None:
        return MicroprobeTestParserDefault()
    elif version is '0.5':
        return MicroprobeTestParserV0x5()
    else:
        raise MicroprobeValueError(
            "Unknown MPT version '%s' requested" % version
        )


def mpt_shift(definition, start, end, shift):

    addresses = [elem.address for elem in definition.code]
    addresses += [elem.address for elem in definition.variables]
    addresses += [definition.default_code_address]
    addresses += [definition.default_data_address]
    addresses = [addr for addr in addresses if addr is not None]

    if not [elem for elem in addresses if elem >= start and elem <= end]:
        LOG.debug("Shift not needed")
        return

    addresses = []

    for instruction in definition.code:
        if instruction.address is not None:
            addresses.append(instruction.address)
            instruction.address = instruction.address + shift

    for variable in definition.variables:
        if variable.address is not None:
            addresses.append(variable.address)
            variable.address = variable.address + shift

    if definition.default_code_address is not None:
        addresses.append(definition.default_code_address)
        definition.set_default_code_address(
            definition.default_code_address + shift)

    if definition.default_data_address is not None:
        addresses.append(definition.default_data_address)
        definition.set_default_data_address(
            definition.default_data_address + shift)

    maxf = 0
    found = False
    while not found:
        mask = "F" * maxf + "0" * (16 - maxf)
        mask = int(mask, 16)
        paddress = set([elem & mask for elem in addresses])
        if 0 not in paddress:
            found = True
            addresses = paddress
            break
        maxf = maxf + 1

    for register in definition.registers:
        if register.value is not 0:
            if register.value & mask in addresses:
                register.value = register.value + shift

    for variable in definition.variables:
        if variable.var_type is not "uint8_t":
            continue

        for idx in range(0, variable.num_elements, 8):
            idx_st = idx
            idx_end = idx + 8
            val = "".join(["%02x" % elem
                           for elem in variable.init_value[idx_st:idx_end]])
            val = int("0x" + val, 16)
            if val == 0:
                continue

            if val & mask in addresses:
                newval = val + shift
                valstr = "%016x" % newval
                for elem in range(0, 8):
                    valsstr = valstr[2 * elem:2 * (elem + 1)]
                    variable.init_value[idx_st + elem] = int(valsstr, 16)


def variable_to_test_definition(variable):

    if isinstance(variable, VariableSingle):
        return MicroprobeTestVariableDefinition(
            variable.name, variable.type, 1, variable.address, variable.align,
            variable.value
        )
    else:
        return MicroprobeTestVariableDefinition(
            variable.name, variable.type, variable.elems, variable.address,
            variable.align, variable.value
        )


# Classes
class MicroprobeTestVariableDefinition(object):
    def __init__(
            self,
            name,
            var_type,
            num_elements,
            address,
            alignment,
            init_value):
        self.name = name
        self.var_type = var_type
        self.num_elements = num_elements
        self.address = address
        self.alignment = alignment
        self.init_value = init_value

    def __iter__(self):
        yield self.name
        yield self.var_type
        yield self.num_elements
        yield self.address
        yield self.alignment
        yield self.init_value


class MicroprobeTestRegisterDefinition(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value


class MicroprobeTestMemoryAccessDefinition(object):
    def __init__(self, dtype, rw, address, length):
        self.data_type = dtype
        self.access_type = rw
        self.address = address
        self.length = length
        assert isinstance(length, int)

    def to_str(self):
        return "%s %s 0X%016X %03d" % (self.data_type, self.access_type,
                                       self.address, self.length)

    def __str__(self):
        return "MemoryAccess(%s, %s, 0X%016X, %03d" % (
            self.data_type, self.access_type, self.address, self.length)


class MicroprobeTestDefinition(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract class to represent a Microprobe Test configuration."""

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def default_data_address(self):
        """Default data section address (::class:`~.int` )."""
        raise NotImplementedError

    @abc.abstractproperty
    def default_code_address(self):
        """Default code section address (::class:`~.int` )."""
        raise NotImplementedError

    @abc.abstractproperty
    def variables(self):
        """List of declared variables (:class:`~.list` of
        :class:`~.MicroprobeTestVariableDefinition`) """
        raise NotImplementedError

    @abc.abstractproperty
    def code(self):
        """List of declared variables (:class:`~.list` of
           :class:`~.MicroprobeInstructionDefinition`)"""
        raise NotImplementedError

    @abc.abstractproperty
    def registers(self):
        """List of declared variables (:class:`~.list` of
           :class:`~.MicroprobeTestRegisterDefinition`)"""
        raise NotImplementedError

    @abc.abstractproperty
    def raw(self):
        """List of declared raw definition (:class:`~.list` of
           :class:`~.str`)"""
        raise NotImplementedError

    @abc.abstractproperty
    def dat_mappings(self):
        raise NotImplementedError

    @abc.abstractproperty
    def dat_properties(self):
        raise NotImplementedError

    @abc.abstractproperty
    def roi_ins(self):
        raise NotImplementedError

    @abc.abstractproperty
    def roi_cyc(self):
        raise NotImplementedError

    @abc.abstractproperty
    def roi_memory_access_trace(self):
        raise NotImplementedError

    @abc.abstractproperty
    def instruction_count(self):
        raise NotImplementedError

    @abc.abstractproperty
    def cycle_count(self):
        raise NotImplementedError

    @abc.abstractmethod
    def set_default_code_address(self, value):
        """Set the default code address to value"""
        raise NotImplementedError

    @abc.abstractmethod
    def set_default_data_address(self, value):
        """Set the default code address to value"""
        raise NotImplementedError

    @abc.abstractmethod
    def register_variable_definition(self, definition):
        """Register a new variable definition."""
        raise NotImplementedError

    @abc.abstractmethod
    def register_register_definition(self, definition):
        """Register a new register definition."""
        raise NotImplementedError

    @abc.abstractmethod
    def register_instruction_definitions(self, definitions):
        """Register new instruction definitions."""
        raise NotImplementedError

    @abc.abstractmethod
    def register_raw_definition(self, name, value):
        """Register new raw definition."""
        raise NotImplementedError

    @abc.abstractmethod
    def register_dat_mapping(self, mapping):
        """Register new DAT mapping."""
        raise NotImplementedError

    @abc.abstractmethod
    def register_dat_property(self, prop, value):
        """Register new DAT property."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_roi_ins(self, value):
        """Set region of interest (in instruction)"""
        raise NotImplementedError

    @abc.abstractmethod
    def set_roi_cyc(self, value):
        """Set region of interest (in cycles)"""
        raise NotImplementedError

    @abc.abstractmethod
    def set_roi_memory_access_trace(self, value):
        """Set memory access trace"""
        raise NotImplementedError

    @abc.abstractmethod
    def set_instruction_count(self, value):
        """Set instruction count"""
        raise NotImplementedError

    @abc.abstractmethod
    def set_cycle_count(self, value):
        """Set cycle count"""
        raise NotImplementedError


class MicroprobeTestDefinitionDefault(MicroprobeTestDefinition):
    """Class to represent a Microprobe Test configuration (default impl.)"""
    version = 0

    def __init__(self):

        super(MicroprobeTestDefinitionDefault, self).__init__()
        self._default_code_address = None
        self._default_data_address = None
        self._code = []
        self._variables = []
        self._registers = []
        self._raw = {}
        self._dat = []
        self._dat_prop = RejectingOrderedDict()
        self._roi_cyc = None
        self._roi_ins = None
        self._roi_memory_access_trace = []
        self._instruction_count = None
        self._cycle_count = None

    @property
    def default_data_address(self):
        """Default data section address (::class:`~.int` )."""
        return self._default_data_address

    @property
    def default_code_address(self):
        """Default code section address (::class:`~.int` )."""
        return self._default_code_address

    @property
    def variables(self):
        """List of declared variables (:class:`~.list` of
        :class:`~.MicroprobeTestVariableDefinition`) """
        return self._variables

    @property
    def code(self):
        """List of declared variables (:class:`~.list` of
           :class:`~.MicroprobeInstructionDefinition`)"""
        return self._code

    @property
    def registers(self):
        """List of declared variables (:class:`~.list` of
           :class:`~.MicroprobeTestRegisterDefinition`)"""
        return self._registers

    @property
    def raw(self):
        return self._raw

    @property
    def dat_mappings(self):
        return self._dat

    @property
    def dat_properties(self):
        return self._dat_prop

    @property
    def roi_ins(self):
        return self._roi_ins

    @property
    def roi_cyc(self):
        return self._roi_cyc

    @property
    def roi_memory_access_trace(self):
        return self._roi_memory_access_trace

    @property
    def instruction_count(self):
        return self._instruction_count

    @property
    def cycle_count(self):
        return self._cycle_count

    def set_default_code_address(self, value):
        """Set the default code address to value"""
        self._default_code_address = value

    def set_default_data_address(self, value):
        """Set the default code address to value"""
        self._default_data_address = value

    def register_variable_definition(self, definition):
        """Register a new variable definition."""
        self._variables.append(definition)

    def register_register_definition(self, definition):
        """Register a new register definition."""
        self._registers.append(definition)

    def register_instruction_definitions(self, definitions, prepend=False):
        """Register new instruction definitions."""

        if prepend:
            self._code = definitions + self._code
        else:
            self._code += definitions

    def register_raw_definition(self, name, value):
        """Register a new raw definition."""
        self._raw[name] = self._raw.get(name, '') + value

    def register_dat_mapping(self, definition):
        """Register a new DAT mapping."""
        if isinstance(definition, list):
            self._dat += definition[:]
        else:
            self._dat.append(definition)

    def register_dat_property(self, prop, value):
        """Register a new DAT property."""
        try:
            self._dat_prop[prop] = value
        except MicroprobeDuplicatedValueError:
            raise MicroprobeMPTFormatError(
                "DAT property '%s' specified twice" % prop
            )

    def set_roi_ins(self, value):
        """Set region of interest (in instruction)"""

        if (value[0] >= value[1]):
            raise MicroprobeMPTFormatError(
                "Empty instruction region of interest range specified "
                "'%s'" % value
            )

        self._roi_ins = value

    def set_roi_memory_access_trace(self, trace):
        """Set memory access trace"""

        if not trace:
            raise MicroprobeMPTFormatError(
                "Empty memory access trace"
            )

        self._roi_memory_access_trace = trace

    def set_roi_cyc(self, value):
        """Set region of interest (in cycles)"""

        if (value[0] >= value[1]):
            raise MicroprobeMPTFormatError(
                "Empty cycle region of interest range specified "
                "'%s'" % list(value)
            )

        self._roi_cyc = value

    def set_instruction_count(self, value):
        """Set instruction count"""
        self._instruction_count = value

    def set_cycle_count(self, value):
        """Set cycle count"""
        self._cycle_count = value


class MicroprobeTestDefinitionV0x5(MicroprobeTestDefinitionDefault):
    """Class to represent a Microprobe Test configuration (v0.5)"""
    version = 0.5


class MicroprobeTestParser(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract class to represent a Microprobe Test configuration parser."""

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractmethod
    def parse_filename(self, filename):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def parse_contents(self, contents):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def parse_variable(self, contents):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def parse_register(self, contents):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def parse_instruction(self, contents):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def dump_mpt_config(self, mpt_config, filename):
        """ """
        raise NotImplementedError


class MicroprobeTestParserDefault(MicroprobeTestParser):
    """Class to represent a Microprobe Test configuration parser."""
    version = 0.5

    def __init__(self):
        """ """
        super(MicroprobeTestParserDefault, self).__init__()
        self._configparser_cls = six.moves.configparser.SafeConfigParser
        self._configparser_default = {}
        self._configparser_dict = OrderedDict

        self._files_readed = RejectingOrderedDict()
        self._filename = None
        self._definition_class = None

    def parse_filename(self, filename):
        """ """

        filename = os.path.abspath(filename)
        LOG.debug("Start parsing microprobe test file: '%s'", filename)

        self._filename = filename
        self._basepath = os.path.dirname(filename)
        self._files_readed[filename] = 0

        contents = self._read_file_contents(filename)
        contents = self._expand(contents)

        try:
            parser = self._parse_contents(contents)
        except six.moves.configparser.ParsingError as exc:
            raise MicroprobeMPTFormatError(
                exc.message.replace(
                    "???", filename
                )
            )

        self._check_sections(parser)

        # Check version number for the parser
        try:
            required_version = float(parser.get("MPT", "mpt_version"))
        except AttributeError as exc:
            raise MicroprobeMPTFormatError(
                "Unable to process the"
                " mpt_version string"
            )
        except ValueError as exc:
            raise MicroprobeMPTFormatError(
                "mpt_version should be a numerical"
                " value"
            )

        LOG.debug("Required version: '%s'", required_version)

        definition = [
            definition_class
            for definition_class in get_all_subclasses(
                MicroprobeTestDefinition
            ) if definition_class.version == required_version
        ]

        if len(definition) == 0:

            versions = [
                definition_class.version
                for definition_class in get_all_subclasses(
                    MicroprobeTestDefinition
                )
            ]

            raise MicroprobeMPTFormatError(
                "Unable to find the specified test definition for "
                "mpt_version: %s. Valid versions: %s" %
                (required_version, versions)
            )

        elif len(definition) > 1:

            raise MicroprobeMPTFormatError(
                "Multiple test format definitions for mpt_version: %s" %
                required_version
            )

        assert len(definition) == 1
        definition = definition[0]
        self._definition_class = definition

        if required_version != self.version:

            # Parse with an appropriate instance version
            parser = [
                parser_class
                for parser_class in get_all_subclasses(MicroprobeTestParser)
                if parser_class.version == required_version
            ]

            if len(parser) == 1:

                return parser[0]().parse_contents(contents)

            elif len(parser) == 0:
                versions = [
                    parser_class.version
                    for parser_class in get_all_subclasses(
                        MicroprobeTestParser
                    )
                ]

                raise MicroprobeMPTFormatError(
                    "Unable to find the specified parser for mpt_version: %s."
                    " Valid versions: %s" % (required_version, versions)
                )

            elif len(parser) > 1:

                raise MicroprobeMPTFormatError(
                    "Multiple parser definitions for mpt_version: %s" %
                    required_version
                )

        else:

            return self.parse_contents(contents)

    def parse_instruction(self, contents):
        return contents

    def parse_contents(self, contents):
        """ """
        # Parse the contents
        LOG.debug("Start parsing contents: \n%s", contents)

        parser = self._parse_contents(contents)

        # Minimum format checks
        LOG.debug("Check sections")
        self._check_sections(parser)

        # Create the test definition object
        test_definition = self._definition_class()

        if parser.has_section("STATE"):
            LOG.debug("Parsing [STATE] section")

            items = parser.items("STATE")

            if "contents" in dict(items):
                content_path = dict(items)["contents"]

                if not os.path.isabs(content_path):
                    content_path = os.path.join(self._basepath,
                                                content_path)

                with open_generic_fd(content_path, "r") as content_file:
                    lineno = 0
                    for line in content_file:
                        words = line.split(";")[0].split()
                        lineno += 1

                        # Empty line
                        if len(words) == 0:
                            continue

                        prefix = words[0]

                        if prefix == "R":
                            if len(words) != 3:
                                raise MicroprobeMPTFormatError(
                                    "Unable to parse content file %s:%d: "
                                    "Bad register format" %
                                    (content_path, lineno)
                                )

                            LOG.debug(
                                "%s:%d: Register %s = %s" %
                                (content_path, lineno, words[1], words[2]))

                            name = words[1]
                            value = words[2]

                            try:

                                register_definition = self.parse_register(
                                    (name.upper(), value)
                                )

                            except SyntaxError:
                                raise MicroprobeMPTFormatError(
                                    "Unable to parse content file %s:%d: "
                                    "Bad register format" %
                                    (content_path, lineno)
                                )
                            except ValueError:
                                raise MicroprobeMPTFormatError(
                                    "Unable to parse content file %s:%d: "
                                    "Bad register format" %
                                    (content_path, lineno)
                                )

                            if register_definition.name in [
                                register.name for register
                                in test_definition.registers
                            ]:
                                LOG.warning(
                                    "Register '%s' defined multiple times",
                                    name.upper()
                                )

                            test_definition.register_register_definition(
                                register_definition
                            )

                        elif prefix == "M":
                            if len(words) != 3:
                                raise MicroprobeMPTFormatError(
                                    "Unable to parse content file %s:%d: "
                                    "Bad memory format" %
                                    (content_path, lineno)
                                )

                            address = words[1]
                            data = words[2]

                            var_name = "mem_" + address
                            # TODO uint32_t instead?
                            var_type = "uint8_t"
                            var_chars = 2
                            var_align = 0
                            var_len = len(data)
                            var_items = [
                                int(data[i:i + var_chars], 16)
                                for i in range(0, var_len, var_chars)
                            ]
                            var_nelems = len(var_items)

                            # TODO Show length
                            LOG.debug(
                                "%s:%d: Memory %s = [%d]",
                                content_path, lineno, words[1], var_nelems
                            )

                            var_def = MicroprobeTestVariableDefinition(
                                var_name.upper().strip(), var_type,
                                var_nelems, int(address, 16),
                                var_align, var_items
                            )

                            test_definition.register_variable_definition(
                                var_def
                            )

                        else:
                            raise MicroprobeMPTFormatError(
                                "Unable to parse content file %s:%d: "
                                "Unknown prefix '%s'" %
                                (content_path, lineno, prefix)
                            )

        # Populate the test definition object
        if parser.has_section("DATA"):

            LOG.debug("Parsing [DATA] section")
            items = parser.items("DATA")

            for name, value in items:

                value = value.replace("\t", " ")
                LOG.debug("Parsing '%s = %s'", name, value)

                try:

                    if name == "default_address":

                        if test_definition.default_data_address is not None:
                            LOG.warning(
                                "default address of '[DATA]' specified"
                                " at least twice"
                            )

                        test_definition.set_default_data_address(
                            _parse_value(value)
                        )

                    else:

                        variable_definition = self.parse_variable(
                            (name, value)
                        )
                        test_definition.register_variable_definition(
                            variable_definition
                        )

                except SyntaxError:
                    LOG.critical("Syntax error")
                    raise MicroprobeMPTFormatError(
                        "Unable to parse line '%s = %s' in "
                        "section [DATA] of file: '%s'" %
                        (name, value, self._filename)
                    )
                except ValueError:
                    LOG.critical("Value error")
                    raise MicroprobeMPTFormatError(
                        "Unable to parse line '%s = %s' in "
                        "section [DATA] of file: '%s'" %
                        (name, value, self._filename)
                    )

        if parser.has_section("REGISTERS"):

            LOG.debug("Parsing [REGISTERS] section")
            items = parser.items("REGISTERS")

            for name, value in items:

                LOG.debug("Parsing '%s = %s'", name.upper(), value)
                value = value.replace("\t", " ")

                try:

                    register_definition = self.parse_register(
                        (name.upper(), value)
                    )

                except SyntaxError:
                    raise MicroprobeMPTFormatError(
                        "Unable to parse line '%s = %s' in "
                        "section [REGISTERS] of file: '%s'" %
                        (name, value, self._filename)
                    )
                except ValueError:
                    raise MicroprobeMPTFormatError(
                        "Unable to parse line '%s = %s' in "
                        "section [REGISTERS] of file: '%s'" %
                        (name, value, self._filename)
                    )

                # TODO Collides with registers in [STATE]
                if register_definition.name in [
                    register.name for register in test_definition.registers
                ]:
                    LOG.warning(
                        "Register '%s' defined multiple times "
                        " in [REGISTERS] section", name.upper()
                    )

                test_definition.register_register_definition(
                    register_definition
                )

        if parser.has_section("RAW"):

            LOG.debug("Parsing [RAW] section")
            items = parser.items("RAW")

            for name, value in items:

                value = value.replace("\t", " ")
                raw_definition = _parse_raw(name.upper(), value)

                if raw_definition[0] not in [
                    'FILE_HEADER', 'FILE_FOOTER', 'CODE_HEADER', 'CODE_FOOTER'
                ]:
                    LOG.warning(
                        "Skipping RAW entry '%s' in [RAW] section",
                        name.upper()
                    )
                    continue

                if raw_definition[0] in [raw for raw in test_definition.raw]:
                    LOG.warning(
                        "RAW entry '%s' defined multiple times "
                        " in [RAW] section. Appending.", name.upper()
                    )

                test_definition.register_raw_definition(*raw_definition)

        if parser.has_section("CODE"):

            LOG.debug("Parsing [CODE] section")
            items = parser.items("CODE")

            if "default_address" in dict(items):

                name = "default_address"
                value = dict(items)[name]
                value = value.replace("\t", " ")

                if test_definition.default_code_address is not None:
                    LOG.warning(
                        "default address of '[CODE]' specified"
                        " at least twice"
                    )

                try:
                    test_definition.set_default_code_address(
                        _parse_value(value)
                    )

                except SyntaxError:
                    raise MicroprobeMPTFormatError(
                        "Unable to parse line '%s = %s' in "
                        "section [CODE] of file: '%s'" %
                        (name, value, self._filename)
                    )
                except ValueError:
                    raise MicroprobeMPTFormatError(
                        "Unable to parse line '%s = %s' in "
                        "section [CODE] of file: '%s'" %
                        (name, value, self._filename)
                    )

            for name, value in items:

                LOG.debug("Parsing '%s = %s'", name, value)
                value = value.replace("\t", " ")

                if name in ["default_address"]:
                    continue

                elif name == "instructions":

                    if len(test_definition.code) > 0:
                        raise MicroprobeMPTFormatError(
                            "'instructions' option in [CODE] section defined"
                            " at least twice"
                        )

                    instruction_definitions = self.parse_code(
                        value, test_definition.default_code_address
                    )

                    test_definition.register_instruction_definitions(
                        instruction_definitions
                    )

        if parser.has_section("DAT"):

            LOG.debug("Parsing [DAT] section")
            items = parser.items("DAT")

            if "dat_raw" in dict(items):

                name = "dat_raw"
                value = dict(items)[name]
                value = value.replace("\t", " ")

                raw_definition = _parse_raw(name.upper(), value)
                test_definition.register_raw_definition(
                    'CODE_FOOTER', raw_definition[1]
                )

            for name, value in items:

                value = value.replace("\t", " ")

                if name in ['dat_raw']:
                    test_definition.register_dat_property(name, value)
                elif name == 'dat_map':
                    dat_definition = _parse_literal(name, value)
                    test_definition.register_dat_mapping(dat_definition[1])
                elif name == 'dat_raw_parse':
                    if value.strip().upper() == "TRUE":
                        test_definition.register_dat_property(name, True)
                elif name == 'dat_raw_decorate':
                    if value.strip().upper() == "TRUE":
                        test_definition.register_dat_property(name, True)
                else:
                    raise MicroprobeMPTFormatError(
                        "Unknown entry: '%s' in [DAT] section" % name
                    )

        if parser.has_section("TRACE"):

            LOG.debug("Parsing [TRACE] section")
            items = parser.items("TRACE")

            roi_start = None
            roi_end = None
            roi_start_cyc = None
            roi_end_cyc = None
            max_ins = None
            max_cyc = None
            memory_access_trace_path = None

            for name, value in items:
                if name == "roi_start_instruction":
                    roi_start = _parse_value(value)
                elif name == "roi_end_instruction":
                    roi_end = _parse_value(value)
                elif name == "instruction_count":
                    max_ins = _parse_value(value)
                elif name == "roi_start_cycle":
                    roi_start_cyc = _parse_value(value)
                elif name == "roi_end_cycle":
                    roi_end_cyc = _parse_value(value)
                elif name == "cycle_count":
                    max_cyc = _parse_value(value)
                elif name == "roi_memory_access_trace":
                    memory_access_trace_path = value
                    if not os.path.isabs(memory_access_trace_path):
                        memory_access_trace_path = os.path.join(
                            self._basepath, memory_access_trace_path)

            roi = None
            if roi_start is not None and roi_end is not None:
                roi = (roi_start, roi_end)
                if roi_start >= roi_end:
                    raise MicroprobeMPTFormatError(
                        "Region of interest (ROI) specified in [TRACE] "
                        "section is empty. (instructions)"
                    )
                test_definition.set_roi_ins(roi)
            elif not (roi_start is None and roi_end is None):
                raise MicroprobeMPTFormatError(
                    "Incomplete definition of the region of interest (roi)"
                    " in [TRACE] section. Specify both: "
                    "roi_start_instruction and roi_end_instruction keys."
                )

            if max_ins is not None:
                test_definition.set_instruction_count(max_ins)
                if roi is not None:
                    if roi[1] > max_ins:
                        raise MicroprobeMPTFormatError(
                            "Trace instruction_count does not cover "
                            "the region of interest."
                        )

            roi_cyc = None
            if roi_start_cyc is not None and roi_end_cyc is not None:
                roi_cyc = (roi_start_cyc, roi_end_cyc)
                if roi_start_cyc >= roi_end_cyc:
                    raise MicroprobeMPTFormatError(
                        "Region of interest (ROI) specified in [TRACE] "
                        "section is empty. (cycles)"
                    )
                test_definition.set_roi_cyc(roi_cyc)
            elif not (roi_start_cyc is None and roi_end_cyc is None):
                raise MicroprobeMPTFormatError(
                    "Incomplete definition of the region of interest (roi)"
                    " in [TRACE] section. Specify both: "
                    "roi_start_cycle and roi_end_cycle keys."
                )

            if max_cyc is not None:
                test_definition.set_cycle_count(max_cyc)
                if roi_cyc is not None:
                    if roi_cyc[1] > max_cyc:
                        raise MicroprobeMPTFormatError(
                            "Trace cycle_count does not cover "
                            "the region of interest."
                        )

            if memory_access_trace_path is not None:
                memtrace = []
                with open_generic_fd(memory_access_trace_path, "r") as \
                        content_file:
                    lineno = 0
                    for line in content_file:
                        # Remove comments
                        words = line.split(";")[0].split()
                        lineno += 1

                        # Empty line
                        if len(words) == 0:
                            continue

                        if len(words) != 4:
                            raise MicroprobeMPTFormatError(
                                "Unable to parse trace file %s:%d: "
                                "Bad number of words in format" %
                                (memory_access_trace_path, lineno)
                            )

                        dtype, rw, address, length = words

                        if dtype not in ['D', 'I']:
                            raise MicroprobeMPTFormatError(
                                "Unable to parse trace file %s:%d: "
                                "Unknown data type '%d'."
                                "Only 'D' or 'I' types allowed" %
                                (memory_access_trace_path, lineno, dtype)
                            )

                        if rw not in ['R', 'W']:
                            raise MicroprobeMPTFormatError(
                                "Unable to parse trace file %s:%d: "
                                "Unknown access type '%d'."
                                "Only 'R'or 'W' access type allowed" %
                                (memory_access_trace_path, lineno, rw)
                            )

                        try:
                            address = int(address, 16)
                        except ValueError:
                            raise MicroprobeMPTFormatError(
                                "Unable to parse trace file %s:%d: "
                                "Invalid address." %
                                (memory_access_trace_path, lineno)
                            )

                        try:
                            length = int(length, 10)
                        except ValueError:
                            raise MicroprobeMPTFormatError(
                                "Unable to parse trace file %s:%d: "
                                "Invalid length." %
                                (memory_access_trace_path, lineno)
                            )

                        memtrace.append(
                            MicroprobeTestMemoryAccessDefinition(
                                dtype, rw, address, length
                            )
                        )

                test_definition.set_roi_memory_access_trace(memtrace)

        return test_definition

    # def _parse_dat(self, dat_str):
    #    logical = "LOGICAL[ ]*=[ ]*[0-9A-F]+"
    #    hostabs = "HOSTABS[ ]*=[ ]*[0-9A-F]+"
    #    asce = "ASCE[ ]*=[ ]*[0-9A-F]+"
    #    print dat_str
    #    print re.findall(logical, dat_str)
    #    print re.findall(hostabs, dat_str)
    #    print re.findall(asce, dat_str)
    #    exit(-1)

    def parse_variable(self, contents):
        """ """
        name, definition = contents
        definition = _normalize_variable(definition)

        LOG.debug("Normalized variable definition: '%s'", definition)

        rndfp = False
        rndint = False

        if len(re.findall(" RNDFP ", definition)) > 0:
            definition = definition.replace(" RNDFP ", " None ")
            rndfp = True

        if len(re.findall(" RNDINT ", definition)) > 0:
            definition = definition.replace(" RNDINT ", " None ")
            rndint = True

        LOG.debug("Parsing variable definition: '%s'", definition)
        definition_elements = ast.literal_eval(definition)

        if rndfp:
            definition_elements[4] = RNDFP

        if rndint:
            definition_elements[4] = RNDINT

        return MicroprobeTestVariableDefinition(
            name.upper().strip(), definition_elements[0],
            definition_elements[1], definition_elements[2],
            definition_elements[3], definition_elements[4]
        )

    def parse_register(self, contents):
        """ """
        name, value = contents
        value = _parse_value(value)

        return MicroprobeTestRegisterDefinition(name, value)

    def parse_code(self, contents, base_address):
        """ """

        LOG.debug("Start parsing code")

        if base_address is None:
            base_address = 0

        instruction_definitions = []
        content_lines = contents.split("\n")

        current_label = None
        current_address = None
        current_decorator = ' '
        comments = []

        progress = Progress(len(content_lines), msg="Code lines parsed:")

        for line in content_lines:

            progress()

            LOG.debug("Parse line: '%s'", line)
            line = line.replace("\t", " ")

            if line.strip().startswith("#"):
                LOG.debug("Skip comment line")
                continue

            if line.strip() == "":
                LOG.debug("Skip empty line")
                continue

            if (line + ";").split(";")[1] != '':
                comments.append((line + ";").split(";")[1])
            line = line.split(";")[0]

            LOG.debug("Clean line: '%s'", line)

            if line.find(":") < 0:

                LOG.debug("Instruction/decorator alone detected")

                ins_def = MicroprobeAsmInstructionDefinition(
                    self.parse_instruction(line.split('@')[0].strip()),
                    current_label, current_address, _parse_decorators(
                        current_decorator + (
                            line + '@'
                        ).split('@')[1].strip()
                    ), comments
                )

                if ins_def.assembly != "":

                    instruction_definitions.append(ins_def)
                    current_label = None
                    current_address = None
                    comments = []
                    current_decorator = ' '
                    LOG.debug(ins_def)

                else:

                    current_decorator = _parse_decorators(
                        current_decorator + (
                            line + '@'
                        ).split('@')[1].strip()
                    )

            elif len(line.split(":")) == 2:

                LOG.debug("Prefix detected")

                address_label = line.split(":")[0].strip()
                assembly = line.split(":")[1].split('@')[0].strip()
                decorators = (line.split(":")[1] + '@').split('@')[1].strip()

                LOG.debug("Prefix: '%s'", address_label)
                LOG.debug("Assembly: '%s'", assembly)
                LOG.debug("Decorators: '%s", decorators)

                sline = address_label.split()

                label = None
                label_parsed = False

                address = None
                address_parsed = False
                address_relative = False

                LOG.debug("Parsing prefix: '%s'", sline)

                for elem in sline:

                    LOG.debug("Parsing prefix element: '%s'", elem)

                    # TODO: Optimize this case switch

                    if elem.startswith("<") and elem.endswith(">"):
                        LOG.debug("Label detected")
                        label = elem[1:-1]

                        if label_parsed:
                            raise MicroprobeMPTFormatError(
                                "Multiple labels specified for the same "
                                "region of code (line:'%s', file:'%s'" %
                                (line, self._filename)
                            )

                        label_parsed = True

                    elif elem.isdigit():
                        LOG.debug("Decimal absolute address detected")
                        address = int(elem)

                        if address_parsed:
                            raise MicroprobeMPTFormatError(
                                "Multiple addresses specified for the same "
                                "region of code (line:'%s', file:'%s'" %
                                (line, self._filename)
                            )

                        address_parsed = True
                        address_relative = False

                    elif elem.startswith("0x"):
                        LOG.debug("Hex absolute address detected")
                        try:
                            address = int(elem, 16)
                        except ValueError:
                            raise MicroprobeMPTFormatError(
                                "Wrong address '%s' format in line '%s' of"
                                " file '%s'" % (elem, line, self._filename)
                            )

                        if address_parsed:
                            raise MicroprobeMPTFormatError(
                                "Multiple addresses specified for the same "
                                "region of code (line:'%s', file:'%s'" %
                                (line, self._filename)
                            )

                        address_parsed = True
                        address_relative = False

                    elif elem[1:].isdigit() and elem[0] in ['-', '+']:
                        LOG.debug("Decimal relative address detected")
                        address = int(elem)

                        if address_parsed:
                            raise MicroprobeMPTFormatError(
                                "Multiple addresses specified for the same "
                                "region of code (line:'%s', file:'%s'" %
                                (line, self._filename)
                            )

                        address_parsed = True
                        address_relative = True

                    elif elem[1:].startswith("0x") and elem[0] in ['-', '+']:
                        LOG.debug("Hex relative address detected")
                        try:
                            address = int(elem, 16)
                        except ValueError:
                            raise MicroprobeMPTFormatError(
                                "Wrong address '%s' format in line '%s' of"
                                " file '%s'" % (elem, line, self._filename)
                            )

                        if address_parsed:
                            raise MicroprobeMPTFormatError(
                                "Multiple addresses specified for the same "
                                "region of code (line:'%s', file:'%s'" %
                                (line, self._filename)
                            )

                        address_parsed = True
                        address_relative = True

                    else:
                        raise MicroprobeMPTFormatError(
                            "Unable to parse line: '%s' in '%s'. Check syntax"
                            % (line, self._filename)
                        )

                if label is not None and current_label is not None:
                    raise MicroprobeMPTFormatError(
                        "Multiple label definition to the same point: "
                        "'%s' and '%s' in '%s'. Check syntax" %
                        (label, current_label, self._filename)
                    )

                current_label = label

                if address is not None and current_address is not None:
                    raise MicroprobeMPTFormatError(
                        "Multiple address definition to the same point: "
                        "'%s' and '%s' in '%s'. Check syntax" %
                        (address, current_address, self._filename)
                    )

                current_address = address
                if current_address is not None and not address_relative:
                    LOG.debug(
                        "Computing absolute address: 0x%x", current_address
                    )
                    current_address = current_address - base_address
                    LOG.debug("Relative address: 0x%x", current_address)

                if assembly != "":

                    ins_def = MicroprobeAsmInstructionDefinition(
                        self.parse_instruction(assembly), current_label,
                        current_address, _parse_decorators(
                            current_decorator + decorators
                        ), comments
                    )

                    instruction_definitions.append(ins_def)
                    current_label = None
                    current_address = None
                    comments = []
                    current_decorator = ' '

                    LOG.debug(ins_def)

            else:
                raise MicroprobeMPTFormatError(
                    "Unable to parse line: '%s' in '%s'. Check syntax." %
                    (line, self._filename)
                )

        instruction_definitions = self._sort_by_instructions(
            instruction_definitions)

        return instruction_definitions

    def _sort_by_instructions(self, instr_list):

        new_list = []
        block_dict = {}

        last_address = None
        current_list = []
        extra = 0
        for instr in instr_list:
            if instr.address is not None:
                if (last_address in block_dict and
                        current_list != block_dict[last_address]):

                    raise MicroprobeMPTFormatError(
                        "Same instruction address "
                        "specified more than one time in the "
                        "MPT file"
                    )

                if last_address in block_dict:
                    extra += len(current_list)

                block_dict[last_address] = current_list
                last_address = instr.address
                current_list = [instr]
                continue
            current_list.append(instr)

        if current_list:
            if last_address in block_dict:
                extra += len(current_list)
            block_dict[last_address] = current_list

        if None in block_dict.keys():
            new_list.extend(block_dict[None])

        for address in sorted([elem for elem in block_dict.keys()
                               if elem is not None]):
            new_list.extend(block_dict[address])

        assert(len(instr_list) == (len(new_list) + extra))

        if extra:
            LOG.warning(
                "MPT includes repeated code regions. Ignoring it"
            )

        return new_list

    def dump_mpt_config(self, mpt_config, filename):

        output_string = []
        output_string.extend(self._dump_header())
        output_string.extend(self._dump_registers(mpt_config.registers))
        output_string.extend(
            self._dump_variables(
                mpt_config.default_data_address, mpt_config.variables
            )
        )
        output_string.extend(
            self._dump_code(
                mpt_config.default_code_address, mpt_config.code
            )
        )

        output_string.extend(
            self._dump_trace(
                filename,
                mpt_config.roi_ins,
                mpt_config.roi_cyc,
                mpt_config.instruction_count,
                mpt_config.cycle_count,
                mpt_config.roi_memory_access_trace
            )
        )

        with open_generic_fd(filename, 'w') as ofd:
            ofd.write("\n".join(output_string))

    def _dump_header(self):

        mstr = []
        mstr.append("; Microprobe Test Definition File")
        mstr.append("[MPT]")
        mstr.append(
            "mpt_version = %s ;  Format version of this MPT file." %
            str(self.version)
        )
        mstr.append("")
        return mstr

    def _dump_registers(self, registers):  # pylint: disable-msg=no-self-use

        mstr = []
        mstr.append(
            "[REGISTERS] ; Section to specify the initial register values"
        )
        mstr.append("")
        mstr.append("; Format: register = value. E.g.:")
        mstr.append("")
        mstr.append(
            "; Set GR0, GR1 and GR2 register to 0, 1, 2 values respectively"
        )
        mstr.append(";GR0 = 0x0")
        mstr.append("")

        for register in registers:
            mstr.append("%-8s = 0x%016X" % (register.name, register.value))

        mstr.append("")

        return mstr

    def _dump_variables(self, default, variables):

        mstr = []

        mstr.append("[DATA] ; Section to specify the variables")
        mstr.append("")
        mstr.append(
            "; Data section default address. Variables will be placed from "
            "this address"
        )
        mstr.append("; if their address is not specified")
        mstr.append("")
        if default is not None:
            mstr.append("default_address = 0x%016x" % default)
        else:
            mstr.append(";default_address = 0x00200000")
        mstr.append("")
        mstr.append("; Variable Declaration")
        mstr.append(
            "; Format: var_name = [ \"type\", nelems, address, alignment, "
            "init_values ]"
        )
        mstr.append("; where:")
        mstr.append(
            ";   - \"type\": is a string specifying the type of elements in "
            "the variable"
        )
        mstr.append(";   - nelems: is the number of elements in the variable")
        mstr.append(
            ";   - address : is the address of the variable, if set the "
            "address will be"
        )
        mstr.append(
            ";               fixed, otherwise, it will be computer by "
            "microprobe"
        )
        mstr.append(
            ";   - alignment : alignment requirements of the variable. "
            "It should not"
        )
        mstr.append(
            ";                 conflict with address if specified. It can be "
            "set to None"
        )
        mstr.append(
            ";   - init_values : if it is a single value, all the elements"
            " will be"
        )
        mstr.append(
            ";                   initialized to that value, if it is an "
            "array, elements"
        )
        mstr.append(
            ";                   will be initialized to the values specified"
            " in a round-"
        )
        mstr.append(
            ";                   robin fashion. Two special keywords can be "
            "specified:"
        )
        mstr.append(
            ";                   RNDFP and RNDINT to initialize the elements"
            " to random FP"
        )
        mstr.append(";                   and random INT values")
        mstr.append(";")
        mstr.append(
            "; Note that variable names ARE NOT case sensitive. I.e. "
            "VAR = Var = var"
        )
        mstr.append("")
        for var in variables:
            mstr.append(self._dump_variable(var))
        mstr.append("")

        return mstr

    def _dump_variable(self, var):  # pylint: disable-msg=no-self-use

        address = "None"
        if var.address is not None:
            if isinstance(var.address, six.integer_types):
                address = "0x%016X" % var.address
            else:
                assert var.address.base_address == "code"
                address = "0x%016X" % var.address.displacement

        alignment = "None"
        if var.alignment is not None:
            alignment = "0x%04X" % var.alignment

        values = "None"
        if var.init_value is not None:
            values = "%s" % var.init_value

        return "%s = [\"%s\", %08d, %s, %s, %s]" % (
            var.name, var.var_type, var.num_elements, address, alignment,
            values
        )

    def _dump_code(self, default, instructions):

        mstr = []

        mstr.append("[CODE] ; Section to specify the code")
        mstr.append("")
        mstr.append(
            "; Code section default address. Code will be placed from this "
            "address"
        )
        mstr.append("; if the instruction address is not specified")
        mstr.append("")
        if default is not None:
            mstr.append("default_address = 0x%016x" % default)
        else:
            mstr.append(";default_address = 0x00100000")
        mstr.append("")
        mstr.append(
            "; The code specified after 'instructions' entry (below) is the "
            "code that will be"
        )
        mstr.append(
            "; processed by microprobe. The instruction format is similar to "
            "GNU assembler"
        )
        mstr.append(
            "; format, it also allows the specification of labels (NOT case "
            "sensitive) and"
        )
        mstr.append(
            "; references to the declared variables. It is also possible to "
            "specify instruction"
        )
        mstr.append(
            "; addresses and to do code expansion by referencing other user"
        )
        mstr.append(
            "; defined entries. Check the example below to see examples of "
            "these features."
        )
        mstr.append(";")
        mstr.append(
            "; **************************************************************"
            "***************"
        )
        mstr.append(
            "; ******  Although Microprobe performs some sanity checks, it "
            "is the   ********"
        )
        mstr.append(
            "; ******  responsibility of the user to define correct code. "
            "          ********"
        )
        mstr.append(
            "; ******                                                       "
            "        ********"
        )
        mstr.append(
            "; *************************************************************"
            "****************"
        )
        mstr.append("")
        mstr.append("instructions =")

        for instruction in instructions:
            mstr.extend(self._dump_instruction(instruction))

        mstr.append("")
        return mstr

    def _dump_instruction(self, instr):  # pylint: disable-msg=no-self-use
        mstr = []

        if instr.address is not None or instr.label is not None:

            address = ""
            fmt = "  "
            if instr.address is not None:
                address = "0x%016X" % instr.address.displacement
                fmt += "%s" % address

            if instr.label is not None:
                if instr.address is not None:
                    fmt += " "
                fmt += "<%s>" % instr.label

            fmt += ":"
            mstr.append(fmt)

        mstr.append("    " + "%-50s" % instr.asm)

        if instr.decorators is not None and instr.decorators != {}:
            mstr[-1] += "@"
            for decorator in instr.decorators:
                mstr[-1] += " %s=%s" % (
                    decorator.upper(),
                    instr.decorators[decorator]['value']
                )

        if (instr.comments is not None and instr.comments != '' and
                instr.comments != []):
            mstr[-1] += " ; %s" % " | ".join(instr.comments)

        return mstr

    def _dump_trace(self, filename, roi_ins, roi_cyc, instr_count, cyc_count,
                    memory_trace):

        mstr = []

        if (roi_cyc is None and roi_ins is None and instr_count is None and
                cyc_count is None):
            return mstr

        mstr.append("[TRACE]")
        mstr.append("")
        if roi_ins is not None:
            mstr.append("roi_start_instruction = %d" % roi_ins[0])
            mstr.append("roi_end_instruction = %d" % roi_ins[1])

        if roi_cyc is not None:
            mstr.append("roi_start_cycle = %d" % roi_cyc[0])
            mstr.append("roi_end_cycle = %d" % roi_cyc[1])

        if instr_count is not None:
            mstr.append("instruction_count = %d" % instr_count)

        if cyc_count is not None:
            mstr.append("cycle_count = %d" % cyc_count)

        if memory_trace:
            memtracefile = os.path.splitext(filename)[0] + ".memtrace.gz"
            mstr.append(
                "roi_memory_access_trace = %s" %
                os.path.basename(memtracefile))
            self._dump_memtrace(memtracefile, memory_trace)

        return mstr

    def _dump_memtrace(self, ofile, memtrace):
        with open_generic_fd(ofile, "w") as ofd:
            for access in memtrace:
                straccess = access.to_str()
                if isinstance(straccess, six.string_types) and six.PY3:
                    ofd.write(straccess.encode())
                    ofd.write('\n'.encode())
                else:
                    ofd.write(straccess)
                    ofd.write('\n')

    def _expand(self, contents, level=0):
        """ """

        content_lines = contents.split("\n")
        new_contents = []

        for line in content_lines:
            if line.strip().startswith("#include"):

                filename = line.split("<")[1].replace(">", "")

                if filename in self._files_readed:
                    if self._files_readed[filename] != level:
                        # We already read this file in a previous level
                        # (circular recursion)
                        raise MicroprobeMPTFormatError(
                            "Recursive #include found in Microprobe test "
                            "file: '%s'. Check include: '%s'" %
                            (self._filename, filename)
                        )
                else:

                    self._files_readed[filename] = level + 1

                new_contents += self._expand(
                    self._read_file_contents(filename),
                    level=level + 1
                )

            elif "@" in line:

                pdecorators = [elem for elem in line.split(
                    "@")[1].split(";")[0].split(" ") if elem != ""]

                for decorator in pdecorators:

                    dvalue = decorator.split("=")[1]
                    dvaluepath = dvalue

                    if not os.path.isabs(dvalue):
                        dvaluepath = os.path.join(self._basepath, dvalue)

                    if os.path.isfile(dvaluepath):

                        decorator_contents = self._read_file_contents(dvalue)
                        decorator_contents = decorator_contents.replace('\n',
                                                                        ',')
                        line = line.replace(dvalue, decorator_contents)

                new_contents.append(line)
            else:
                new_contents.append(line)

        return "\n".join(new_contents)

    def _read_file_contents(self, filename):
        """ """

        if not os.path.isabs(filename):
            filename = os.path.join(self._basepath, filename)

        if not os.path.isfile(filename):
            if filename != self._filename:
                raise MicroprobeMPTFormatError(
                    "Referenced file '%s' not found!!" % filename
                )
            else:
                raise MicroprobeMPTFormatError("'%s' not found!!" % filename)

        with open_generic_fd(filename, 'r') as filename_fd:
            read_contents = filename_fd.read()
            if read_contents == '':
                raise MicroprobeMPTFormatError("'%s' empty!" % filename)

            return read_contents

    def _parse_contents(self, contents):
        """ """

        kwargs = {}
        if six.PY3:
            kwargs["inline_comment_prefixes"] = ";"

        parser = self._configparser_cls(
            self._configparser_default, self._configparser_dict,
            **kwargs
        )

        if six.PY2:
            parser.readfp(io.BytesIO(contents))
        elif six.PY3:
            parser.readfp(io.StringIO(contents))

        return parser

    def _check_sections(self, parser):
        """ """

        section = 'MPT'
        if not parser.has_section(section):
            raise MicroprobeMPTFormatError(
                "No '[%s]' section defined in '%s'" % (section, self._filename)
            )

        section = 'CODE'
        if not parser.has_section(section):
            raise MicroprobeMPTFormatError(
                "No '[%s]' section defined in '%s'" % (section, self._filename)
            )

        for section in parser.sections():
            if section not in ['CODE', 'DATA', 'REGISTERS',
                               'MPT', 'RAW', 'STATE', 'TRACE']:
                LOG.warning("Not processing unknown section '[%s]'", section)


class MicroprobeTestParserV0x5(MicroprobeTestParserDefault):
    """Class to represent a Microprobe Test configuration (v0.5)"""
    version = 0.5

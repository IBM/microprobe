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
""":mod:`microprobe.target.isa` package

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc
import os

# Third party modules

# Own modules
import microprobe.code.ins
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.context import Context
from microprobe.code.var import VariableArray
from microprobe.exceptions import MicroprobeArchitectureDefinitionError, \
    MicroprobeCodeGenerationError, MicroprobeTargetDefinitionError, \
    MicroprobeYamlFormatError
from microprobe.target.isa import comparator as comparator_mod
from microprobe.target.isa import generator as generator_mod
from microprobe.target.isa import instruction as instruction_mod
from microprobe.target.isa import instruction_field as ifield_mod
from microprobe.target.isa import instruction_format as iformat_mod
from microprobe.target.isa import operand as operand_mod
from microprobe.target.isa import register as register_mod
from microprobe.target.isa import register_type as register_type_mod
from microprobe.target.isa.dat import GenericDynamicAddressTranslation
from microprobe.utils.imp import get_object_from_module, \
    import_cls_definition, import_definition, import_operand_definition
from microprobe.utils.logger import DEBUG, get_logger
from microprobe.utils.misc import dict2OrderedDict, findfiles, natural_sort
from microprobe.utils.yaml import read_yaml
import six

# Local modules


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "isa.yaml"
)
DEFAULT_ISA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "default", "isa.yaml"
)
LOG = get_logger(__name__)
__all__ = [
    "find_isa_definitions", "import_isa_definition", "ISA", "GenericISA"
]


# Functions
def _read_isa_extensions(isadefs, path):
    """

    :param isadefs:
    :param path:

    """

    if "Extends" in isadefs[-1]:
        isadefval = isadefs[-1]["Extends"]
        del isadefs[-1]["Extends"]

        if not os.path.isabs(isadefval):
            isadefval = os.path.join(path, isadefval)

        isadef = read_yaml(os.path.join(isadefval, "isa.yaml"), SCHEMA)
        isadef["Path"] = isadefval
        isadefs.append(isadef)

        _read_isa_extensions(isadefs, isadefval)


def _read_yaml_definition(isadefs, path):
    """

    :param isadefs:
    :param path:

    """

    isadef = read_yaml(os.path.join(path, "isa.yaml"), SCHEMA)
    isadef["Path"] = path

    isadefs.append(isadef)

    _read_isa_extensions(isadefs, path)

    baseisa = read_yaml(DEFAULT_ISA, SCHEMA)
    baseisa["Path"] = DEFAULT_ISA
    isadefs.append(baseisa)

    complete_isadef = {}
    isadefs.reverse()

    for isadef in isadefs:
        for key, val in isadef.items():
            if not isinstance(val, dict):
                complete_isadef[key] = isadef[key]
            else:

                override = val.get("Override", False)

                if key not in complete_isadef:
                    complete_isadef[key] = {}

                for key2 in val:

                    if key2 in ["YAML", "Modules"]:
                        if key2 not in complete_isadef[key]:
                            complete_isadef[key][key2] = []

                        if os.path.isabs(val[key2]):
                            if override:
                                complete_isadef[key][key2] = [val[key2]]
                            else:
                                complete_isadef[key][key2].append(val[key2])
                        else:
                            if override:
                                complete_isadef[key][key2] = [
                                    os.path.join(
                                        isadef["Path"], val[key2]
                                    )
                                ]
                            else:
                                complete_isadef[key][key2].append(
                                    os.path.join(
                                        isadef["Path"], val[key2]
                                    )
                                )
                    elif key2 == "Module":
                        if val[key2].startswith("microprobe"):
                            val[key2] = os.path.join(
                                os.path.dirname(__file__), "..", "..", "..",
                                val[key2]
                            )

                        if os.path.isabs(val[key2]):
                            complete_isadef[key][key2] = val[key2]
                        else:
                            complete_isadef[key][key2] = os.path.join(
                                isadef["Path"], val[key2]
                            )
                    else:
                        complete_isadef[key][key2] = val[key2]

    return complete_isadef


def import_isa_definition(path):
    """Imports a ISA definition given a path

    :param path:

    """

    LOG.info("Start ISA import")
    LOG.debug("Importing definition from '%s'", path)

    if not os.path.isabs(path):
        path = os.path.abspath(path)

    isadef = _read_yaml_definition([], path)

    regts, force = import_definition(
        isadef, os.path.join(path, "isa.yaml"), "Register_type",
        register_type_mod, None
    )
    regts = dict2OrderedDict(regts)

    regs, force = import_definition(
        isadef,
        os.path.join(
            path, "isa.yaml"
        ),
        "Register",
        register_mod,
        regts,
        force=force
    )
    regs = dict2OrderedDict(regs)

    ops, force = import_operand_definition(
        isadef,
        os.path.join(
            path, "isa.yaml"
        ),
        "Operand",
        operand_mod,
        regs,
        force=force
    )
    ops = dict2OrderedDict(ops)

    ifields, force = import_definition(
        isadef,
        os.path.join(
            path, "isa.yaml"
        ),
        "Instruction_field",
        ifield_mod,
        ops,
        force=force
    )
    ifields = dict2OrderedDict(ifields)

    iformats, force = import_definition(
        isadef,
        os.path.join(
            path, "isa.yaml"
        ),
        "Instruction_format",
        iformat_mod,
        ifields,
        force=force
    )

    iformats = dict2OrderedDict(iformats)

    ins, force = import_definition(
        isadef,
        os.path.join(
            path, "isa.yaml"
        ),
        "Instruction",
        instruction_mod, (iformats, ops),
        force=force
    )
    ins = dict2OrderedDict(ins)

    comp_clss = import_cls_definition(
        isadef, os.path.join(path, "isa.yaml"), "Comparator", comparator_mod
    )

    gen_clss = import_cls_definition(
        isadef, os.path.join(path, "isa.yaml"), "Generator", generator_mod
    )

    isa_cls = get_object_from_module(
        isadef["ISA"]["Class"], isadef["ISA"]["Module"]
    )

    try:
        isa = isa_cls(
            isadef["Name"], isadef["Description"], ins,
            regs, comp_clss, gen_clss
        )
    except TypeError as exc:
        LOG.critical("Unable to import ISA definition.")
        LOG.critical("Check if you definition is complete.")
        LOG.critical("Error reported: %s", exc)
        raise MicroprobeTargetDefinitionError(exc)

    LOG.info("ISA '%s' imported", isa)

    if not LOG.isEnabledFor(DEBUG):
        return isa

    # Check definition. Ensure that all the components defined are referenced.
    for unused_regt in [
        regt
        for regt in regts.values()
        if regt not in [reg.type for reg in isa.registers.values()]
    ]:
        LOG.warning("Unused register type definition: %s", unused_regt)

    for unused_reg in [
        reg for reg in regs.values() if reg not in list(isa.registers.values())
    ]:
        LOG.warning("Unused register definition: %s", unused_reg)

    used_operands = []
    for ins in isa.instructions.values():
        for oper in ins.operands.values():
            used_operands.append(oper[0].name)
        for operand in [operand.type for operand in ins.implicit_operands]:
            used_operands.append(operand.name)
        for field in ins.format.fields:
            used_operands.append(field.default_operand.name)

    for unused_op in [
        operand for operand in ops.values()
        if operand.name not in used_operands
    ]:
        LOG.warning("Unused operand definition: %s", unused_op)

    used_fields = []
    for ins in isa.instructions.values():
        used_fields += [field.name for field in ins.format.fields]

    for unused_field in [
        field for field in ifields.values() if field.name not in used_fields
    ]:
        LOG.warning("Unused field definition: %s", unused_field)

    used_formats = []
    for ins in isa.instructions.values():
        used_formats.append(ins.format.name)

    for unused_format in [
        iformat
        for iformat in iformats.values() if iformat.name not in used_formats
    ]:
        LOG.warning("Unused format definition: %s", unused_format)

    return isa


def find_isa_definitions(paths=None):

    if paths is None:
        paths = []

    paths = paths + MICROPROBE_RC["architecture_paths"] \
        + MICROPROBE_RC["default_paths"]

    results = []
    isafiles = findfiles(paths, "^isa.yaml$")

    if len(isafiles) > 0:
        from microprobe.target import Definition

    for isafile in isafiles:

        try:
            isadef = read_yaml(isafile, SCHEMA)
        except MicroprobeYamlFormatError as exc:
            LOG.info("Exception: %s", exc)
            LOG.info("Skipping '%s'", isafile)
            continue

        try:
            definition = Definition(
                isafile, isadef["Name"], isadef["Description"]
            )
            if (
                definition not in results and
                not definition.name.endswith("common")
            ):
                results.append(definition)
        except TypeError as exc:
            # Skip bad definitions
            LOG.info("Exception: %s", exc)
            LOG.info("Skipping '%s'", isafile)
            continue
    return results


# Classes
class ISA(six.with_metaclass(abc.ABCMeta, object)):
    """Abstract class to represent an Instruction Set Architecture (ISA).

    An instruction set architecture (ISA) object defines the part of the
    computer architecture related to programming, including instructions,
    registers, operands, memory operands, etc.
    """

    @abc.abstractmethod
    def __init__(self):
        """ """
        pass

    @abc.abstractproperty
    def name(self):
        """ISA name (:class:`~.str`)."""
        raise NotImplementedError

    @abc.abstractproperty
    def description(self):
        """ISA description (:class:`~.str`)."""
        raise NotImplementedError

    @abc.abstractproperty
    def instructions(self):
        """ISA instructions (:class:`~.dict` mapping strings to
           :class:`~.InstructionType`). """
        raise NotImplementedError

    @abc.abstractproperty
    def target(self):
        """Associated target object (:class:`~.Target`)."""
        raise NotImplementedError

    @abc.abstractproperty
    def registers(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def scratch_registers(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def address_registers(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def float_registers(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def control_registers(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def scratch_var(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def context_var(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def __str__(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def full_report(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def set_register(self, reg, value, context):
        """

        :param reg:
        :param value:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def negate_register(self, reg, context):
        """

        :param reg:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def load(self, reg, address, context):
        """

        :param reg:
        :param address:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def load_float(self, reg, address, context):
        """

        :param reg:
        :param address:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def store_float(self, reg, address, context):
        """

        :param reg:
        :param address:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def store_integer(self, reg, address, length, context):
        """

        :param reg:
        :param address:
        :param length:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def store_decimal(self, address, length, value, context):
        """

        :param address:
        :param length:
        :param value:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def set_register_to_address(
        self,
        reg,
        address,
        context,
        force_absolute=False,
        force_relative=False
    ):
        """

        :param reg:
        :param address:
        :param context:
        :param force_absolute:  (Default value = False)

        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_register_for_address_arithmetic(self, context):
        """

        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_register_for_float_arithmetic(self, context):
        """

        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def set_register_bits(self, register, value, mask, shift, context):
        """

        :param register:
        :param value:
        :param mask:
        :param shift:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def new_instruction(self, name):
        """

        :param name:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def set_target(self, target):
        """

        :param target:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def add_to_register(self, register, value):
        """

        :param register:
        :param value:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def branch_unconditional_relative(self, source, target):
        """

        :param source:
        :param target:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def branch_to_itself(self):
        raise NotImplementedError

    @abc.abstractmethod
    def compare_and_branch(self, val1, val2, cond, target, context):
        """

        :param val1:
        :param val2:
        :param cond:
        :param target:
        :param context:

        """
        raise NotImplementedError

    @abc.abstractmethod
    def nop(self):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def flag_registers(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def get_dat(self, **kwargs):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def set_context(self, variable=None, tmpl_path=None):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def get_context(self, variable=None, tmpl_path=None):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def register_value_comparator(self, comp):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def normalize_asm(self, mnemonic, operands):
        """ """
        raise NotImplementedError


class GenericISA(ISA):
    """Class to represent a generic Instruction Set Architecture (ISA)."""

    def __init__(self, name, descr, ins, regs, comparators, generators):
        """

        :param name:
        :param descr:
        :param ins:
        :param regs:
        :param comparators:
        :param generators:

        """
        super(GenericISA, self).__init__()
        self._name = name
        self._descr = descr
        self._instructions = ins
        self._registers = regs
        self._target = None

        self._address_registers = [
            reg for reg in regs.values() if reg.used_for_address_arithmetic
        ]
        self._float_registers = [
            reg for reg in regs.values() if reg.used_for_float_arithmetic
        ]

        self._comparators = []
        for comparator in comparators:
            self._comparators.append(comparator(self))

        self._generators = []
        for generator in generators:
            self._generators.append(generator(self))

        self._scratch_registers = []
        self._control_registers = []
        self._flag_registers = []

        self._scratch_var = VariableArray(
            "%s_scratch_var" % self._name, "char", 256
        )
        self._context_var = None

    @property
    def name(self):
        """ """
        return self._name

    @property
    def description(self):
        """ """
        return self._descr

    @property
    def address_registers(self):
        """ """
        return self._address_registers

    @property
    def float_registers(self):
        """ """
        return self._float_registers

    @property
    def flag_registers(self):
        """ """
        return self._flag_registers

    @property
    def instructions(self):
        """ """
        return self._instructions

    @property
    def scratch_var(self):
        """ """
        return self._scratch_var

    @property
    def registers(self):
        """ """
        return self._registers

    @property
    def target(self):
        """ """
        return self._target

    def normalize_asm(self, mnemonic, operands):
        """ """
        return mnemonic, operands

    def set_target(self, target):
        """

        :param target:

        """
        self._target = target

    def __str__(self):
        """ """
        return "ISA Name: %s - %s" % (self.name, self.description)

    def new_instruction(self, name):
        """

        :param name:

        """
        ins_type = self.instructions[name]
        return microprobe.code.ins.instruction_factory(ins_type)

    def full_report(self):
        """ """
        rstr = "-" * 80 + "\n"
        rstr += "ISA Name: %s\n" % self.name
        rstr += "ISA Description: %s\n" % self.name
        rstr += "-" * 80 + "\n"
        rstr += "Register Types:\n"
        for regt in set([reg.type for reg in self.registers.values()]):
            rstr += str(regt) + "\n"
        rstr += "-" * 80 + "\n"
        rstr += "Architected registers:\n"
        for regname in self.registers:
            rstr += str(self.registers[regname]) + "\n"
        rstr += "-" * 80 + "\n"
        rstr += "Instructions:\n"
        for ins_name in self.instructions:
            rstr += str(self.instructions[ins_name].full_report()) + "\n"

        rstr += "\n Instructions defined: %s \n" % \
            len(set([ins.mnemonic for ins in self.instructions.values()]))

        rstr += " Variants defined: %s \n" % len(self.instructions)
        rstr += "-" * 80 + "\n"
        return rstr

    def set_register(self, reg, value, context):
        """

        :param reg:
        :param value:
        :param context:

        """
        raise MicroprobeCodeGenerationError(
            "Unable to set register '%s' to "
            " value '%d'." % (reg.name, value)
        )

    @property
    def scratch_registers(self):
        """ """
        return self._scratch_registers

    @property
    def control_registers(self):
        """ """
        return self._control_registers

    def get_register_for_address_arithmetic(self, context):
        """

        :param context:

        """
        reg = [
            reg
            for reg in self._address_registers
            if reg not in context.reserved_registers
        ]

        if len(reg) == 0:
            raise MicroprobeCodeGenerationError(
                "No free registers available. "
                "Change your policy."
            )

        # REG0 tends to have special meaning and it is usually at the
        # beginning, move it
        reg = reg[1:] + [reg[0]]
        return reg[0]

    def get_register_for_float_arithmetic(self, context):
        """

        :param context:

        """
        reg = [
            reg
            for reg in self._float_registers
            if reg not in context.reserved_registers
        ]

        assert len(reg) > 0, "All registers for floats already reserved"

        # REG0 tends to have special meaning and it is usually at the
        # beginning, move it
        reg = reg[1:] + [reg[0]]
        return reg[0]

    def add_to_register(self, register, value):
        """

        :param register:
        :param value:

        """
        super(GenericISA, self).add_to_register(register, value)

    def branch_unconditional_relative(self, source, target):
        """

        :param source:
        :param target:

        """
        return super(GenericISA, self).branch_unconditional_relative(
                source, target)

    def branch_to_itself(self):
        instr = self.branch_unconditional_relative(
            InstructionAddress(
                base_address="code"
            ),
            InstructionAddress(
                base_address="code"
            )
        )
        instr.set_address(None)
        return instr

    def get_dat(self, **kwargs):
        """ """
        return GenericDynamicAddressTranslation(self, **kwargs)

    def set_context(self, variable=None, tmpl_path=None):
        """ """

        if variable is None:
            variable = self.context_var

        if variable.size < self.context_var.size:
            raise MicroprobeCodeGenerationError(
                "Variable '%s' is too small to restore the target context"
            )

        asm = open(os.path.join(tmpl_path, "setcontext.S")).readlines()

        if len(asm) == 0:
            return []

        reg = self._scratch_registers[0]
        instrs = self.set_register_to_address(reg, variable.address, Context())

        return instrs + \
            microprobe.code.ins.instructions_from_asm(asm, self.target)

    def get_context(self, variable=None, tmpl_path=None):
        """ """

        if variable is None:
            variable = self.context_var

        if variable.size < self.context_var.size:
            raise MicroprobeCodeGenerationError(
                "Variable '%s' is too small to save the target context"
            )

        asm = open(os.path.join(tmpl_path, "getcontext.S")).readlines()

        if len(asm) == 0:
            return []

        reg = self._scratch_registers[0]
        instrs = self.set_register_to_address(reg, variable.address, Context())

        return instrs + \
            microprobe.code.ins.instructions_from_asm(asm, self.target)

    def register_value_comparator(self, comp):
        """ """
        raise NotImplementedError

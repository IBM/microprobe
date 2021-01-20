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
""":mod:`microprobe.passes.initialization` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules

# Third party modules
from six.moves import zip

# Own modules
import microprobe.code
import microprobe.passes
from microprobe.code.ins import instruction_set_def_properties
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeDuplicatedValueError
from microprobe.utils.asm import interpret_asm
from microprobe.utils.cmdline import print_warning
from microprobe.utils.ieee import ieee_float_to_int64
from microprobe.utils.logger import get_logger

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = [
    'AutoAlignPass',
    'AddInitializationAssemblyPass',
    'AddFinalizationAssemblyPass',
    'AddInitializationInstructionsPass',
    'InitializeRegistersPass',
    'InitializeRegisterPass',
    'ReserveRegistersPass',
    'UnReserveRegistersPass',
]

# Functions


# Classes
class AddInitializationAssemblyPass(microprobe.passes.Pass):
    """AddInitializationAssemblyPass pass.

    """

    def __init__(self, assembly, allow_registers=None):
        """

        :param assembly:
        :type assembly:
        """

        super(AddInitializationAssemblyPass, self).__init__()
        self._asm = assembly
        self._aregs = allow_registers

        self._description = "Append the '%s' instructions at the init of the"\
            "building block." % ";".join(assembly)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        instructions_def = interpret_asm(self._asm.split("\n"), target,
                                         building_block.labels)

        instructions = []
        for definition in instructions_def:
            instruction = microprobe.code.ins.Instruction()
            instruction_set_def_properties(instruction,
                                           definition,
                                           building_block=building_block,
                                           target=target,
                                           allowed_registers=self._aregs)
            instructions.append(instruction)

        building_block.add_init(instructions)


class AddFinalizationAssemblyPass(microprobe.passes.Pass):
    """AddFinalizationAssemblyPass pass.

    """

    def __init__(self, assembly, allow_registers=None):
        """

        :param assembly:
        :type assembly:
        """

        super(AddFinalizationAssemblyPass, self).__init__()
        self._asm = assembly
        self._aregs = allow_registers

        self._description = "Append the '%s' instructions at the init of the"\
            "building block." % ";".join(assembly)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        instructions_def = interpret_asm(
            self._asm.split("\n"), target, building_block.labels
        )

        instructions = []
        for definition in instructions_def:
            instruction = microprobe.code.ins.Instruction()
            instruction_set_def_properties(
                instruction,
                definition,
                building_block=building_block,
                target=target,
                allowed_registers=self._aregs
            )
            instructions.append(instruction)

        building_block.add_fini(instructions)


class ReserveRegistersPass(microprobe.passes.Pass):
    """ReserveRegistersPass pass.

    """

    def __init__(self, register_names):
        """

        :param register_names:
        :type register_names:
        """

        super(ReserveRegistersPass, self).__init__()
        self._register_names = register_names
        self._description = "Reserve registers '%s'" \
                            % (self._register_names)

    def __call__(self, building_block, target):

        for register_name in self._register_names:
            try:
                register = target.registers[register_name]
            except KeyError:
                raise MicroprobeCodeGenerationError(
                    "Unknown register '%s'. Known registers: %s" %
                    (register_name, list(target.registers.keys())))
            building_block.context.add_reserved_registers([register])


class UnReserveRegistersPass(microprobe.passes.Pass):
    """UnReserveRegistersPass pass.

    """

    def __init__(self, register_names):
        """

        :param register_names:
        :type register_names:
        """

        super(UnReserveRegistersPass, self).__init__()
        self._register_names = register_names
        self._description = "Reserve registers '%s'" \
                            % (self._register_names)

    def __call__(self, building_block, target):

        for register_name in self._register_names:
            try:
                register = target.registers[register_name]
            except KeyError:
                raise MicroprobeCodeGenerationError(
                    "Unknown register '%s'. Known registers: %s" %
                    (register_name, list(target.registers.keys())))
            building_block.context.remove_reserved_registers([register])


class InitializeRegistersPass(microprobe.passes.Pass):
    """InitializeRegistersPass pass.

    """

    def __init__(self, *args, **kwargs):
        """

        :param value:  (Default value = None)
        :param fp_value:  (Default value = None)
        :param v_value:  (Default value = None)

        """
        super(InitializeRegistersPass, self).__init__()

        value = kwargs.get("value", None)
        fp_value = kwargs.get("fp_value", None)
        v_value = kwargs.get("v_value", None)
        skip_unknown = kwargs.get("skip_unknown", False)
        warn_unknown = kwargs.get("warn_unknown", False)
        self._force_code = kwargs.get("force_code", False)

        if len(args) == 1:
            self._reg_dict = dict([
                (elem.name, elem.value) for elem in args[0]
            ])
            self._priolist = [elem.name for elem in args[0]]
        else:
            self._reg_dict = {}
            self._priolist = []

        self._value = value
        self._fp_value = fp_value
        self._vect_value = None
        self._vect_elemsize = None
        self._skip_unknown = skip_unknown
        self._warn_unknown = warn_unknown
        self._force_reserved = kwargs.get("force_reserved", False)
        self._skip_control = kwargs.get("skip_control", False)

        if v_value is not None:
            self._vect_value, self._vect_elemsize = v_value

        self._description = "Initialize general registers to: " \
                            " '%s' and FP registers to '%s' and" \
                            " Vector register to '%s' " % (self._value,
                                                           self._fp_value,
                                                           v_value)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        if not self._skip_unknown:
            for register_name in self._reg_dict:
                if register_name not in list(target.registers.keys()):
                    raise MicroprobeCodeGenerationError(
                        "Unknown register name: '%s'. Unable to set it" %
                        register_name)

        if self._warn_unknown:
            for register_name in self._reg_dict:
                if register_name not in list(target.registers.keys()):
                    print_warning(
                        "Unknown register name: '%s'. Unable to set it" %
                        register_name)

        regs = sorted(target.registers.values(),
                      key=lambda x: self._priolist.index(x.name)
                      if x.name in self._priolist else 314159)

        for reg in regs:

            value = None
            elemsize = None
            force_direct = False

            if reg.name in self._reg_dict:
                value = self._reg_dict[reg.name]
                self._reg_dict.pop(reg.name)
                force_direct = True

            if (reg in building_block.context.reserved_registers and
                    not self._force_reserved):
                LOG.debug("Skip reserved - %s", reg)
                continue
            elif (reg in target.control_registers and
                    (value is None or self._skip_control)):
                LOG.debug("Skip control - %s", reg)
                continue

            if value is None:
                if reg.used_for_vector_arithmetic:
                    if self._vect_value is not None:
                        value = self._vect_value
                        elemsize = self._vect_elemsize
                    else:
                        LOG.debug("Skip no vector default value provided - %s",
                                  reg)
                        continue
                elif reg.used_for_float_arithmetic:
                    if self._fp_value is not None:
                        value = self._fp_value
                    else:
                        LOG.debug("Skip no float default value provided - %s",
                                  reg)
                        continue
                else:
                    if self._value is not None:
                        value = self._value
                    else:
                        LOG.debug("Skip no default value provided - %s", reg)
                        continue

                while callable(value):
                    value = value()

                if reg.used_for_float_arithmetic:

                    value = ieee_float_to_int64(float(value))

                elif reg.used_for_vector_arithmetic:
                    if isinstance(value, float):
                        if elemsize != 64:
                            raise MicroprobeCodeGenerationError(
                                "Unable to initialize '%s' to '%s'. Only 64bit"
                                " vector element initialization is supported" %
                                (reg.name, (value, elemsize)))
                        value = ieee_float_to_int64(float(value))
                        value = "%d_%d" % (value, elemsize)
                    else:
                        value = "%d_%d" % (value, elemsize)

            LOG.debug("Setting reg %s to val %s", reg, value)

            if (target.wrapper.direct_initialization_support and
                    not self._force_code):
                try:
                    target.wrapper.register_direct_init(
                        reg, value, force=force_direct
                    )
                    if isinstance(value, str):
                        LOG.debug("Direct set of '%s' to '%s'", reg, value)
                    else:
                        LOG.debug("Direct set of '%s' to '0x%x'", reg, value)
                except MicroprobeCodeGenerationError:
                    building_block.add_init(target.set_register(
                        reg, value, building_block.context))
                    LOG.debug("Set '%s' to '0x%x'", reg, value)
                except MicroprobeDuplicatedValueError:
                    LOG.debug("Skip already set - %s", reg)
            else:
                building_block.add_init(target.set_register(
                    reg, value, building_block.context))
            building_block.context.set_register_value(reg, value)

    def check(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        raise NotImplementedError


class InitializeRegisterPass(microprobe.passes.Pass):
    """InitializeRegisterPass pass.

    """

    def __init__(self,
                 register_name,
                 value,
                 reserve=None,
                 force=False,
                 force_code=False,
                 force_control=False):
        """

        :param register_name:
        :param value:
        :param reserve:  (Default value = False)

        """
        super(InitializeRegisterPass, self).__init__()
        self._value = value
        self._register_name = register_name
        self._reserve = reserve
        self._force = force
        self._force_code = force_code
        self._force_control = force_control

        self._description = "Initialize register '%s' to " \
                            "'%s'" % (self._register_name, self._value)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        reg = [
            reg
            for reg in target.registers.values()
            if reg.name == self._register_name
        ][0]

        value = self._value

        if (reg in building_block.context.reserved_registers and
                self._reserve):
            raise MicroprobeCodeGenerationError("Register '%s' already"
                                                " reserved" % str(reg))

        if reg in target.control_registers and self._force_control is False:
            raise MicroprobeCodeGenerationError(
                "Register '%s' in Target definition control"
                " registers" % str(reg))

        if callable(value):
            value = value()

        if reg.used_for_float_arithmetic:
            value = ieee_float_to_int64(float(value))

        if (target.wrapper.direct_initialization_support and
                not self._force_code):
            target.wrapper.register_direct_init(reg, value, force=self._force)
        else:
            building_block.add_init(target.set_register(
                reg, value, building_block.context))

        building_block.context.set_register_value(reg, value)

        if (self._reserve is not False and
                reg not in building_block.context.reserved_registers):
            building_block.context.add_reserved_registers([reg])

    def check(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        raise NotImplementedError


class AddInitializationInstructionsPass(microprobe.passes.Pass):
    """AddInitializationInstructionsPass pass.

    """

    def __init__(self, instr, operands):
        """

        :param instr:
        :param operands:

        """
        super(AddInitializationInstructionsPass, self).__init__()
        self._instr = instr
        self._operands = operands
        self._description = "Add %s in the init sequence with " \
            "operands: %s" % (instr, operands)

        # TODO: improve description string

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for instr, operands in zip(self._instr, self._operands):
            newinstr = microprobe.code.ins.Instruction()
            # print instr
            # print self._instr
            newinstr.set_arch_type(instr)
            newinstr.set_operands(operands)
            # print operands
            building_block.add_init([newinstr])


class AutoAlignPass(microprobe.passes.Pass):
    """AutoAlignPass pass.

    """

    def __init__(self, instr, operands, mod):
        """

        :param instr:
        :type instr:
        :param operands:
        :type operands:
        :param mod:
        :type mod:
        """
        super(AutoAlignPass, self).__init__()
        self._instr = instr
        self._operands = operands
        self._mod = mod
        self._description = "Align the loop to be module '%s' using '%s'" \
            " instruction with '%s' operands" % (mod, instr, operands)

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        displacement = building_block.init[-1].address.displacement
        while ((displacement) % self._mod) != 0:
            for instr, operands in zip(self._instr, self._operands):
                newinstr = microprobe.code.ins.Instruction()
                newinstr.set_arch_type(instr)
                newinstr.set_operands(operands)

                displacement += newinstr.format.length
                if ((displacement) % self._mod) == 0:
                    break

                building_block.add_init([newinstr])

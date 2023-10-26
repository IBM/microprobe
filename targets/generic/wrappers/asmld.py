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
This is the asm module documentation
"""
# Futures
from __future__ import absolute_import

# Built-in modules
import itertools
from typing import List, Union
from random import Random

# Own modules
import microprobe.code.wrapper
from microprobe.code.context import Context
from microprobe.code.ins import Instruction
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import getnextf
from microprobe.utils.ieee import ieee_float_to_int64
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.utils.typeguard_decorator import typeguard_testsuite
from microprobe.code.var import Variable, VariableArray
from microprobe.target import Target

# Constants
LOG = get_logger(__name__)
__all__ = ["AsmLd"]

# Functions


# Classes
@typeguard_testsuite
class AsmLd(microprobe.code.wrapper.Wrapper):
    """:class:`Wrapper` to generate assembly (.s) files."""

    def __init__(
        self,
        init_code_address: int = 0x0000100000,
        init_data_address: int = 0x0010000000,
    ):
        """Initialization abstract method."""
        super(AsmLd, self).__init__()
        self._current_address = None
        self._instr_ant: Union[Instruction, None] = None
        self._init_code_address = init_code_address
        self._init_data_address = init_data_address

    def outputname(self, name: str):
        """

        :param name:

        """
        if not name.endswith(".s"):
            return "%s.s" % name
        return name

    def headers(self):
        """ """
        return "# MICROPROBE LD @SECTIONS { \n"

    def post_var(self):
        """ """
        return ""

    def declare_global_var(self, var: Variable):
        """

        :param var:

        """

        section_name = ".data.microprobe.data.%s" % var.name

        section_address = var.address.displacement

        if var.address.base_address == "code":
            section_address += 0
        elif var.address.base_address == "data":
            section_address += 0
        else:
            section_address = None
            # raise NotImplementedError(str(var.address))

        # make sure we always have the same state
        random = Random()
        random.seed(10)

        assert isinstance(var, VariableArray)

        if var.array():
            typesize = var.size // var.elems
        else:
            typesize = var.size

        str_fmt = "%%0%dx" % (typesize * 2)

        myvalue = var.value
        if myvalue is None:
            if var.array():
                myvalue = [
                    random.randint(0, (2**(typesize * 8) - 1))
                    for elem in range(0, var.elems)
                ]
            else:
                myvalue = random.randint(0, (2**(typesize * 8) - 1))

        if not var.array():
            if not isinstance(myvalue, list):
                value = myvalue
            else:
                LOG.warning(
                    "Multiple initial values specified for a "
                    "single element variable. Var: '%s'", var)
                value = myvalue[0]
            values = [value]
        else:
            elems = var.size // typesize
            if not isinstance(myvalue, list):
                values = [myvalue] * elems
            else:
                values = (myvalue * ((len(myvalue) // elems) + 1))[0:elems]

        for idx, value in enumerate(values):
            if callable(value):
                value = value()
            if isinstance(value, float):
                values[idx] = ieee_float_to_int64(value)
                assert var.type in ["float", "double"]
            elif isinstance(value, int):
                values[idx] = value
            else:
                raise MicroprobeCodeGenerationError(
                    "Unable to initialize variable var: '%s' "
                    "to value '%s'" % (myvalue, type(myvalue)))

        value_str = "".join([str_fmt % value for value in values])
        value_list = [
            "0x%s" % value_str[i:i + 2] for i in range(0, len(value_str), 2)
        ]
        value_str = ".byte %s" % ",".join(value_list)

        astr: List[str] = []
        if False:
            if var.array():

                value = var.value
                if var.value is not None:
                    value = [0]

                valuestr = ""

                if not isinstance(value, list):
                    value = [value]

                get_value = getnextf(itertools.cycle(value))

                for dummy_idx in range(var.elems):
                    value = get_value()
                    if callable(value):
                        value = value()
                    valuestr = "%s%s," % (valuestr, value)

            else:

                value = var.value
                if var.value is not None:
                    value = 0

                valuestr = ".byte 0x%x" % value

        if section_address is not None:
            astr.append("# MICROPROBE LD @    %s 0x%X : { *(%s) }  " %
                        (section_name, section_address, section_name))
        else:
            astr.append("# MICROPROBE LD @    %s : { *(%s) }  " %
                        (section_name, section_name))
        astr.append(".section %s" % section_name)
        astr.append(".global %s" % var.name)
        astr.append("%s:" % var.name)
        astr.append("%s\n" % value_str)

        return "\n".join(astr)

    def init_global_var(self, dummy_var, dummy_value):
        """

        :param dummy_var:
        :param dummy_value:

        """
        return ""

    def required_global_vars(self):
        """ """
        return []

    def start_main(self):
        """ """
        return ".text\n"

    def start_loop(self,
                   dummy_instr,
                   dummy_instr_reset,
                   dummy_aligned: bool = True):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        return ""

    def wrap_ins(self, instr: Union[str, Instruction]):
        """

        :param instr:

        """
        ins: List[str] = []

        if isinstance(instr, str):
            return (instr)

        section_address = None
        if instr.address is not None and self._current_address is None:

            if instr.address.base_address not in ['code']:
                raise NotImplementedError

            self._current_address = instr.address.displacement + \
                self._init_code_address
            section_address = self._current_address

        elif instr.address is not None and self._current_address is not None:

            if instr.address.base_address not in ['code']:
                raise NotImplementedError

            self._current_address = self._current_address + \
                self._instr_ant.architecture_type.format.length

            if self._current_address != (instr.address.displacement +
                                         self._init_code_address):
                section_address = instr.address.displacement + \
                    self._init_code_address
                self._current_address = section_address
            else:
                section_address = None

        if section_address is not None:
            assert section_address > 0
        if self._current_address is not None:
            assert self._current_address > 0

        if section_address:
            section_name = ".text.microprobe.code.%016X" % section_address
            ins.append("# MICROPROBE LD @    %s 0x%X : { *(%s) }  " %
                       (section_name, section_address, section_name))
            ins.append(".section %s" % section_name)

        if len(self.benchmark.init) > 0:
            if instr == self.benchmark.init[0]:
                ins.append(".global main")
                ins.append(".type   main, @function")
                ins.append("main:")
        else:
            if instr == self.benchmark.cfg.bbls[0].instrs[0]:
                ins.append(".global main")
                ins.append(".type   main, @function")
                ins.append("main:")

        if instr.name == "raw" or instr.disable_asm or instr.unsupported:
            asm_list: List[str] = []
            if instr.label is not None:
                asm_list.append(instr.label + ":")

            fmtstr = "%%0%dx" % (len(instr.binary()) / 4)
            hstr = fmtstr % int(instr.binary(), 2)

            if self.target.isa.name.startswith("power"):
                asm_list.append(".byte " + ",".join([
                    "0x%s" % hstr[idx:idx + 2]
                    for idx in reversed(range(2, len(hstr), 2))
                ]))
            else:
                asm_list.append(".byte " + ",".join([
                    "0x%s" % hstr[idx:idx + 2]
                    for idx in reversed(range(0, len(hstr), 2))
                ]))
            asm = " ".join(asm_list)
        else:
            asm = instr.assembly()

        if instr.comments:
            bstr = " " * len(asm) + " /* "

            for idx, comment in enumerate(instr.comments):
                if idx == 0:
                    asm = asm + " /* " + comment + " */ "
                else:
                    asm = asm + "\n" + bstr + comment + " */ "
            ins.append(asm)
        else:
            ins.append(asm)

        if (self.target.isa.name == "riscv_v22"):
            # GCC will sometimes translate regular instructions to compressed
            # instructions. Because we want to reproduce the instruction
            # sequence verbatim, put a rv/norvc directive before each
            # instruction to prevent GCC from using the wrong instruction.

            if instr.architecture_type.mnemonic.startswith("C."):
                ins.insert(len(ins) - 1, ".option rvc")
            else:
                ins.insert(len(ins) - 1, ".option norvc")

        self._instr_ant = instr

        ins_str = "\n".join(ins)
        return ins_str + "\n"

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """
        return ""

    def footer(self):
        """ """
        return "# MICROPROBE LD @} \n"

    def end_main(self):
        """ """
        return ""

    def infinite(self):
        """ """
        return False

    def reserved_registers(self, dummy_reserved, dummy_target: Target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

    def context(self):
        """ """

        context = Context()
        context.set_code_segment(self._init_code_address)
        context.set_data_segment(self._init_data_address)
        context.set_symbolic(True)
        # context.set_absolute(True)

        return context

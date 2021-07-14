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
This is the asm module documentation
"""
# Futures
from __future__ import absolute_import

# Built-in modules
import itertools

# Own modules
import microprobe.code.wrapper
from microprobe.code.ins import Instruction, MicroprobeInstructionDefinition
from microprobe.code.address import InstructionAddress
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import getnextf


# Constants
LOG = get_logger(__name__)
__all__ = ["Assembly"]

# Functions

# Classes


class Assembly(microprobe.code.wrapper.Wrapper):
    """:class:`Wrapper` to generate assembly (.s) files."""

    def __init__(self, sections=[], start_label=None):
        """Initialization abstract method."""
        super(Assembly, self).__init__()
        self._sections = sections
        self._start_label = start_label
        self._padding_page_str = ".byte %s" % ",".join(["0" for i in range(4096)])
        self._last_address = None

    def outputname(self, name):
        """

        :param name:

        """
        if not name.endswith(".s"):
            return "%s.s" % name
        return name

    def headers(self):
        """ """
        return ""

    def post_var(self):
        """ """
        return ""

    def declare_global_var(self, var):
        """

        :param var:

        """

        align = var.align
        if align is None or align is 0:
            align = ""
        else:
            align = ".align %d" % align

        if var.array():

            if var.value is not None:

                valuestr = ""

                value = var.value
                if not isinstance(value, list):
                    value = [value]

                get_value = getnextf(itertools.cycle(value))

                for dummy_idx in range(var.elems):
                    value = get_value()
                    if callable(value):
                        value = value()
                    valuestr = "%s%s," % (valuestr, value)

                address = int(var.name[4:], 16)

                retval = ""

                if self._last_address != None and (address - self._last_address <= 4096 * 8):
                    # Add up to 8 pages for padding to reduce sections
                    for i in range(self._last_address + 4096, address, 4096):
                        retval += self._padding_page_str + "\n"
                else:
                    retval += ".section .data.%s\n.global %s\n%s:\n" % (
                            var.name, var.name, var.name
                    )

                self._last_address = address

                retval += ".byte %s\n" % valuestr[:-1]

                return retval

        else:

            if var.value is not None:

                return ".section .data.%s\n.global %s\n%s:\n.byte %s\n" % (
                    var.name, var.name, var.name, var.value
                )

        return "# Unhandled variable: %s\n" % var.name

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
        return "\n.text\n.global _start\n_start:"

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=True):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        return ""

    def wrap_ins(self, instr):
        """

        :param instr:

        """
        ins = []

        if isinstance(instr, str):
            return(instr)

        asm = instr.assembly()

        if instr.architecture_type.mnemonic == "raw":
            parts = asm.split(" ")
            bytes_str = ["0x" + parts[1][i-2:i] for i in range(len(parts[1]), 2, -2)]
            asm = ".byte " + ",".join(reversed(bytes_str))

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

        directives = ""

        # Section directive
        if instr.address is not None and instr.address.displacement in self._sections:
            section_name = ".text.%s" % hex(instr.address.displacement)
            directives += "\n.section %s\n" % section_name

        if self.target.isa.name == "riscv_v22" and self.target.environment.name == "riscv64_linux_gcc":
            # GCC will sometimes translate regular instructions to compressed
            # instructions. Because we want to reproduce the instruction
            # sequence verbatim, put a rv/norvc directive before each
            # instruction to prevent GCC from using the wrong instruction.

            if instr.architecture_type.mnemonic.startswith("C."):
                directives += ".option rvc\n"
            else:
                directives += ".option norvc\n"

        return directives + ins[0] + "\n"

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """
        return ""

    def footer(self):
        """ """
        return ""

    def end_main(self):
        """ """
        return ""

    def infinite(self):
        """ """
        return False

    def reserved_registers(self, dummy_reserved, dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

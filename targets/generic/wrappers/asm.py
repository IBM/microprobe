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
from typing import List, Union
from microprobe.code.ins import Instruction

# Own modules
import microprobe.code.wrapper
from microprobe.utils.logger import get_logger
from microprobe.utils.typeguard_decorator import typeguard_testsuite
from microprobe.target import Target

# Constants
LOG = get_logger(__name__)
__all__ = ["Assembly"]

# Functions

# Classes


@typeguard_testsuite
class Assembly(microprobe.code.wrapper.Wrapper):
    """:class:`Wrapper` to generate assembly (.s) files."""

    def __init__(self):
        """Initialization abstract method."""
        super(Assembly, self).__init__()

    def outputname(self, name: str):
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

        :param dummy_var:

        """
        return ""

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
        return ""

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

        if instr.comments:
            asm = instr.assembly()
            bstr = " " * len(asm) + " /* "

            for idx, comment in enumerate(instr.comments):
                if idx == 0:
                    asm = asm + " /* " + comment + " */ "
                else:
                    asm = asm + "\n" + bstr + comment + " */ "
            ins.append(asm)
        else:
            ins.append(instr.assembly())

        if (self.target.isa.name == "riscv_v22"):
            # GCC will sometimes translate regular instructions to compressed
            # instructions. Because we want to reproduce the instruction
            # sequence verbatim, put a rv/norvc directive before each
            # instruction to prevent GCC from using the wrong instruction.

            if instr.architecture_type.mnemonic.startswith("C."):
                ins[0] = ".option rvc\n" + ins[0]
            else:
                ins[0] = ".option norvc\n" + ins[0]

        return ins[0] + "\n"

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

    def reserved_registers(self, dummy_reserved, dummy_target: Target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

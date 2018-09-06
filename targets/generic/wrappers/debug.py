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
This is the debug module documentation
"""
# Futures
from __future__ import absolute_import

# Third party modules
from six.moves import range

# Own modules
import microprobe.code.wrapper
from microprobe.code.context import Context
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["DebugBinary", "DebugBinaryDouble"]

# Functions


# Classes
class DebugBinary(microprobe.code.wrapper.Wrapper):
    """ """

    def __init__(self, reset=None):
        """Initialization abstract method."""
        super(DebugBinary, self).__init__()
        self._reset = reset

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

    def declare_global_var(self, dummy_var):
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
        return ""

    def start_main(self):
        """ """
        return ""

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=True):
        """
        :param dummy_instr:
        :param dummy_aligned:  (Default value = True)

        """
        return ""

    def wrap_ins(self, instr):
        """

        :param instr:

        """
        ins = []
        binary = instr.binary()
        ins.append(
            "\n".join(
                [
                    ".byte 0x%02x" % int(
                        binary[i:i + 8], 2
                    ) for i in range(0, len(binary), 8)
                ]
            )
        )
        return "\n".join(ins)

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """
        return ""

    def footer(self):
        """ """
        return ""

    def post_var(self):
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

    def context(self):
        """ """

        context = Context()
        context.set_code_segment(0x100000)
        context.set_data_segment(0x200000)
        context.set_symbolic(False)
        return context


class DebugBinaryDouble(DebugBinary):
    """ """

    def wrap_ins(self, instr):
        """

        :param instr:

        """
        ins = []
        if not instr.disable_asm:
            ins.append(instr.assembly())

        binary = instr.binary()

        while len(binary) != 0:

            if len(binary) >= 8:

                mbinary = binary[0:8]
                binary = binary[8:]

                ins.append(
                    ".byte 0x%02x" % int(mbinary, 2)
                )

            else:

                raise NotImplementedError

        if instr.disable_asm:
            ins = ins + ins

        return "\n".join(ins) + "\n"

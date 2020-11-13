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
This is the bin module documentation
"""
# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import struct

# Third party modules
from six.moves import range

# Own modules
import microprobe.code.wrapper
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.context import Context
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = [
    "Binary",
]

# Functions


# Classes
class Binary(microprobe.code.wrapper.Wrapper):
    """:class:`Wrapper` to generate binary files (.bin).

    Binary files contain a stream of instructions codified in binary
    format.

    """

    def __init__(
        self,
        init_code_address=0x01500000,
        init_data_address=0x01600000,
        reset=False,
        dithering=0,
        endless=False,
        delay=0
    ):
        """Initialization abstract method.

        :param init_code_address:  (Default value = None)
        :param init_data_address:  (Default value = None)
        :param reset:  (Default value = False)

        """
        super(Binary, self).__init__()
        self._init_code_address = init_code_address
        self._init_data_address = init_data_address
        self._start_address = None
        self._reset_state = reset
        self._dithering = dithering
        self._delay = delay
        self._endless = endless
        self._init_loop_pad = None

    def outputname(self, name):
        """

        :param name:

        """
        if not name.endswith(".bin"):
            return "%s.bin" % name
        return name

    def headers(self):
        """ """
        return ""

    def post_var(self):
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
        return []

    def start_main(self):
        """ """
        return ""

    def start_loop(self, instr, instr_reset, dummy_aligned=True):
        """

        :param instr:
        :param instr_reset:
        :param dummy_aligned:  (Default value = True)

        """
        if self.reset:
            if self._start_address is None:
                self._start_address = instr_reset
        else:
            self._start_address = instr

        instrs = []
        for dummy in range(0, self._delay):
            instrs.append(self.target.nop())

        if not instrs:
            return b''

        binall = self.wrap_ins(instrs[0])
        for elem in instrs[1:]:
            binall += self.wrap_ins(elem)

        return binall

    def init_loop_pad(self):
        """ """

        if self._init_loop_pad is None:
            nop = self.target.nop()
            nop.set_address(Address(base_address="code"))
            self.start_loop(nop, nop)

        if self._init_loop_pad is None:
            self._init_loop_pad = 0

        return self._init_loop_pad

    def wrap_ins(self, instr):
        """

        :param instr:

        """
        ins = []

        binary = instr.binary()

        for elem in [binary[i:i + 16] for i in range(0, len(binary), 16)]:

            elem_endian = elem
            new_elem = int(elem_endian, 2)
            ins.append(struct.pack('>H', new_elem))

        LOG.debug("%s:%s -> %s", instr.address, instr.assembly(), ins)

        binall = ins[0]
        for elem in ins[1:]:
            binall += elem

        return binall

    def end_loop(self, instr):
        """

        :param instr:

        """

        padding = 0
        instrs = []
        for dummy in range(0, self._dithering):
            instrs.append(self.target.nop())
            padding += self.target.nop().architecture_type.format.length

        source = InstructionAddress(
            base_address="code",
            displacement=instr.address.displacement + padding +
            instr.architecture_type.format.length
        )

        if self._endless:
            branch = self.target.branch_unconditional_relative(
                source, self._start_address
            )
            instrs.append(branch)

        end = [self.wrap_ins(elem) for elem in instrs]

        if len(end) == 0:
            return []

        endall = end[0]
        for elem in end[1:]:
            endall += elem
        return endall

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

    def context(self):
        """ """

        context = Context()
        context.set_code_segment(self._init_code_address)
        context.set_data_segment(self._init_data_address)
        context.set_symbolic(False)
        context.set_absolute(True)

        return context

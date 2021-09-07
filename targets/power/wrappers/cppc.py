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
This is the c module documentation
"""

# Futures
from __future__ import absolute_import, division

# Built-in modules
import os

# Third party modules
from six.moves import range

# Own modules
from microprobe.code import get_wrapper
from microprobe.utils.logger import get_logger

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
LOG = get_logger(__name__)
__all__ = ["CInfPpc", "CInfPpcSingleLiteral", "CLoopPpc", "CSpecialPpc"]
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

# Functions


# Classes
class CInfPpc(get_wrapper("CWrapper")):
    """A wrapper for the C language with an infinite loop specific for PPC
    architecture.


    """

    def __init__(self):
        super(CInfPpc, self).__init__()
        self._loop_label = None

    def start_loop(self, instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param instr:
        :param dummy_aligned:  (Default value = False)

        """
        if instr.label is None:
            instr.set_label("infloop")

        self._loop_label = instr.label

        return ""

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """

        loop = []
        loop.append(self.wrap_ins("b %s" % self._loop_label))
        return "\n".join(loop)

    def infinite(self):  # pylint: disable=no-self-use
        """ """
        return True

    def reserved_registers(self,  # pylint: disable=no-self-use
                           dummy_reserved,
                           dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []


class CInfPpcSingleLiteral(get_wrapper("CWrapper")):
    """A wrapper for the C language with an infinite loop specific for PPC
    architecture.


    """

    def start_loop(self, instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param instr:
        :param dummy_aligned:  (Default value = False)

        """
        self._loop = 1
        loop = []
        loop.append("__asm__(")
        instr.set_label("infloop")
        return "\n".join(loop)

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """
        loop = []
        loop.append(self.wrap_ins("b infloop"))
        loop.append(");")
        return "\n".join(loop)

    def infinite(self):  # pylint: disable=no-self-use
        """ """
        return True

    def reserved_registers(self,  # pylint: disable=no-self-use
                           dummy_reserved,
                           dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

    def wrap_ins(self, instr):
        """

        :param instr:

        """
        if self._loop:
            ins = ["\""]
            ins.append(instr.assembly())
            ins.append("\\n\"")
            return " ".join(ins)
        else:
            ins = []
            ins.append("__asm__(\"")
            ins.append(instr.assembly())
            ins.append("\");")
            return " ".join(ins)


class CLoopPpc(get_wrapper("CWrapper")):
    """A wrapper for the C language with a loop with n iterations specific
    for PPC architecture.

    """

    def __init__(self, size):
        """

        :param size:

        """
        super(CLoopPpc, self).__init__()
        self._size = int(size)

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        loop = []
        loop.append(self.wrap_ins("li 0, %s" % self._size))
        loop.append(self.wrap_ins("mtctr 0"))
        loop.append(self.wrap_ins("infloop:"))
        return "\n".join(loop)

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """
        loop = []
        loop.append(self.wrap_ins("bdnz+ infloop"))
        return "\n".join(loop)

    def infinite(self):  # pylint: disable=no-self-use
        """ """
        return False

    def reserved_registers(self, dummy_reserved, dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        raise NotImplementedError
        # return [microprobe.arch.ppc._powerpc_CTR]


class CSpecialPpc(get_wrapper("CWrapper")):
    """A wrapper for the C language specfific for PPC architecture, special for
    some experiments.


    """

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        # special prologue
        loop = []
        loop.append(self.wrap_ins("li 3, 0"))
        loop.append(self.wrap_ins("infloop:"))
        return "\n".join(loop)

    def end_loop(self, dummy_instr):
        """

        :param dummy_instr:

        """
        # special epilogue
        loop = []
        loop.append(self.wrap_ins("addi 3,3,1"))
        loop.append(self.wrap_ins("mfspr 4, 1023"))
        loop.append(self.wrap_ins("andi. 4, 4, 3"))
        loop.append(self.wrap_ins("slwi 4, 4, 3"))
        loop.append(self.wrap_ins("ori 4, 4, 0x20"))
        loop.append(self.wrap_ins("mtspr 276,4"))
        loop.append(self.wrap_ins("isync"))
        loop.append(self.wrap_ins("mtspr 277,3"))
        loop.append(self.wrap_ins("isync"))
        loop.append(self.wrap_ins("b infloop"))
        return "\n".join(loop)

    def infinite(self):  # pylint: disable=no-self-use
        """ """
        return True

    def reserved_registers(self,  # pylint: disable=no-self-use
                           dummy_reserved,
                           dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        # reserved registers
        # raise NotImplementedError
        rlist = []
        # rlist.append(microprobe.arch.ppc._powerpc_registers["GPR3"])
        # rlist.append(microprobe.arch.ppc._powerpc_registers["GPR4"])
        # rlist.append(microprobe.arch.ppc._powerpc_registers["GPR10"])
        # rlist.append(microprobe.arch.ppc._powerpc_registers["GPR11"])
        # rlist.append(microprobe.arch.ppc._powerpc_registers["GPR12"])
        return rlist

    def declare_global_var(self, var):  # pylint: disable=no-self-use
        """

        :param var:

        """
        # declaration without alignment
        if var.array():
            return "extern THREAD %s[%d];\n" % (var.name, var.size)
        else:
            return "extern THREAD %s;\n" % (var.name)

    def headers(self):  # pylint: disable=no-self-use
        """ """
        # the special header you wanted
        header = []
        header.append('#include "common.h"')
        return "\n".join(header)

    def init_global_var(self,  # pylint: disable=no-self-use
                        dummy_var,
                        dummy_value):
        """

        :param dummy_var:
        :param dummy_value:

        """
        # No initializations at all
        return ""

    def start_main(self):
        """ """
        main = []
        main.append("void %s(u64* parm_array)" % self._name)
        main.append("{")
        return "\n".join(main)

    def __init__(self, name):
        """

        :param name:

        """
        super(CSpecialPpc, self).__init__()
        self._max_array_var = None
        self._max_array_var_value = None
        self._name = name


class CPSynchStepMultithread(get_wrapper("CWrapper")):

    """ """

    def __init__(
        self, synctype,
        steps,
        bias,
        dithering=0,
        delay=0,
        master_delay=0,
        reset=False
    ):
        """

        :param synctype:
        :param steps:
        :param bias:
        :param dithering:  (Default value = 0)

        """

        super(CPSynchStepMultithread, self).__init__(reset=reset)

        self._synctype = synctype
        self._steps = steps
        self._bias = bias
        self._dithering = dithering
        self._delay = delay
        self._master_delay = master_delay

        with open(
                os.path.join(
                    _MODULE_DIR, "CPSynchStepMultithread.headers"
                ),
                'r') as textfile:

            for header in textfile.readlines():
                self._extra_headers.append(header[:-1])

    def headers(self):
        """ """
        header = []
        for elem in self._extra_headers:
            header.append(elem)
        return "\n".join(header)

    def start_main(self):
        """ """

        main = [super(CPSynchStepMultithread, self).start_main()]

        with open(
                os.path.join(
                    _MODULE_DIR, "CPSynchStepMultithread.start_main"
                ),
                'r') as textfile:

            for elem in textfile.readlines():
                main.append(elem[:-1])

        return "\n".join(main)

    def post_var(self):
        """

        """
        mstr = [self.wrap_ins(ins) for ins in self.target.get_context()]
        if self._reset:
            mstr.append(self.wrap_ins("infloop:"))
        return "".join(mstr)

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        loop = []

        if not self._reset:
            loop.append(self.wrap_ins("infloop:"))

        with open(
                os.path.join(
                    _MODULE_DIR, "CPSynchStepMultithread.start_loop"
                ),
                'r') as textfile:

            for elem in textfile.readlines():
                loop.append(elem[:-1])

        treplace = []
        if self._synctype == '4ms':
            treplace.append(("$SYNCHMASK1$", "MASK_4US_1"))
            treplace.append(("$SYNCHMASK2$", "MASK_4US_2"))
        else:
            treplace.append(("$SYNCHMASK1$", "MASK_1S_1"))
            treplace.append(("$SYNCHMASK2$", "MASK_1S_2"))

        treplace.append(("$SYNCHBIAS$", str(self._bias)))

        treplace.append(("$MASTERSTEPS$",
                         self.wrap_ins("li 0, %s" % max(self._steps // 2, 1))))
        treplace.append(("$SLAVESTEPS$",
                         self.wrap_ins("li 0, %s" % self._steps)))

        master_delay = []
        for dummy_idx in range(0, self._master_delay):
            master_delay.append(self.wrap_ins(self.target.nop())[:-1])
        master_delay = "\n".join(master_delay)

        treplace.append(("$MASTERDELAY$", master_delay))

        delay = []
        for dummy_idx in range(0, self._delay):
            delay.append(self.wrap_ins(self.target.nop())[:-1])
        delay = "\n".join(delay)

        treplace.append(("$DELAY$", delay))

        for idx, line in enumerate(loop):
            for orig, new in treplace:
                line = line.replace(orig, new)
                loop[idx] = line

        loop.append(self.wrap_ins("mtctr 0"))
        loop.append(self.wrap_ins("steploop:"))

        return "\n".join(loop)

    def outputname(self, name):  # pylint: disable=no-self-use
        """

        :param name:

        """
        if not name.endswith(".c"):
            return "%s.c" % name
        return name

    def end_loop(self, dummy_ins):
        """

        :param dummy_ins:

        """

        instr_list = []

        for dummy in range(0, self._dithering):
            instr_list.append(self.wrap_ins(self.target.nop()))

        instr_list.extend([self.wrap_ins("bdnz+ steploop"),
                           self.wrap_ins("b infloop")])

        return "\n".join(instr_list)

    def reserved_registers(self, reserved, target):
        """

        :param reserved:
        :param target:

        """

        reserved = super(
            CPSynchStepMultithread, self
        ).reserved_registers(
            reserved, target
        )

        reserved.append(target.registers["GPR1"])
        reserved.append(target.registers["GPR9"])
        reserved.append(target.registers["GPR30"])
        reserved.append(target.registers["GPR31"])
        reserved.append(target.registers["GPR2"])
        reserved.append(target.registers["GPR8"])
        reserved.append(target.registers["GPR10"])

        return reserved

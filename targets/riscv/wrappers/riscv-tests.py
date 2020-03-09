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
# Futures
from __future__ import absolute_import


# Own modules
from microprobe.code import get_wrapper
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["RiscvTestsP"]

# Functions


# Classes
class RiscvTestsP(get_wrapper("Assembly")):

    def __init__(self, endless=False, reset=False):
        self._endless = endless
        self._reset = reset
        super(RiscvTestsP, self).__init__()

    def headers(self):
        return """\

/* Headers */
#include "riscv_test.h"
#include "riscv-tests/isa/macros/scalar/test_macros.h"

"""

    def start_main(self):
        return """\

/* Start Main */
RVTEST_RV64UF
RVTEST_CODE_BEGIN

"""

    def outputname(self, name):
        """

        :param name:

        """
        if not name.endswith(".S"):
            return "%s.S" % name
        return name

    def post_var(self):
        return "".join("reset:")

    def start_loop(self, instr, instr_reset, dummy_aligned=True):
        """

        :param instr:
        :param instr_reset:
        :param dummy_aligned:  (Default value = True)

        """

        start_loop = ["/* Building block start */\n"]
        if not self._endless:
            return "\n".join(start_loop)

        if self._reset:
            instr_reset.add_comment("Loop start reseting")
            if not instr_reset.label:
                instr_reset.set_label("reset")
                self._loop_label = "reset"
            else:
                self._loop_label = instr_reset.label

        else:
            instr.add_comment("Loop start")
            if not instr.label:
                instr.set_label("infloop")
                self._loop_label = "infloop"
            else:
                self._loop_label = instr.label

        return "\n".join(start_loop)

    def end_loop(self, dummy_instr):
        """
        """
        if not self._endless:
            return "/* Loop End */"

        loop = ["/* Loop End */"]
        loop.append(self.wrap_ins("j %s" % self._loop_label))
        return "\n".join(loop)

    def end_main(self):
        return """\

/* End Main */
  TEST_CASE( 1, x0, 0, nop )
  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END

"""

    def declare_global_var(self, var):
        if var.align:
            return ".comm %s, %d, %d\n" % (var.name, var.size, var.align)
        else:
            return ".comm %s, %d\n" % (var.name, var.size)

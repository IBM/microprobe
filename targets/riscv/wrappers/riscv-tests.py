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


class RiscvTestsP(get_wrapper("Assembly")):
    def start_main(self):
        return """\
#include "riscv_test.h"
#include "riscv-tests/isa/macros/scalar/test_macros.h"

RVTEST_RV64UF
RVTEST_CODE_BEGIN
"""

    def end_main(self):
        return """\
  TEST_CASE( 1, x0, 0, nop )
  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END"""

    def outputname(self, name):
        if not name.endswith(".S"):
            return "%s.S" % name
        return name

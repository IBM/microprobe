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
docstring ${module}
"""
# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import os
from tempfile import SpooledTemporaryFile, mkstemp
from typing import Union
from unittest import TestCase, main, skipIf

# Own modules
import microprobe

import subprocess

# Constants
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)


# Classes
class c2mpt(TestCase):  # pylint: disable=invalid-name
    """
    c2mpt Test Class.
    """
    _multiprocess_can_split_ = True

    name = "mp_c2mpt"
    description = "mp_c2mpt tool tests"
    cmd = [
        os.path.join(BASEPATH, "targets", "generic", "tools", "mp_c2mpt.py")
    ]
    target = os.path.join(BASEPATH, "targets")
    trials = 3

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        tempfile = mkstemp(prefix="microprobe_%s_" % self.name, suffix=".mpt")
        os.close(tempfile[0])
        os.unlink(tempfile[1])
        self.filenames = [tempfile[1]]

    def tearDown(self):

        for filename in [
                fname for fname in self.filenames if os.path.isfile(fname)
        ]:
            os.unlink(filename)

    @skipIf(MP_TESTING_ARCH != "RISCV", "TBD: Enable test")
    @skipIf(MP_TESTING_ARCH is not None, "Long testing")
    def test_001(self):
        """
        c2mpt_test001 on riscv_v22-riscv_generic-riscv64_linux_gcc
        """
        self._wrapper(
            "riscv_v22-riscv_generic-riscv64_linux_gcc",
            os.path.join(BASEPATH, "targets", "generic", "tests", "tools",
                         "c2mpt_test001.c"),
        )

    @skipIf(MP_TESTING_ARCH != "RISCV", "TBD: Enable test")
    @skipIf(MP_TESTING_ARCH is not None, "Long testing")
    def test_002(self):
        """
        c2mpt_test002 on riscv_v22-riscv_generic-riscv64_linux_gcc
        """
        self._wrapper(
            "riscv_v22-riscv_generic-riscv64_linux_gcc",
            os.path.join(BASEPATH, "targets", "generic", "tests", "tools",
                         "c2mpt_test002.c"))

    def _wrapper(self,
                 target: str,
                 filename: str,
                 extra: Union[str, None] = None):
        """
        Common execution wrapper
        """

        test_cmd = self.cmd[:]

        if extra is not None:
            test_cmd.extend(extra.split(' '))

        test_cmd.extend(["-T", target])
        test_cmd.extend(["-P", self.target])
        test_cmd.extend(["-i", filename])
        test_cmd.extend(["-O", self.filenames[0]])

        if "riscv" in target:
            test_cmd.extend([
                "--target-c-compiler",
                os.environ.get("MP_TESTING_COMPILER_RISCV",
                               "riscv64-linux-gnu-gcc")
            ])
            test_cmd.extend([
                "--target-objdump",
                os.environ.get("MP_TESTING_COMPILER_RISCV",
                               "riscv64-linux-gnu-gcc").replace(
                                   "gcc", "objdump")
            ])
        print(" ".join(test_cmd))

        for trial in range(0, self.trials):
            print("Trial %s" % trial)
            tfile = SpooledTemporaryFile()
            error_code = subprocess.call(test_cmd,
                                         stdout=tfile,
                                         stderr=subprocess.STDOUT)
            if error_code == 0:
                break

        if error_code != 0:
            tfile.seek(0)
            print(tfile.read())

        self.assertEqual(error_code, 0)


TEST_CLASSES = [c2mpt]

if __name__ == '__main__':
    main()

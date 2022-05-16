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
import shutil
from tempfile import SpooledTemporaryFile, mkdtemp
from unittest import TestCase, main, skipIf

# Third party modules
import six
from six.moves import range

# Own modules
import microprobe

if six.PY2:
    import subprocess32 as subprocess  # @UnresolvedImport @UnusedImport
else:
    import subprocess  # @Reimport


# Constants
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)


# Classes
class seqtune(TestCase):  # pylint: disable=invalid-name
    """
    seqtune Test Class.
    """
    _multiprocess_can_split_ = True

    name = "mp_seqtune"
    description = "mp_seqtune tool tests"
    cmd = [os.path.join(BASEPATH,
                        "targets", "generic", "tools", "mp_seqtune.py")]
    target = os.path.join(BASEPATH, "targets")
    trials = 3

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.tdirname = mkdtemp(prefix="microprobe_%s_" % self.name,
                                suffix=".seqtune")

    def tearDown(self):

        shutil.rmtree(self.tdirname, True)

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_001(self):
        """
        test_001 on riscv_v22-riscv_generic-riscv64_test_p
        """
        self._wrapper(
            "riscv_v22-riscv_generic-riscv64_test_p",
            extra="-B 1024 -re ADD_V0:XOR_V0:1-2 -p " +
            "-me 1-2:2048:1:144:1:0:1:0 " +
            "-seq ADD_V0,ADDI_V0,FMUL.S_V0,MULW_V0,LD_V0,SD_V0"
        )

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_002(self):
        """
        test_001 on riscv_v22-riscv_generic-riscv64_linux_gcc
        """
        self._wrapper(
            "riscv_v22-riscv_generic-riscv64_linux_gcc",
            extra="-B 1024 -re ADD_V0:XOR_V0:1-2 -p " +
            "-me 1-2:2048:1:144:1:0:1:0 " +
            "-seq ADD_V0,ADDI_V0,FMUL.S_V0,MULW_V0,LD_V0,SD_V0"
        )

    def _wrapper(self, target, extra=None):
        """
        Common execution wrapper
        """

        test_cmd = self.cmd[:]
        test_cmd.extend(["-T", target])
        test_cmd.extend(["-P", self.target])
        test_cmd.extend(["-D", self.tdirname])

        if extra is not None:
            extra = extra.strip()
            test_cmd.extend(extra.split(' '))

        print(" ".join(test_cmd))

        for trial in range(0, self.trials):
            print("Trial %s" % trial)
            tfile = SpooledTemporaryFile()
            error_code = subprocess.call(
                test_cmd,
                stdout=tfile,
                stderr=subprocess.STDOUT
            )
            if error_code == 0:
                break

        if error_code != 0:
            tfile.seek(0)
            print(tfile.read())

        self.assertEqual(error_code, 0)


TEST_CLASSES = [seqtune]

if __name__ == '__main__':
    main()

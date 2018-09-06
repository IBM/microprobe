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
docstring ${module}
"""
# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import os
from tempfile import SpooledTemporaryFile, mkstemp
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
class objdump2dma(TestCase):  # pylint: disable=invalid-name
    """objdump2dma test class."""

    _multiprocess_can_split_ = True

    name = "mp_objdump2dma"
    description = "mp_objdump2dma tool tests"
    cmd = [os.path.join(BASEPATH,
                        "targets", "generic", "tools", "mp_objdump2dma.py")]
    target = os.path.join(BASEPATH, "targets")
    trials = 3

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        tempfile = mkstemp(prefix="microprobe_%s_" % self.name, suffix=".dma")
        os.close(tempfile[0])
        os.unlink(tempfile[1])
        self.filenames = [tempfile[1]]

    def tearDown(self):

        for filename in [
            fname for fname in self.filenames if os.path.isfile(fname)
        ]:
            os.unlink(filename)

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_001(self):
        """
        objdump2dma_test001
        """
        self._wrapper(
            os.path.join(
                BASEPATH, "targets", "generic", "tests", "tools",
                "objdump2dma_test001.dump"
            )
        )

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_002(self):
        """
        objdump2dma_test002
        """
        self._wrapper(
            os.path.join(
                BASEPATH, "targets", "generic", "tests", "tools",
                "objdump2dma_test002.dump"
            )
        )

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_003(self):
        """
        objdump2dma_test003
        """
        self._wrapper(
            os.path.join(
                BASEPATH, "targets", "generic", "tests", "tools",
                "objdump2dma_test003.dump"
            )
        )

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_004(self):
        """
        objdump2dma_test004
        """
        self._wrapper(
            os.path.join(
                BASEPATH, "targets", "generic", "tests", "tools",
                "objdump2dma_test004.dump"
            )
        )

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_005(self):
        """
        objdump2dma_test005
        """
        self._wrapper(
            os.path.join(
                BASEPATH, "targets", "generic", "tests", "tools",
                "objdump2dma_test005.dump"
            )
        )

    def _wrapper(self, filename, extra=None):
        """
        Common execution wrapper
        """

        test_cmd = self.cmd[:]
        test_cmd.extend(["-i", filename])
        test_cmd.extend(["-O", self.filenames[0]])

        if extra is not None:
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


TEST_CLASSES = [objdump2dma]

if __name__ == '__main__':
    main()

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
import subprocess
from tempfile import SpooledTemporaryFile, mkstemp
from unittest import TestCase, main, skipIf

# Third party modules

# Own modules
import microprobe


__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)


# Classes
class objdump2mpt(TestCase):  # pylint: disable=invalid-name
    """
    objdump2mpt Test class
    """
    _multiprocess_can_split_ = True

    name = "mp_objdump2mpt"
    description = "mp_objdump2mpt tool tests"
    cmd = [
        os.path.join(BASEPATH, "targets", "generic", "tools",
                     "mp_objdump2mpt.py")
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

    @skipIf(True, "Too long test. Skip")
    @skipIf(MP_TESTING_ARCH not in ["POWER8"], "Long testing")
    def test_001(self):
        """
        objdump2mpt_test001 on power_v206-power8-ppc64_linux_gcc
        """
        self._wrapper(
            "power_v206-power8-ppc64_linux_gcc",
            os.path.join(BASEPATH, "targets", "power", "tests", "tools",
                         "objdump2mpt_test001.dump.gz"))

    @skipIf(MP_TESTING_ARCH not in [None, "POWER8"], "Long testing")
    def test_002(self):
        """
        objdump2mpt_test002 on power_v206-power8-ppc64_linux_gcc
        """
        self._wrapper("power_v206-power8-ppc64_linux_gcc",
                      os.path.join(BASEPATH, "targets", "power", "tests",
                                   "tools", "objdump2mpt_test002.dump"),
                      extra="--elf-abi --stack-size 2000 --stack-name my_test"
                      " -s microprobe.text")

    @skipIf(MP_TESTING_ARCH not in [None, "POWER8"], "Long testing")
    def test_003(self):
        """
        objdump2mpt_test003 on power_v206-power8-ppc64_linux_gcc
        """
        self._wrapper(
            "power_v206-power8-ppc64_linux_gcc",
            os.path.join(BASEPATH, "targets", "power", "tests", "tools",
                         "objdump2mpt_test003.dump"),
            extra="--elf-abi --stack-address 0x1234500 --start-symbol my_test"
            " -s microprobe.text")

    def _wrapper(self, target, filename, extra=None):
        """
        Common execution wrapper
        """

        test_cmd = self.cmd[:]
        test_cmd.extend(["-T", target])
        test_cmd.extend(["-P", self.target])
        test_cmd.extend(["-i", filename])
        test_cmd.extend(["-O", self.filenames[0]])

        if extra is not None:
            test_cmd.extend(extra.split(' '))

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


TEST_CLASSES = [objdump2mpt]

if __name__ == '__main__':
    main()

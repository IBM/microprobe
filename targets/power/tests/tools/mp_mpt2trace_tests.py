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
    # Third party modules
    import subprocess32 as subprocess  # @UnresolvedImport @UnusedImport
else:
    # Built-in modules
    import subprocess  # @Reimport

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
class mpt2trace(TestCase):  # pylint: disable=invalid-name
    """
    mpt2trace Test Class.
    """
    _multiprocess_can_split_ = True

    name = "mp_mpt2trace"
    description = "mp_mpt2trace tool tests"
    cmd = [
        os.path.join(BASEPATH, "targets", "power", "tools", "mp_mpt2trace.py")
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
        self.tdirname = mkdtemp(prefix="microprobe_%s_" % self.name,
                                suffix=".mpt2trace")

    def tearDown(self):

        shutil.rmtree(self.tdirname, True)

    @skipIf(MP_TESTING_ARCH not in [None, "POWER9"], "Long testing")
    def test_001(self):
        """
        test_001 on power_v300-power9-ppc64_linux_gcc
        """
        self._wrapper("power_v300-power9-ppc64_linux_gcc",
                      "mpt2trace_test001.mpt",
                      "output.qt",
                      extra="--default-memory-access-pattern 0x1234")

    @skipIf(MP_TESTING_ARCH not in [None, "POWER9"], "Long testing")
    def test_002(self):
        """
        test_002 on power_v300-power9-ppc64_linux_gcc
        """
        self._wrapper("power_v300-power9-ppc64_linux_gcc",
                      "mpt2trace_test002.mpt",
                      "output.qt.gz",
                      extra="--default-memory-access-pattern 0x1234")

    @skipIf(MP_TESTING_ARCH not in [None, "POWER9"], "Long testing")
    def test_003(self):
        """
        test_003 on power_v300-power9-ppc64_linux_gcc
        """
        self._wrapper("power_v300-power9-ppc64_linux_gcc",
                      "mpt2trace_test003.mpt",
                      "output.qt.bz2",
                      extra="--default-memory-access-pattern 0x1234")

    def _wrapper(self, target, testfile, output, extra=None):
        """
        Common execution wrapper
        """

        test_cmd = self.cmd[:]
        test_cmd.extend(["-T", target])
        test_cmd.extend(["-P", self.target])
        test_cmd.extend(["-O", os.path.join(self.tdirname, output)])
        test_cmd.extend([
            "-t",
            os.path.join(BASEPATH, "targets", "power", "tests", "tools",
                         testfile)
        ])

        if extra is not None:
            extra = extra + " --max-trace-size 100"
            extra = extra.strip()
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


TEST_CLASSES = [mpt2trace]

if __name__ == '__main__':
    main()

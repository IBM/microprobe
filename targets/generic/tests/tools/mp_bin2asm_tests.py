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
from tempfile import SpooledTemporaryFile
from unittest import TestCase, main, skipIf

# Own modules
import microprobe

import subprocess

# Constants
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)


# Classes
class bin2asm(TestCase):  # pylint: disable-msg=invalid-name
    """
    bin2asm test class
    """

    _multiprocess_can_split_ = True

    name = "mp_bin2asm"
    description = "mp_bin2asm tool tests"
    cmd = [
        os.path.join(BASEPATH, "targets", "generic", "tools", "mp_bin2asm.py")
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
        pass

    def tearDown(self):
        pass

    @skipIf(MP_TESTING_ARCH is not None, "Long testing")
    def test_001(self):
        """
        bin2asm_test001 test
        """
        self._wrapper("none", "none", extra="-h")

    def _wrapper(self, target, filename, extra=None):
        """
        Common execution wrapper
        """

        test_cmd = self.cmd[:]

        if extra is not None:
            test_cmd.extend(extra.split(' '))

        test_cmd.extend(["-T", target])
        test_cmd.extend(["-P", self.target])
        test_cmd.extend(["-i", filename])

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


TEST_CLASSES = [bin2asm]

if __name__ == '__main__':
    main()

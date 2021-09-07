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
import copy
import os
import types
from tempfile import SpooledTemporaryFile
from unittest import TestCase, main

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


def copy_func(f, name=None):
    return types.FunctionType(f.__code__, copy.copy(f.__globals__),
                              name or f.__name__,
                              f.__defaults__, f.__closure__)


# Classes
TARGETS = []
if MP_TESTING_ARCH is None:
    TARGETS = [
        'riscv_v22-riscv_generic-riscv64_linux_gcc',
    ]
elif MP_TESTING_ARCH == "RISCV":
    TARGETS = ['riscv_v22-riscv_generic-riscv64_linux_gcc']

TCLASSES = []
for target in TARGETS:

    targetname = target.replace("-", "_")

    class TestTargetQuery(TestCase):
        """
        Generic TestTargetQuery Class
        """

        _multiprocess_can_split_ = True

        name = "mp_target"
        description = "mp_target tool tests"
        cmd = [os.path.join(BASEPATH,
                            "targets", "generic", "tools", "mp_target.py")]
        targetpath = os.path.join(BASEPATH, "targets")
        trials = 3

        def __init__(self, methodName='runTest'):
            # pylint: disable=E1003
            super(self.__class__, self).__init__(methodName=methodName)
            self.target = getattr(self, methodName).__doc__.split("'")[1]

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

        def run_cmd(self, extra):
            """

            :param extra:
            :type extra:
            """
            test_cmd = self.cmd[:]
            test_cmd.extend(["-T", self.target])
            test_cmd.extend(["-P", self.targetpath])

            if extra is not None:
                test_cmd.extend(extra.split(" "))

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

    newclass = type(
        "mp_target_%s" % targetname, TestTargetQuery.__bases__,
        dict(TestTargetQuery.__dict__)
    )

    globals().pop("TestTargetQuery")

    # Add regular query
    fname = "test_full_report"

    def test_function(self):
        """
        Test function
        """
        return self.run_cmd(None)

    setattr(newclass, fname, copy_func(test_function, fname))

    if six.PY2:
        mfunc = getattr(getattr(newclass, fname), "__func__")
    else:
        mfunc = getattr(newclass, fname)

    setattr(mfunc, "__doc__", "mp_target - full report of '%s' " % target
            )
    mfunc.__name__ = fname

    globals().pop("mfunc")
    globals().pop("fname")
    globals().pop("test_function")

    TCLASSES.append(
        type(
            "mp_target_%s" % targetname, newclass.__bases__, dict(
                newclass.__dict__
            )
        )
    )
    globals().pop("newclass")

for tclass in TCLASSES:
    globals()[tclass.__name__] = tclass

if "tclass" in globals():
    globals().pop("tclass")

if __name__ == '__main__':
    main()

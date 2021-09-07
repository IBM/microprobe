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
import itertools
import os
import types
from tempfile import SpooledTemporaryFile, mkstemp
from unittest import TestCase, main

# Third party modules
import six
from six.moves import range

# Own modules
import microprobe
from microprobe.target import import_definition

if six.PY2:
    import subprocess32 as subprocess  # @UnresolvedImport @UnusedImport
else:
    import subprocess  # @Reimport


# Constants
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)
MP_CI = os.environ.get("TRAVIS", None)


def copy_func(f, name=None):
    return types.FunctionType(f.__code__, copy.copy(f.__globals__),
                              name or f.__name__,
                              f.__defaults__, f.__closure__)


def variations(basestr, params):
    """

    :param basestr:
    :type basestr:
    :param params:
    :type params:
    """
    tvariation = itertools.product(*params)
    return [
        basestr + " " + " ".join([elem2 for elem2 in elem if elem2 != ""])
        for elem in tvariation
    ]


def subins(instructions):
    """

    :param instructions:
    :type instructions:
    """

    if MP_TESTING_ARCH is not None and MP_CI is None:
        return instructions

    myins = []

    for instr in instructions:
        if instr.format not in [ins.format for ins in myins]:
            myins.append(instr)
            continue

    #    if str(instr.instruction_checks) not in [
    #            str(ins.instruction_checks) for ins in myins]:

    #        myins.append(instr)
    #        continue

    #    if str(instr.target_checks) not in [
    #            str(ins.target_checks) for ins in myins]:

    #        myins.append(instr)
    #        continue

    #    if str(instr.operands) not in [
    #            str(ins.operands) for ins in myins]:

    #        myins.append(instr)
    #        continue

    return myins


# Classes
class epi(TestCase):  # pylint: disable-msg=invalid-name
    """
    epi test class
    """

    _multiprocess_can_split_ = True

    name = "mp_epi"
    description = "mp_epi tool tests"
    cmd = [os.path.join(BASEPATH, "targets", "generic", "tools", "mp_epi.py")]
    target = os.path.join(BASEPATH, "targets")
    trials = 3

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        tempfile = mkstemp(prefix="microprobe_%s_" % self.name)
        os.close(tempfile[0])
        os.unlink(tempfile[1])
        self.filename = tempfile[1]

    def tearDown(self):
        if os.path.isfile(self.filename):
            os.unlink(self.filename)

    def wrapper(self, target, oformat, instr, extra=None):
        """
        Common execution wrapper
        """

        self.filename = "%s.%s" % (self.filename, oformat)

        test_cmd = self.cmd[:]
        test_cmd.extend(["-T", target])
        test_cmd.extend(["-P", self.target])
        test_cmd.extend(["-O", self.filename])
        test_cmd.extend(["-ins", instr])

        if extra is not None:
            test_cmd.extend(extra.split(' '))

        test_cmd = [elem for elem in test_cmd if elem != ""]

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

        if oformat == "bin":

            print("Checking BIN...")

            test_cmd = [os.path.join(BASEPATH, "targets", "generic", "tools",
                                     "mp_bin2objdump.py")]
            test_cmd.extend(['-T', target])
            test_cmd.extend(['-i', self.filename])
            test_cmd.append("-S")

            tfile = SpooledTemporaryFile()

            error_code = subprocess.call(
                test_cmd,
                stdout=tfile,
                stderr=subprocess.STDOUT
            )

            if error_code != 0:
                tfile.seek(0)
                print(tfile.read())

            self.assertEqual(error_code, 0)


TEST_TARGETS = []

if MP_TESTING_ARCH is None:
    _PARAM1 = ['']
    _PARAM2 = ['']
    _PARAM3 = ['-B 5']

    TEST_TARGETS.append(("riscv_v22-riscv_generic-riscv64_linux_gcc",
                         "c",
                         ["C.FSDSP_V0", "C.JALR_V0", "C.LDSP_V0",
                          "C.LWSP_V0", "C.LW_V0", "C.SWSP_V0",
                          "C.SDSP_V0", "JALR_V0"]))
    TEST_TARGETS.append(("riscv_v22-riscv_generic-riscv64_test_p",
                         "S",
                         ["C.FSDSP_V0", "C.JALR_V0", "C.LDSP_V0",
                          "C.LWSP_V0", "C.LW_V0", "C.SWSP_V0",
                          "C.SDSP_V0", "JALR_V0"]))
else:
    _PARAM1 = ['', '-dd 1']
    _PARAM2 = ['', '-R']
    _PARAM3 = ['-B 5']

    if MP_TESTING_ARCH == "RISCV":
        TEST_TARGETS.append(("riscv_v22-riscv_generic-riscv64_linux_gcc",
                             "c",
                             ["C.FSDSP_V0", "C.JALR_V0", "C.LDSP_V0",
                              "C.LWSP_V0", "C.LW_V0", "C.SWSP_V0",
                              "C.SDSP_V0", "JALR_V0"]))
        TEST_TARGETS.append(("riscv_v22-riscv_generic-riscv64_test_p",
                             "S",
                             ["C.FSDSP_V0", "C.JALR_V0", "C.LDSP_V0",
                              "C.LWSP_V0", "C.LW_V0", "C.SWSP_V0",
                              "C.SDSP_V0", "JALR_V0"]))

TEST_FLAGS = []
TEST_FLAGS.extend(
    variations("", [_PARAM1, _PARAM2, _PARAM3])
)

_TEST_NUMBER = 1
for _TEST_TARGET in TEST_TARGETS:

    _TARGET = import_definition(_TEST_TARGET[0])

    for _TEST_INSTR in [
        my_instr.name for my_instr in subins(
            list(_TARGET.isa.instructions.values()))]:

        if _TEST_INSTR in _TEST_TARGET[2]:
            continue

        for _TEST_FLAG in TEST_FLAGS:

            def test_function(self):
                """ test_function """
                self.wrapper(
                    _TEST_TARGET[0],
                    _TEST_TARGET[1],
                    _TEST_INSTR,
                    extra=_TEST_FLAG)

            func_name = "test_%s_%03d" % (
                _TEST_INSTR.replace(".", "x"), _TEST_NUMBER)
            func_doc = "epi_test_%s_%03d on %s flags: %s" % (
                _TEST_INSTR.replace(".", "x"), _TEST_NUMBER, _TEST_TARGET[0],
                _TEST_FLAG)

            setattr(epi, func_name, copy_func(test_function, func_name))

            if six.PY2:
                mfunc = getattr(getattr(epi, func_name), "__func__")
            else:
                mfunc = getattr(epi, func_name)

            setattr(mfunc, "__doc__", func_doc)
            mfunc.__name__ = func_name

            globals().pop("mfunc")
            globals().pop("test_function")
            _TEST_NUMBER += 1


TEST_CLASSES = [epi]

if __name__ == '__main__':
    main()

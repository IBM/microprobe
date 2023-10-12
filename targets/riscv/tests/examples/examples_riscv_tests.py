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
import ctypes
import os
import shutil
import signal
import time
from tempfile import SpooledTemporaryFile, mkdtemp
from typing import List
from unittest import TestCase, main, skipIf

# Own modules
import microprobe

# Built-in modules
import subprocess

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)
if MP_TESTING_ARCH is not None:
    if MP_TESTING_ARCH.startswith("RISCV"):
        MP_TESTING_ARCH = "RISCV"
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
_LIBC = ctypes.CDLL("libc.so.6")


def _get_child_processes(parent_pid: int) -> List[str]:
    ps_command = subprocess.Popen("ps -o pid --ppid %d --noheaders" %
                                  parent_pid,
                                  shell=True,
                                  stdout=subprocess.PIPE)
    ps_output = ps_command.stdout.read()
    retcode = ps_command.wait()
    if retcode == 1:
        return []
    elif retcode == 0:
        if isinstance(ps_output, bytes):
            ps_output = ps_output.decode()
        pids = ps_output.split("\n")[:-1]
        for pid_str in ps_output.split("\n")[:-1]:
            pids += _get_child_processes(int(pid_str))
        return pids
    else:
        return []


def _kill_child_processes(parent_pid: int,
                          sig: signal.Signals = signal.SIGKILL):

    pids = _get_child_processes(parent_pid)

    for pid_str in pids:

        try:
            os.kill(int(pid_str), sig)
        except IOError:
            print(f"unable to kill: {pid_str}")
            continue


def _set_pdeathsig(sig: signal.Signals = signal.SIGKILL):

    def function():
        """
        Kill process function
        """
        return _LIBC.prctl(1, sig)

    return function


# Classes
class riscv_example_suite(TestCase):  # pylint: disable=invalid-name
    """
    riscv_example_suite Test Class.
    """
    _multiprocess_can_split_ = True
    _multiprocess_shared_ = False

    name = "riscv_example"
    description = "riscv example tests"
    target = os.path.join(BASEPATH, "targets")
    trials = 3
    timeout = 20  # in seconds

    def _dir(self, arch: str = 'riscv'):
        return f"{BASEPATH}/targets/{arch}/examples/"

    def setUp(self):
        tempdir = mkdtemp(prefix=f"microprobe_examples_{self.name}_",
                          suffix=".example")
        self.dirnames = [tempdir]

    def tearDown(self):
        for dirname in self.dirnames:
            shutil.rmtree(dirname)

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_001(self):
        """
        riscv_example_suite: riscv_branch.py
        """
        self._wrapper([self._dir() + 'riscv_branch.py'])

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_002(self):
        """
        riscv_example_suite: riscv_ipc_c.py
        """
        self._wrapper([self._dir() + 'riscv_ipc_c.py'])

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_003(self):
        """
        riscv_example_suite: riscv_ipc_seq.py
        """
        self._wrapper([self._dir() + 'riscv_ipc_seq.py'])

    @skipIf(MP_TESTING_ARCH not in [None, "RISCV"], "Long testing")
    def test_004(self):
        """
        riscv_example_suite: riscv_ipc.py
        """
        self._wrapper([self._dir() + 'riscv_ipc.py'])

    def _wrapper(self, commands: List[str]):
        """
        Common execution wrapper
        """

        print(" ".join(commands))

        error_code = None
        tfile = None

        for _ in range(0, self.trials):
            tfile = SpooledTemporaryFile()
            process = subprocess.Popen(commands,
                                       stdout=tfile,
                                       stderr=subprocess.STDOUT,
                                       preexec_fn=_set_pdeathsig(
                                           signal.SIGTERM))
            ctime = 0

            while ctime < self.timeout:

                error_code = process.poll()

                if error_code is None:
                    time.sleep(0.1)
                    ctime += 0.1
                else:
                    break

            if error_code == 0:
                break
            elif error_code is None:
                try:
                    _kill_child_processes(process.pid)
                    process.kill()
                except OSError:
                    # Maybe the process already finished
                    pass
                error_code = 0
                break

        if error_code is None or tfile is None:
            raise ValueError("No riscv trials specified for testing.")

        if error_code != 0:
            tfile.seek(0)
            print(tfile.read())

        self.assertEqual(error_code, 0)


TEST_CLASSES = [riscv_example_suite]

if __name__ == '__main__':
    main()

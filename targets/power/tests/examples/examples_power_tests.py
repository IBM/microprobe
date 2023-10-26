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
import subprocess
from tempfile import SpooledTemporaryFile, mkdtemp
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
MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)
if MP_TESTING_ARCH is not None:
    if MP_TESTING_ARCH.startswith("POWER"):
        MP_TESTING_ARCH = "POWER"
BASEPATH = os.path.join(os.path.dirname(microprobe.__file__), "..", "..")
_LIBC = ctypes.CDLL("libc.so.6")


def _get_child_processes(parent_pid):
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


def _kill_child_processes(parent_pid, sig=signal.SIGKILL):

    pids = _get_child_processes(parent_pid)

    for pid_str in pids:

        try:
            os.kill(int(pid_str), sig)
        except IOError:
            print("unable to kill: %s" % pid_str)
            continue


def _set_pdeathsig(sig=signal.SIGKILL):

    def function():
        """
        Kill process function
        """
        return _LIBC.prctl(1, sig)

    return function


# Classes
class power_example_suite(TestCase):  # pylint: disable=invalid-name
    """
    Power_example_suite Test Class.
    """
    _multiprocess_can_split_ = True
    _multiprocess_shared_ = False

    name = "power_example"
    description = "power example tests"
    target = os.path.join(BASEPATH, "targets")
    trials = 3
    timeout = 20  # in seconds

    def _dir(self, arch='power'):
        return "%s/targets/%s/examples/" % (BASEPATH, arch)

    def setUp(self):
        tempdir = mkdtemp(prefix="microprobe_examples_%s_" % self.name,
                          suffix=".example")
        self.dirnames = [tempdir]

    def tearDown(self):
        for dirname in self.dirnames:
            shutil.rmtree(dirname)

    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_001(self):
        """
        power_example_suite: isa_power_v206_info.py
        """
        self._wrapper([self._dir() + 'isa_power_v206_info.py'])

    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_002(self):
        """
        power_example_suite: power_v206_power7_ppc64_linux_gcc_profile.py
        """
        self._wrapper([
            self._dir() + 'power_v206_power7_ppc64_linux_gcc_profile.py', '-p',
            '1', '-O', self.dirnames[0]
        ])

    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_003(self):
        """
        power_example_suite: power_v206_power7_ppc64_linux_gcc_fu_stress.py
        """
        self._wrapper([
            self._dir() + 'power_v206_power7_ppc64_linux_gcc_fu_stress.py',
            '-O', self.dirnames[0]
        ])

    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_004(self):
        """
        power_example_suite: power_v206_power7_ppc64_linux_gcc_memory.py
        """
        self._wrapper([
            self._dir() + 'power_v206_power7_ppc64_linux_gcc_memory.py',
            self.dirnames[0]
        ])

    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_005(self):
        """
        power_example_suite: power_v206_power7_ppc64_linux_gcc_random.py
        """
        self._wrapper([
            self._dir() + 'power_v206_power7_ppc64_linux_gcc_random.py',
            self.dirnames[0]
        ])

    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_006(self):
        """
        power_example_suite: power_v206_power7_ppc64_linux_gcc_custom.py
        """
        self._wrapper([
            self._dir() + 'power_v206_power7_ppc64_linux_gcc_custom.py',
            self.dirnames[0]
        ])

    @skipIf(True, "Deprecated (removing PyEvolve)")
    @skipIf(MP_TESTING_ARCH not in [None, "POWER"], "Long testing")
    def test_007(self):
        """
        power_example_suite: power_v206_power7_ppc64_linux_gcc_genetic.py
        """
        self._wrapper([
            self._dir() + 'power_v206_power7_ppc64_linux_gcc_genetic.py',
            self.dirnames[0],
            '%s/genetic_eval.sh' % self._dir('power')
        ])

    def _wrapper(self, commands):
        """
        Common execution wrapper
        """

        print(" ".join(commands))

        for dummy_trial in range(0, self.trials):
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

        if error_code != 0:
            tfile.seek(0)
            print(tfile.read())

        self.assertEqual(error_code, 0)


TEST_CLASSES = [power_example_suite]

if __name__ == '__main__':
    main()

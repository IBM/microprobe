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
""":mod:`microprobe.utils.run` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import shlex
import subprocess

# Third party modules
import six
from six.moves import range

# Own modules
from microprobe.exceptions import MicroprobeCalledProcessError, \
    MicroprobeRunCmdError
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["run_cmd", "run_cmd_output", "run_cmd_output_redirect"]


# Functions
def run_cmd(scmd, trials=1, _return_output=False):

    cmd = shlex.split(scmd)
    for dummy in range(0, trials):
        error_code, cmd_output = _run(cmd)
        if error_code == 0:
            break

    if error_code is not 0:
        raise MicroprobeRunCmdError(
            "Command '%s' non-zero return code.\nOutput:\n%s" % (
                scmd, cmd_output
            )
        )

    if _return_output:
        if six.PY2:
            return cmd_output.encode("ascii")
        elif six.PY3:
            return cmd_output.decode()


def run_cmd_output(cmd, trials=1):

    return run_cmd(cmd, trials=trials, _return_output=True)


def run_cmd_output_redirect(cmd, out_file, trials=1):

    file_fd = open(out_file, "w")
    output = run_cmd_output(cmd, trials=trials)
    file_fd.write(str(output))
    file_fd.close()


def _run(cmd):
    error_code = 0
    try:
        cmd_output = _check_output(cmd, stderr=subprocess.STDOUT)
    except MicroprobeCalledProcessError as exc:
        error_code = exc.returncode
        cmd_output = exc.output

    return error_code, cmd_output


def _check_output(*popenargs, **kwargs):

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    try:
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs,
                                   **kwargs)
    except OSError:
        raise MicroprobeCalledProcessError(
            -1, " ".join(popenargs[0]), "empty"
        )

    output, dummy_err = process.communicate()

    retcode = process.poll()
    if retcode:
        raise MicroprobeCalledProcessError(
            retcode, " ".join(popenargs[0]), output
        )
    return output

# Classes

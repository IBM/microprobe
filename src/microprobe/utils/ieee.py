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
""":mod:`microprobe.utils.ieee` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import struct

# Third party modules
import six

# Own modules
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["ieee_float_to_int64"]


# Functions
def ieee_float_to_int64(float_val):
    """convert float to binary string

    :param f:

    """
    binary = struct.pack('>d', float_val)

    if six.PY2:
        string = ''.join('{0:08b}'.format(ord(b)) for b in binary)
    elif six.PY3:
        string = ''.join('{0:08b}'.format(b) for b in binary)

    # strip off leading zeros
    for idx, char in enumerate(string):
        if char != '0':
            break
    else:  # all zeros
        string = '0'
        idx = 0
    return int(string[idx:], 2)

# Classes

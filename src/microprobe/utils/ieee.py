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
__all__ = ["ieee_float_to_int64", "float_to_nnp_data_type_1"]


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


def float_to_nnp_data_type_1(float_val):
    """convert float to nnp_data_type_1

    :param f:

    """

    # Format parameters
    fsize = 16
    bias = 31
    exponent_size = 6

    # Sign
    sign = ""
    if float_val > 0:
        sign += "0"
    else:
        sign += "1"

    real = abs(int(float_val))
    fraction = abs(float_val) - abs(real)

    assert real + fraction == abs(float_val)

    fraction_bits = []
    while fraction > 0:
        fraction = fraction * 2
        fraction_bits.append(int(fraction))
        fraction = fraction - int(fraction)

    fraction_bits = "".join(["%d" % bit for bit in fraction_bits])

    real_bits = bin(real)[2:]

    if real_bits[0] == "1":
        shift = len(real_bits) - 1
        fraction_bits = real_bits[1:] + fraction_bits
    else:
        shift = -1
        while fraction_bits[0] == "0":
            shift = shift - 1
            fraction_bits = fraction_bits[1:]
        fraction_bits = fraction_bits[1:]

    exponent = shift + bias
    expfmt = "{0:>0%db}" % exponent_size
    exponent = expfmt.format(exponent)

    bits = sign + exponent + fraction_bits
    bits = bits[0:fsize]
    while len(bits) < fsize:
        bits += "0"

    # Validation
    # vsignificand = "1" + bits[exponent_size+1:]
    # value = 0
    # bitvalue = 1
    # for bit in vsignificand:
    #     if bit == "1":
    #        value = value + bitvalue
    #    bitvalue = bitvalue / 2

    # vexponent = bits[1:exponent_size+1]
    # vexponent = int(vexponent, 2) - bias

    # print(vexponent)
    # print((2**vexponent)*value)

    # vsign = bits[0]

    assert len(bits) == fsize
    return int(bits, 2)

# Classes

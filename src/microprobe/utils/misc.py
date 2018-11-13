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
""":mod:`microprobe.utils.misc` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import bz2
import gzip
import itertools
import os
import random
import re
import sys
import timeit

# Third party modules

# Own modules
from microprobe.exceptions import MicroprobeDuplicatedValueError
from microprobe.utils.logger import get_logger

try:
    from collections import OrderedDict
except ImportError:
    # python 2.6 or earlier, use ordereddict back-port
    # pylint: disable-msg=F0401
    from ordereddict import OrderedDict


# Constants
LOG = get_logger(__name__)
__all__ = [
    "natural_sort", "dict2OrderedDict", "RejectingDict",
    "RejectingOrderedDict", "Pickable", "primes", "closest_divisor",
    "smart_copy_dict", "findfiles", "RNDINT", "RNDFP", "twocs_to_int",
    "int_to_twocs", "iter_flatten", "which", "Progress",
    "range_to_sequence", "longest_common_substr", "open_generic_fd",
    "getnextf"
]

_RND_SEED = 13  # My favorite number ;)
_RNDINT = random.Random()
_RNDINT.seed(_RND_SEED)

_RNDFP = random.Random()
_RNDFP.seed(_RND_SEED)


# Functions
def getnextf(itr):

    def next_function():
        return next(itr)

    return next_function


def natural_sort(input_list):
    """

    :param input_list:

    """

    def convert(text):
        """

        :param text:
        :type text:
        """
        if text.isdigit():
            return int(text)
        else:
            return text.lower()

    def alphanum_key(key):
        """

        :param key:
        :type key:
        """
        return [convert(c) for c in re.split('([0-9]+)', key)]

    return sorted(input_list, key=alphanum_key)


def dict2OrderedDict(my_dict):  # pylint: disable-msg=C0103
    """

    :param my_dict:

    """
    odict = OrderedDict()

    for key in natural_sort(list(my_dict.keys())):

        odict[key] = my_dict[key]

    return odict


def twocs_to_int(val, bits):
    """compute the int value of a two compliment int"""
    assert len(bin(val)) - 2 <= bits, (val, bits)  # check if it fits
    if (val & (1 << (bits - 1))) != 0:  # if sign bit is set -> 8bit: 128-255
        val = val - (1 << bits)  # compute negative value
    return val  # return positive value as is


def int_to_twocs(val, bits):
    """compute the two compliment of a int"""

    # check if it fits
    if val < 0:
        assert len(bin(val)) - 3 <= bits
    else:
        assert len(bin(val)) - 2 <= bits, "%s - %s" % (bin(val), bits)

    return int(bin(val & int('0b' + '1' * bits, 2)), 2)


def shift_with_sign(val, bits, shift):
    """shift value extending sign in twocs format"""

    # check if it fits
    if val < 0:
        assert len(bin(val)) - 3 <= bits
    else:
        assert len(bin(val)) - 2 <= bits

    ormask = int('1' * shift + '0' * (bits - shift), 2)
    mask = int('1' * bits, 2)
    return ((val >> shift) | ormask) & mask


def primes(number):
    """

    :param number:

    """

    primfac = []
    divisor = 2

    while divisor * divisor <= number:
        while (number % divisor) == 0:
            # supposing you want multiple factors repeated
            primfac.append(divisor)
            number /= divisor
        divisor += 1

    if number > 1:
        primfac.append(number)

    return primfac


def closest_divisor(target, closer):
    """

    :param target:
    :param closer:

    """

    mprimes = primes(int(target))
    value = 1

    for elem in reversed(mprimes):

        if value * elem > int(closer * 1.5):
            continue

        value = value * elem

    if value < (closer * 0.1):
        value = closer

    # print(target, mprimes, closer, value)
    return value


def smart_copy_dict(olddict):
    """

    :param olddict:

    """

    new_dict = {}
    if isinstance(olddict, RejectingDict):
        new_dict = RejectingDict()

    for key, value in olddict.items():

        if isinstance(key, list):
            key = key[:]
        elif isinstance(key, (dict, RejectingDict)):
            key = smart_copy_dict(key)

        if isinstance(value, list):
            value = value[:]
        elif isinstance(value, (dict, RejectingDict)):
            value = smart_copy_dict(value)

        new_dict[key] = value

    return new_dict


def findfiles(paths, regexp, full=False):
    """

    :param paths:
    :type paths:
    :param regexp:
    :type regexp:
    """

    LOG.debug("Start find files")
    LOG.debug("Paths: %s", paths)
    LOG.debug("Regexp: '%s'", regexp)

    results = []
    re_obj = re.compile(regexp)

    path_seen = []
    for path in paths:

        if path in path_seen:
            continue

        all_files = os.walk(path)
        for base_path, dummy_dirnames, filenames in all_files:
            for filename in filenames:
                fullname = os.path.join(base_path, filename)

                if full:
                    filename = fullname

                if fullname in results:
                    continue

                if re_obj.search(filename):
                    results.append(fullname)
                    LOG.debug("File match: %s", results[-1])

        path_seen.append(path)

    LOG.debug("End find files")
    return results


def RNDINT():  # pylint: disable-msg=invalid-name
    """Returns a random integer between 0 and 2^32. """
    return _RNDINT.randint(0, (2**64))


def RNDFP():  # pylint: disable-msg=invalid-name
    """Returns a random floating point between 1 and 1.0000001. """
    return (_RNDFP.random() / 1000000) + 1


def iter_flatten(iterable):
    """

    :param iterable:
    :type iterable:
    """
    iterator = iter(iterable)
    for element in iterator:
        if isinstance(element, (list, tuple)):
            for another_element in iter_flatten(element):
                yield another_element
        else:
            yield element


def range_to_sequence(start, *args):
    """

    """

    if len(args) > 2:
        raise NotImplementedError(
            "This function does not support more than 3 arguments")

    step = 1

    if isinstance(start, str):
        start = int(start, 0)

    if len(args) > 0:
        end = args[0]
        if isinstance(end, str):
            end = int(end, 0)
    else:
        return [start]

    if len(args) > 1:
        step = args[1]

        if isinstance(step, str):
            step = int(step, 0)

    return list(
        itertools.islice(
            itertools.count(start, step),
            (end - start + step - 1 + 2 * (step < 0)) // step
        )
    )


def which(program):
    """

    :param program:
    :type program:
    """

    def is_exe(fpath):
        """

        :param fpath:
        :type fpath:
        """
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    def ext_candidates(fpath):
        """

        :param fpath:
        :type fpath:
        """
        yield fpath
        for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
            yield fpath + ext

    fpath, dummy_fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            for candidate in ext_candidates(exe_file):
                if is_exe(candidate):
                    return candidate

    return None


def longest_common_substr(str1, str2):
    """

    :param str1:
    :type str1:
    :param str2:
    :type str2:
    """

    if not str1 or not str2:
        return ""

    str1_char, str1_rest, str2_char, str2_rest = \
        str1[0], str1[1:], str2[0], str2[1:]

    if str1_char == str2_char:
        return str1_char + longest_common_substr(str1_rest, str2_rest)
    else:
        return max(
            longest_common_substr(str1, str2_rest),
            longest_common_substr(str1_rest, str2),
            key=len)


# Classes
class RejectingDict(dict):
    """A dictionary that raise an exception if the key is already set.

    """

    def __setitem__(self, key, value):
        """

        :param key:
        :param value:

        """

        if key in list(self.keys()):
            raise MicroprobeDuplicatedValueError(
                "Key '%s' is already present" % str(key)
            )
        else:
            return super(RejectingDict, self).__setitem__(key, value)


class RejectingOrderedDict(OrderedDict):
    """An ordered dictionary that raises an exception if key is already set.

    """

    def __setitem__(self, key, value):  # pylint: disable=arguments-differ
        """

        :param key:
        :param value:

        """

        if key in list(self.keys()):
            raise MicroprobeDuplicatedValueError(
                "Key '%s' is already present" % str(key)
            )
        else:
            return super(RejectingOrderedDict, self).__setitem__(key, value)


class Pickable(object):  # pylint: disable-msg=R0903
    """A helper class to implement the pickling interface.

    Objects that inherit from this class are automatically serialized/
    deserialized to disk whenever is needed. Check what is 'pickle' in
    python for more details.
    """

    def __getstate__(self):
        """  """
        return self.__dict__

    def __setstate__(self, state):
        """

        :param state:

        """
        self.__dict__.update(state)


class Progress(object):  # pylint: disable-msg=too-few-public-methods
    """A counting progress indicator."""

    def __init__(self, total, msg="", out=sys.stderr):
        """
        :arg total: Objective progress count.
        :type total: int

        :arg msg: Message to prefix to the progress indicator.
        :type msg: str

        :arg out: Output file.
        :type out: file
        """
        self._total = total
        self._msg = msg
        self._count = 0
        self._fd = out
        self._fmt = " %%s  %%%%%dd / %%d (%%%%2.1f/100) " \
            "ETA: %%%%s                         \r" % (len(str(self._total))
                                                       )
        self._fmt = self._fmt % (msg, self._total)
        self._start = timeit.default_timer()
        self._eta = "???"
        self._skip_delete = False
        self._module = 0

    def __call__(self, increment=1):
        """Increment the progress indicator by *increment*."""
        self._count += increment

        if (self._total / 100) == 0:
            return

        module = self._count % (self._total / 100)
        required_time = 0

        if module < self._module:

            time_per_increment = (
                timeit.default_timer() - self._start
            ) / self._count

            required_time = time_per_increment * (self._total - self._count)

            minut, sec = divmod(required_time, 60)
            hour, minut = divmod(minut, 60)
            self._eta = "%dh:%02dm:%02ds" % (hour, minut, sec)

        self._module = module

        if required_time > 1:
            self._fd.write(
                self._fmt % (
                    self._count, (
                        (float(self._count) / self._total)
                    ) * 100, self._eta
                )
            )

    def __del__(self):
        """Delete the progress indicator from screen."""

        if self._total < 100:
            return

        length = len(self._fmt % (0, 0, 0))
        self._fd.write((" " * length) + "\r")
        total_time = timeit.default_timer() - self._start
        minut, sec = divmod(total_time, 60)
        hour, minut = divmod(minut, 60)

        if minut > 1:
            time_str = "%s Elapsed time: %dh:%02dm:%02ds\n" % \
                (self._msg, hour, minut, sec)
            self._fd.write(time_str)


def open_generic_fd(filename, mode):

    if filename.endswith(".gz"):
        if 'b' not in mode:
            mode += 'b'
        fd = gzip.open(filename, mode, compresslevel=9)
    elif filename.endswith(".bz2"):
        if 'b' not in mode:
            mode += 'b'
        fd = bz2.BZ2File(filename, mode, compresslevel=9)
    else:
        fd = open(filename, mode)

    return fd

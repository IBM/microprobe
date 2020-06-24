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
""":mod:`microprobe.utils.distrib` module

"""

# Futures
from __future__ import absolute_import, division

# Built-in modules
import bisect
import itertools
from random import Random

# Third party modules
import six
from six.moves import range, zip

# Own modules
from microprobe.exceptions import MicroprobeValueError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import getnextf


# Constants
LOG = get_logger(__name__)
__all__ = [
    "Choice", "weighted_choice", "discrete_average", "shuffle",
    "locality",
    "sort_by_distance", "sort_by_usage", "generate_plain_profile",
    "generate_weighted_profile", "compute_weighted_profile_average",
    "regular_seq", "average", "pstdev"
]

# Functions


# Classes
class Choice(object):  # pylint: disable-msg=too-few-public-methods
    """Choice """

    def __init__(self, items):
        """

        :param items:

        """
        self._items = items[:]
        self._oitems = items[:]
        self._random = Random()
        self._random.seed(10)

    def __call__(self, rnd=None, bis=bisect.bisect):
        """

        :param rnd:  (Default value = None)
        :param bis:  (Default value = bisect.bisect)

        """

        added_weights = []
        last_sum = 0

        if rnd is None:
            rnd = self._random.random

        for dummy, weight in self._items:
            last_sum += weight
            added_weights.append(last_sum)

        index = bis(added_weights, rnd() * last_sum)
        item = self._items[index][0]

        return item


def weighted_choice(items):
    """Returns a function that makes a weighted random choice from items.

    :param items:

    """

    if isinstance(items, dict):
        items = list(items.items())
    else:
        items = list(items)

    return Choice(items)


def discrete_average(average_val):
    """

    :param average_val:

    """

    if average_val == int(average_val):
        return lambda: int(average_val)

    low = int(average_val)
    high = low + 1
    array = [low, high]
    weights = [1, 1]

    caverage = average(array, weights=weights)
    while abs(caverage - average_val) > 0.01:
        if caverage > average_val:
            weights[0] = weights[0] + 1
        else:
            weights[1] = weights[1] + 1

        caverage = average(array, weights=weights)

    return weighted_choice((list(zip(array, weights))))


def average(array, weights=None):
    """

    :param array:
    :type array:
    :param weights:
    :type weights:
    """

    if weights is None:
        weights = [1.0] * len(array)

    if len(weights) != len(array):
        raise MicroprobeValueError(
            "Length of weights not compatible with length of the array"
        )

    ave_val = (sum(
        [
            array[idx] * weights[idx] for idx in range(0, len(array))
        ]
    ) * 1.0) / sum(weights)

    return ave_val


def pstdev(data):
    """Calculates the population standard deviation"""
    ldata = len(data)
    if ldata < 2:
        raise MicroprobeValueError(
            "variance requires at least two data points"
        )

    data_ave = average(data)
    squared_sum = sum((x - data_ave)**2 for x in data)

    pvar = squared_sum / (ldata)
    return pvar**0.5


def regular_seq(items):
    """

    :param items:
    :type items:
    """
    total = 0

    for item, weight in items.items():
        total = total + weight

    sequence = []
    for idx in range(0, total):
        for item, weight in items.items():
            if weight == 0:
                continue
            every = (total // weight) - 1
            if every == 0:
                sequence.append(item)
            elif idx % every == 0:
                sequence.append(item)

    return getnextf(itertools.cycle(sequence))


def shuffle(slist, threshold):
    """

    :param slist:
    :param threshold:

    """

    rlist = []
    slist = sorted(slist)

    random = Random()
    random.seed(10)

    if threshold == -1:
        random.shuffle(slist)
        return slist

    if threshold == 0:
        return slist

    if len(slist) == 0:
        return []

    init_value = slist[0]
    temp_list = [init_value]

    for val in slist[1:]:
        if (val - init_value) >= threshold:
            random.shuffle(temp_list)
            rlist = rlist + temp_list
            init_value = val
            temp_list = [val]
        else:
            temp_list.append(val)

    random.shuffle(temp_list)
    rlist = rlist + temp_list

    return rlist


def sort_by_distance(
    regs, distdict, useddict, distance, dummy_instr, dummy_idx
):
    """

    :param regs:
    :param distdict:
    :param useddict:
    :param distance:
    :param dummy_instr:
    :param dummy_idx:

    """
    req = 0
    while req < 1:
        # LOG.debug(": %s", req)
        for key, value in distdict.items():

            LOG.debug("%s : %s ", key, value)
            LOG.debug("Valid: %s, %s", key in regs, value == distance)
            if key in regs and value == distance:
                return key

        req = req + 1

    LOG.warning(
        "Unable to get a used register in the requested distance."
        " Failback to usage sorting."
    )
    return sort_by_usage(regs, useddict, distdict)


def sort_by_usage(regs, lastdict, dummy_defdict):
    """

    :param regs:
    :param lastdict:
    :param dummy_defdict:

    """

    assert len(regs) > 0

    for reg in six.iterkeys(lastdict):
        LOG.debug("Dict key: %s", reg)
        if reg in regs:
            LOG.debug("Last used register: %s", reg)
            return reg

    # None of the regs has ben used yet
    # Return the first one
    return regs[0]

    # LOG.critical("Regs: %s", regs)
    # LOG.critical("Dictionary keys: %s", lastdict.keys())
    # raise MicroprobeException("Sort error")


def generate_plain_profile(elements):
    """

    :param elements:

    """
    return [(elem, 1) for elem in elements]


def generate_weighted_profile(
    elements, attribute,
    targetvalue, maxvalue=None,
    minvalue=None
):
    """

    :param elements:
    :param attribute:
    :param targetvalue:
    :param maxvalue:  (Default value = None)
    :param minvalue:  (Default value = None)

    """

    profile = generate_plain_profile(elements)

    if maxvalue is not None:
        profile = [
            (entry, weight)
            for entry, weight in profile
            if getattr(entry, attribute) <= maxvalue
        ]

    if minvalue is not None:
        profile = [
            (entry, weight)
            for entry, weight in profile
            if getattr(entry, attribute) >= minvalue
        ]

    aver = compute_weighted_profile_average(profile, attribute)

    count = 0
    step = 1

    random = Random()
    random.seed(10)

    if aver < targetvalue:

        above = [
            idx
            for idx, entry in enumerate(profile)
            if getattr(entry[0], attribute) > targetvalue
        ]

        if len(above) > 0:
            while aver < targetvalue:
                index = random.choice(above)
                above.remove(index)
                profile[index] = (profile[index][0], profile[index][1] + step)
                aver = compute_weighted_profile_average(profile, attribute)

                if len(above) == 0:
                    above = [
                        idx
                        for idx, entry in enumerate(profile)
                        if getattr(entry[0], attribute) > targetvalue
                    ]

                count = count + 1
                if count % 1000 == 0:
                    step = step * 10

        else:
            maximum = max(
                [
                    getattr(entry, attribute) for entry, weight in profile
                ]
            )
            profile = [
                (entry, weight)
                for entry, weight in profile
                if getattr(entry, attribute) == maximum
            ]

    elif aver > targetvalue:

        below = [
            idx
            for idx, entry in enumerate(profile)
            if getattr(entry[0], attribute) < targetvalue
        ]

        if len(below) > 0:
            while aver > targetvalue:
                index = random.choice(below)
                below.remove(index)
                profile[index] = (profile[index][0], profile[index][1] + step)
                aver = compute_weighted_profile_average(profile, attribute)

                if len(below) == 0:
                    below = [
                        idx
                        for idx, entry in enumerate(profile)
                        if getattr(entry[0], attribute) < targetvalue
                    ]

                count = count + 1
                if count % 1000 == 0:
                    step = step * 10

        else:
            minimum = min(
                [
                    getattr(entry, attribute) for entry, weight in profile
                ]
            )
            profile = [
                (entry, weight)
                for entry, weight in profile
                if getattr(entry, attribute) == minimum
            ]

    return profile


def compute_weighted_profile_average(profile, attribute):
    """

    :param profile:
    :param attribute:

    """
    return sum([getattr(entry, attribute) * weight for
                entry, weight in profile]) / \
        sum([weight for entry, weight in profile])


def locality(values, locdef):
    """

    """
    length = locdef[0]
    repeat = locdef[1]

    if repeat <= 0:
        return values

    values = [
        values[i:i + length] * repeat
        for i in range(0, len(values), length)
    ]
    values = [item for sublist in values for item in sublist]
    return values


def probability(value):
    """

    """
    assert value >= 0 and value <= 1, "Invalid probability"

    crandom = Random()
    crandom.seed(10)

    def func():
        return crandom.uniform(0, 1) <= value

    return func


def regular_probability(value):
    """
    Returns callable that returns True every value calls
    """
    def func():
        count = 0
        while True:
            count = count + 1
            ret = (count % value) == 0
            yield ret

    generator = func()

    def func2():
        return next(generator)

    return func2

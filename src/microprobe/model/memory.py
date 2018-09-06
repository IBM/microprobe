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
""":mod:`microprobe.model.memory` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Third party modules
from six.moves import range, zip

# Own modules
from microprobe.code.address import Address
from microprobe.code.var import VariableArray
from microprobe.exceptions import MicroprobeModelError
from microprobe.model import GenericModel
from microprobe.utils.distrib import shuffle, weighted_choice
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["EndlessLoopInstructionMemoryModel", "EndlessLoopDataMemoryModel"]

# Functions


# Classes
class EndlessLoopInstructionMemoryModel(GenericModel):
    """ """

    def __init__(self,
                 name,
                 cache_hierarchy,
                 percentages,
                 minimum_chunks=None,
                 minimum_displacement=None):
        """

        :param name:
        :param cache_hierarchy:
        :param percentages:
        :param minimum_chunks:  (Default value = None)
        :param minimum_displacement:  (Default value = None)

        """
        super(EndlessLoopInstructionMemoryModel, self).__init__(
            name, "Generic instruction memory model for endless loops")

        self._cache_hierarchy = cache_hierarchy
        self._percentages = percentages

        assert len(cache_hierarchy) == len(percentages)
        assert sum(percentages) == 100, \
            "The memory access model is not complete"

        cache_ant = None
        displacements = []
        number_of_chunks = []
        for cache, ratio in zip(cache_hierarchy, percentages):
            if cache_ant is None and ratio > 0:
                displacements.append(0)
                number_of_chunks.append(1)
            elif ratio == 0:
                displacements.append(0)
                number_of_chunks.append(0)
            elif ratio > 0:
                displacements.append(2**(cache_ant.bits_x_set + 1 +
                                         cache_ant.bits_x_offset))
                number_of_chunks.append(cache_ant.ways + 1)
                assert cache.ways >= cache_ant.ways + 1, "Overflowing two " \
                    "levels at the same time? Not Implemented."

            cache_ant = cache

        if minimum_chunks is not None:
            # print number_of_chunks
            # print displacements
            assert [x for x in number_of_chunks
                    if x >= 0][-1] < minimum_chunks, \
                "Minimum chunks forced, but more chunks are needed."
            number_of_chunks[
                [
                    x[0] for x in enumerate(number_of_chunks) if x[1] > 0
                ][-1]] = minimum_chunks

        if minimum_displacement is not None:
            for idx, displacement in enumerate(displacements):
                if displacement < minimum_displacement:
                    displacements[idx] = minimum_displacement

        iterations = [1] * len(number_of_chunks)

        def get_percentages(iterations, number_chunks):
            """

            :param iterations:
            :param number_chunks:

            """
            total_count = sum([
                x * y for x, y in zip(iterations, number_chunks)
            ])
            return [
                ((x * y) / total_count) * 100
                for x, y in zip(iterations, number_chunks)
            ]

        def max_percentage_diff(percentages, target_percentages):
            """

            :param percentages:
            :param target_percentages:

            """
            return max([
                abs(x - y) for x, y in zip(percentages, target_percentages)
            ])

        def min_percentage_idx(percentages, target_percentages):
            """

            :param percentages:
            :param target_percentages:

            """
            min_value = min([
                (x - y) for x, y in zip(percentages, target_percentages)
            ])
            return [
                idx
                for idx, elem in enumerate(zip(percentages,
                                               target_percentages))
                if (elem[0] - elem[1]) == min_value
            ][0]

        current_percentages = get_percentages(iterations, number_of_chunks)
        while max_percentage_diff(current_percentages,
                                  self._percentages) > 0.1:

            iterations[
                min_percentage_idx(current_percentages,
                                   self._percentages)] += 1

            current_percentages = get_percentages(iterations, number_of_chunks)

        descriptors = list(zip(number_of_chunks, displacements, iterations))
        self._descriptors = descriptors

    def __call__(self, bbl_size):
        """

        :param bbl_size:

        """

        # print self._descriptors
        for elem in [
                x[1] for x in self._descriptors[1:] if x[2] > 0 and x[0] > 0
        ]:
            # print(elem, bbl_size)
            if bbl_size > elem:
                raise MicroprobeModelError("Basic block size ('%d') is too "
                                           "large for the model" % bbl_size)

        return self._descriptors


class EndlessLoopDataMemoryModel(GenericModel):
    """ """

    def __init__(self, name, cache_hierarchy, percentages):
        """

        :param name:
        :param cache_hierarchy:
        :param percentages:

        """
        super(EndlessLoopDataMemoryModel,
              self).__init__(name, "Generic memory model for endless loops")

        self._cache_hierarchy = cache_hierarchy
        self._percentages = percentages

        assert len(cache_hierarchy) == len(percentages)

        items = []
        all_ratio = 0
        accum = 100
        mcomp_ants = []
        sets_dict = {}

        for mcomp, ratio in zip(cache_hierarchy, percentages):

            items.append((mcomp, ratio))
            all_ratio += ratio

            if accum == 0:
                sets = []
            elif len(mcomp_ants) == 0:
                sets = mcomp.setsways()
                lsets = len(sets)
                sets = sets[0:int(lsets * ratio // accum)]
            else:
                sets = mcomp.setsways()
                sets_length = len(sets)
                setm = [1] * len(sets)
                for mcomp_ant in mcomp_ants:
                    # sets = mcomp.setsways()
                    sets_ant = (elem & ((1 << mcomp_ant.set_ways_bits) - 1)
                                for elem in sets)
                    sets_ant = list(sets_ant)
                    # zipping = zip(sets, sets_ant)
                    # fset = frozenset(sets_dict[mcomp_ant])
                    # sets = [s1 for s1, s2 in zipping if s2 not in fset]

                    # print(len(sets))

                    if len(sets_dict[mcomp_ant]) > 0:

                        fset = frozenset(sets_dict[mcomp_ant])
                        idxes = (idx
                                 for idx in range(0, sets_length)
                                 if setm[idx] != 0)
                        for idx in idxes:
                            # print(idx, sets_length)

                            # if setm[idx] == 0:
                            #    continue

                            if sets_ant[idx] in fset:  # sets_dict[mcomp_ant]:
                                # print(idx, sets_length)
                                setm[idx] = 0

                # sets = mcomp.setsways()
                sets = [s1 for s1, s2 in zip(sets, setm) if s2 is not 0]
                lsets = len(sets)
                sets = sets[0:int(lsets * ratio // accum)]

            sets_dict[mcomp] = sets
            accum = accum - ratio
            mcomp_ants.append(mcomp)

        mcomp_ant = None

        for mcomp, ratio in zip(cache_hierarchy, percentages):

            slist = [elem << mcomp.offset_bits for elem in sets_dict[mcomp]]

            # TODO: strided parameter or random or pseudorandom (32k ranges)
            # TODO: shuffle function too slow for pseudorandom

            if mcomp_ant is None:
                mcomp_ant = mcomp

            if False:
                slist = shuffle(slist, 32768)
            elif False:
                slist = shuffle(slist, -1)
            elif False:
                slist = shuffle(slist, mcomp_ant.size)

            if len(slist) > 0:
                tlist = []
                tlist.append(slist[0])
                tlist.append(slist[-1])

            sets_dict[mcomp] = slist
            mcomp_ant = mcomp

        self._sets = sets_dict
        self._func = weighted_choice(dict(items))
        self._state = {}

        assert all_ratio == 100, "The memory access model is not complete"
        assert accum == 0, "Something wrong"

    def initialize_model(self):
        """ """
        mant = None
        for elem in self._cache_hierarchy:
            var = VariableArray(
                elem.name.replace(" ", "_"),
                "char",
                elem.size,
                align=256 * 1024)
            count = 0
            max_value = 0

            if mant is None:
                module = len(self._sets[elem])
            else:
                module = min(
                    int(4 * (len(mant.setsways()) - len(self._sets[mant]))),
                    len(self._sets[elem]))

            self._state[elem] = (var, count, max_value, module, [])
            mant = elem

    def finalize_model(self):
        """ """

        actions = []
        cache_ant = None
        for cache, ratio in zip(self._cache_hierarchy, self._percentages):

            var, count, max_value, \
                dummy_module, dummy_cca = self._state[cache]

            # General checks
            if count == 0 and ratio > 0:
                raise MicroprobeModelError(
                    "Zero accesses generated to the"
                    " cache level '%s' and '%d%%' of all accesses"
                    " are required." % (cache, ratio))

            if count > 0 and ratio == 0:
                raise MicroprobeModelError("%d accesses generated to the"
                                           " cache level '%s' and not accesses"
                                           " are required." % (count, cache))

            if cache_ant is None or ratio == 0:
                cache_ant = cache
                continue

            size = len(self._sets[cache])
            real_size = len(cache_ant.setsways()) - len(self._sets[cache_ant])

            incsize = max_value // cache_ant.size
            if (max_value % cache_ant.size) > 0:
                incsize += 1
            incsize = cache_ant.size * incsize

            guard = cache.size // incsize

            LOG.debug("Level: %s", cache)
            LOG.debug("  Accesses: %d", count)
            LOG.debug("  Max.Value: %d", max_value)
            LOG.debug("  Previous level size: %d", real_size)
            LOG.debug("  Increment size: %d", incsize)
            LOG.debug("  Iterations: %d", guard)

            if (guard * count) < (2 * real_size):
                # Too few accesses that we can not overflow the previous
                # cache level

                raise MicroprobeModelError(
                    "Too few accesses to cache level"
                    " '%s' to overflow the previous cache level '%s'. "
                    "Consider increasing the number of accesses to this"
                    " level (more %% of accesses or larger benchmark size)."
                    " You need '%d' more accesses. Accesses: %s ;"
                    " Iterations: %s ; Size: %s " % (cache, cache_ant, (
                        (2 * real_size) - (guard * count)) // guard, count,
                        guard, real_size))

            if count > size or count > (2 * real_size):
                # No action required
                continue

            increment_size = cache.size // guard
            actions.append((var, increment_size, guard))

        return actions

    def _check_integrity(self):
        """ """
        # Make sure we are accessing to different CC on each
        # memory element
        for elem1 in self._cache_hierarchy:
            for elem2 in self._cache_hierarchy:

                if elem1 == elem2:
                    continue

                intr = set(self._state[elem1][4]).intersection((self._state[
                    elem2][4]))

                if len(intr) > 0:
                    LOG.debug("%s, %s", elem1, self._state[elem1][4])
                    LOG.debug("%s, %s", elem2, self._state[elem1][4])
                    LOG.critical("MEMORY MODEL NOT IMPLEMENTED CORRECTLY")
                    exit(-1)

    def __call__(self, lengths):
        """

        :param lengths:

        """

        mcomp = self._func()
        var, count, max_value, module, cca = self._state[mcomp]

        value = self._sets[mcomp][count % module]
        count = count + 1
        max_value = max(value, max_value)
        cgc = mcomp.congruence_class(value)

        self._check_integrity()

        if cgc not in cca:
            cca.append(cgc)

        self._state[mcomp] = (var, count, max_value, module, cca)
        return Address(base_address=var, displacement=value), max(lengths)

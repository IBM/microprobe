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
""":mod:`microprobe.target.uarch.cache` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import math

# Third party modules
from six.moves import range

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = [
    "cache_hierarchy_from_elements", "Cache", "SetAssociativeCache",
    "CacheHierarchy"
]


# Functions
def cache_hierarchy_from_elements(elements):
    """

    :param elements:

    """

    caches = _caches_from_elements(elements)

    if len(caches) == 0:
        raise MicroprobeArchitectureDefinitionError(
            "Expecting cache hierarchy"
            " elements in the microarchitecture"
            " description, but none found."
        )

    cache_hierarchy = CacheHierarchy(caches)

    return cache_hierarchy


def _caches_from_elements(elements):
    """

    :param elements:

    """

    LOG.debug("Start")

    caches = []
    for element in elements.values():

        LOG.debug("Checking: '%s'", element)
        try:
            if not element.type.data_cache and \
                    not element.type.instruction_cache:
                continue
        except Exception:
            raise MicroprobeArchitectureDefinitionError(
                "Microarchitecture "
                "definition requires the definition of the "
                "'data_cache' and 'instruction_cache' properties "
                "for the element types."
            )

        LOG.debug("Cache element found:'%s'", element)

        try:
            size = element.type.cache_size * 1024
            line_size = element.type.cache_linesize
            level = element.type.cache_level
            address_size = element.type.cache_address_size
        except AttributeError as exc:
            # pylint: disable-msg=E1101
            raise MicroprobeArchitectureDefinitionError(
                "Element '%s' defined as a cache, but required "
                "property '%s' not specified in its type "
                "'%s'" % (element, exc.message.split("'")[3], element.type)
            )

        # Figuring out the cache type based on element attributes
        # Right now, we only implement N-way set associative

        ways = getattr(element.type, "cache_ways", None)

        if ways is not None:
            new_cache = SetAssociativeCache(
                element, size, level, line_size, address_size,
                element.type.data_cache, element.type.instruction_cache, ways
            )
            caches.append(new_cache)
        else:
            raise MicroprobeArchitectureDefinitionError(
                "Element '%s' defined "
                "as a cache, but cache type can not be "
                "determined. Please specify on of the "
                "following properties: ['cache_ways']"
            )

    LOG.debug("End")
    return caches


# Classes
class Cache(object):
    """Class to represent a cache."""

    def __init__(
        self, element, size, level, line_size, address_size, data, ins
    ):
        """Create a Cache object.

        :param element: Micrarchitecture element
        :type element: :class:`~.MicroarchitectureElement`
        :param size: Cache size in kilobytes
        :type size: :class:`~.int`
        :param level: Cache level
        :type level: :class:`~.int`
        :param line_size: Line size in bytes
        :type line_size: :class:`~.int`
        :param address_size: Address size in bits
        :type address_size: :class:`~.int`
        :param data: Data cache flag
        :type data: :class:`~.bool`
        :param ins: Instruction cache flag
        :type ins: :class:`~.bool`
        :return: Cache instance
        :rtype: :class:`~.Cache`
        """
        self._element = element
        self._size = size
        self._level = level
        self._line_size = line_size
        self._address_size = address_size
        self._data = data
        self._ins = ins

        # Implement value checking for parameters

    @property
    def element(self):
        """Corresponding microarchitecture element
        (:class:`~.MicroarchitectureElement`)."""
        return self._element

    @property
    def size(self):
        """Cache size in kilobytes (class:`~.int`)."""
        return self._size

    @property
    def line_size(self):
        """Cache line size in bytes (class:`~.int`)."""
        return self._line_size

    @property
    def contains_data(self):
        """Data cache flag (class:`~.bool`)."""
        return self._data

    @property
    def contains_instructions(self):
        """Instruction cache (class:`~.bool`)."""
        return self._ins

    @property
    def level(self):
        """Cache level (class:`~.int`)."""
        return self._level

    @property
    def name(self):
        """Cache name (class:`~.str`)."""
        return "%s Cache" % self.element.full_name

    @property
    def description(self):
        """Cache description (class:`~.str`)."""

        if self.contains_data ^ self.contains_instructions:
            if self.contains_data:
                dscr = "Data"
            else:
                dscr = "Instruction"
        else:
            dscr = "Mixed (instruction and data)"

        return "Level %s %s %s" % (self.level, dscr, self.name)

    def __str__(self):
        """"x.__str__() <==> str(x)"""
        return "%s('%s')" % (self.__class__.__name__, self.description)


class SetAssociativeCache(Cache):
    """Class to represent a set-associative cache."""

    def __init__(
        self, element, size, level, line_size, address_size, data, ins, ways
    ):
        """Create a SetAssociativeCache object.

        :param element: Micrarchitecture element
        :type element: :class:`~.MicroarchitectureElement`
        :param size: Cache size in kilobytes
        :type size: :class:`~.int`
        :param level: Cache level
        :type level: :class:`~.int`
        :param line_size: Line size in bytes
        :type line_size: :class:`~.int`
        :param address_size: Address size in bits
        :type address_size: :class:`~.int`
        :param data: Data cache flag
        :type data: :class:`~.bool`
        :param ins: Instruction cache flag
        :type ins: :class:`~.bool`
        :param ins: Cache ways
        :type ins: :class:`~.int`
        :return: Cache instance
        :rtype: :class:`~.Cache`
        """
        super(SetAssociativeCache, self).__init__(
            element, size, level, line_size, address_size, data, ins
        )

        self._ways = ways
        self._address_size = address_size

        self._sets = size // (ways * line_size)
        self._set_bits = int(math.log(self._sets, 2))

        self._lines = size // (line_size)
        self._lines_bits = int(math.log(self._lines, 2))

        self._offset_bits = int(math.log(line_size, 2))

        self._tag_bits = address_size - self._set_bits - self._offset_bits

        self._setsways = size // line_size
        self._setways_bits = int(math.log(self._setsways, 2))

    @property
    def ways(self):
        """Number of cache ways (class:`~.int`)."""
        return self._ways

    def sets(self):
        """Number of cache sets (class:`~.int`)."""
        return list(range(0, self._sets))

    @property
    def bits_x_set(self):
        """Number of bits per set (class:`~.int`)."""
        return self._set_bits

    def lines(self):
        """Number of lines (class:`~.int`)."""
        return list(range(0, self._lines))

    @property
    def bits_x_lines(self):
        """Number of bits per line (class:`~.int`)."""
        return self._lines_bits

    @property
    def bits_x_offset(self):
        """Number of offset bits (class:`~.int`)."""
        return self._offset_bits

    @property
    def set_ways_bits(self):
        """Number of bits per way (class:`~.int`)."""
        return self._setways_bits

    @property
    def offset_bits(self):
        """Number of offset bits (class:`~.int`)."""
        return self._offset_bits

    def setsways(self):
        """Return the list of sets and ways.

        :return: List of available sets * ways
        :rtype: :class:`~.list` of :class:`~.int`
        """
        return list(range(0, self._setsways))

    def congruence_class(self, value):
        """Return the congruence class for a given *value*.

        :param value: Address
        :type value: :class:`~.int`
        :return: Congruence class
        :rtype: :class:`~.int`
        """
        cgc = (value >> self.offset_bits) & ((1 << (self._set_bits)) - 1)
        return cgc

    def offset(self, value):
        """

        :param value:

        """
        cgc = (value) & ((1 << (self.offset_bits) - 1))
        return cgc

    def print_info(self):
        """ """

        from microprobe.utils.cmdline import print_info
        print_info(self._offset_bits)
        print_info(self._set_bits)
        print_info(self._tag_bits)
        bit_range = [0, self._address_size - 1]
        offset_range = [
            self._address_size - 1 - self.offset_bits, self._address_size - 1
        ]

        ccrange = [
            self._address_size - 1 - self.offset_bits - self._set_bits,
            self._address_size - 1 - self.offset_bits - 1
        ]

        print_info((bit_range, offset_range, ccrange))


class CacheHierarchy(object):
    """Class to represent a cache hierarchy."""

    def __init__(self, caches):
        """

        :param caches:

        """

        first_data_levels = [
            cache for cache in caches
            if cache.level == 1 and cache.contains_data
        ]

        first_ins_levels = [
            cache
            for cache in caches
            if cache.level == 1 and cache.contains_instructions
        ]

        if len(first_ins_levels) == 0:
            raise MicroprobeArchitectureDefinitionError(
                "At least one cache"
                "should be defined as first level instruction"
                "cache."
            )

        if len(first_data_levels) == 0:
            raise MicroprobeArchitectureDefinitionError(
                "At least one cache"
                "should be defined as first level data cache"
            )

        data_levels = {}
        for cache in first_data_levels:
            data_levels[cache.element] = [cache]

        ins_levels = {}
        for cache in first_ins_levels:
            ins_levels[cache.element] = [cache]

        current_level = 2
        next_data_levels = [
            cache
            for cache in caches
            if cache.level == current_level and cache.contains_data
        ]
        next_ins_levels = [
            cache
            for cache in caches
            if cache.level == current_level and cache.contains_instructions
        ]

        while len(next_data_levels + next_ins_levels) > 0:

            if len(next_data_levels) > 0:

                for element in data_levels:

                    data_level = data_levels[element][-1]

                    assert data_level.level == (current_level - 1)

                    new_level = sorted(
                        next_data_levels,
                        key=lambda x, elem=element:
                        x.element.closest_common_element(elem).depth
                    )[-1]

                    data_levels[element].append(new_level)

            if len(next_ins_levels) > 0:

                for element in ins_levels:

                    ins_level = ins_levels[element][-1]

                    assert ins_level.level == (current_level - 1)

                    def my_key(elem):
                        """

                        :param elem:
                        :type elem:
                        """
                        return elem.element.closest_common_element(
                            element
                        ).depth

                    new_level = sorted(next_ins_levels, key=my_key)[-1]

                    ins_levels[element].append(new_level)

            current_level += 1
            next_data_levels = [
                cache
                for cache in caches
                if cache.level == current_level and cache.contains_data
            ]
            next_ins_levels = [
                cache
                for cache in caches
                if cache.level == current_level and cache.contains_instructions
            ]

        self._data_levels = data_levels
        self._ins_levels = ins_levels

    def get_data_hierarchy_from_element(self, element):
        """

        :param element:

        """

        LOG.debug("Generating hierarchy from '%s'", element)
        rhierarchy = [
            entry_level
            for entry_level in self._data_levels.values()
            if element in [cache.element for cache in entry_level]
        ]

        assert len(rhierarchy) == 1
        LOG.debug("Hierarchy: '%s'", [str(elem) for elem in rhierarchy[0]])

        return rhierarchy[0]

    def get_instruction_hierarchy_from_element(self, element):
        """

        :param element:

        """

        LOG.debug("Generating hierarchy from '%s'", element)
        rhierarchy = [
            entry_level
            for entry_level in self._ins_levels.values()
            if element in [cache.element for cache in entry_level]
        ]

        assert len(rhierarchy) == 1
        LOG.debug("Hierarchy: '%s'", [str(elem) for elem in rhierarchy[0]])

        return rhierarchy[0]

    def data_linesize(self):
        """ """
        return self._data_levels[
            list(self._data_levels.keys())[0]][0].line_size

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
""":mod:`microprobe.target.isa.dat` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import abc
import warnings

# Third party modules
import six

# Own modules
from microprobe.exceptions import MicroprobeAddressTranslationError, \
    MicroprobeDuplicatedValueError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict


# Constants

LOG = get_logger(__name__)
__all__ = ["DynamicAddressTranslation", "GenericDynamicAddressTranslation"]

# Functions


# Classes
class DynamicAddressTranslation(six.with_metaclass(abc.ABCMeta, object)):
    """ """

    @abc.abstractmethod
    def __init__(self, target, **kwargs):
        """ """
        pass

    @abc.abstractmethod
    def add_mapping(self, source, target, mask):
        """ """
        raise NotImplementedError

    @abc.abstractproperty
    def maps(self):
        raise NotImplementedError

    @abc.abstractproperty
    def control(self):
        raise NotImplementedError

    @abc.abstractmethod
    def copy(self, **kwargs):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def translate(self, address):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def raw_parse(self, raw_str):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def raw_decorate(self, raw_str):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def required_register_values(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def required_memory_values(self):
        """ """
        raise NotImplementedError

    @abc.abstractmethod
    def update_dat(self, **kwargs):
        """ """
        raise NotImplementedError


class GenericDynamicAddressTranslation(DynamicAddressTranslation):
    """ """

    _control_keys = {'DAT': False}

    def __init__(self, target, **kwargs):
        """ """
        super(GenericDynamicAddressTranslation, self).__init__(
            target, **kwargs
        )

        self._map = RejectingDict()
        self._target = target
        self._control = self._control_keys.copy()
        self._control.update(kwargs)

        tmaps = kwargs.pop('dat_map', False)
        if tmaps:
            for tmap in tmaps:
                self.add_mapping(tmap[0], tmap[1], tmap[2])

    @property
    def control(self):
        return self._control

    @property
    def maps(self):
        return self._map

    def add_mapping(self, source, target, mask):
        """ """

        try:
            self._map[source & mask] = DATmap(source, target, mask)
        except MicroprobeDuplicatedValueError:
            raise MicroprobeAddressTranslationError(
                "Map in '%s' already exists" % hex(source & mask)
            )

    def copy(self, **kwargs):
        """ """

        newargs = self.control.copy()
        newargs.update(kwargs)
        new_dat = GenericDynamicAddressTranslation(self._target, **newargs)
        for datmap in self.maps.values():
            new_dat.add_mapping(datmap.source, datmap.target, datmap.mask)
        return new_dat

    def translate(self, address):
        """ """

        if not self.control['DAT']:
            return address

        tmap = [
            tmap for tmap in self.maps.values() if tmap.address_in_map(address)
        ]

        if len(tmap) > 1:
            raise MicroprobeAddressTranslationError(
                "Multiple translation maps found for address '%s'" %
                hex(address)
            )
        elif len(tmap) < 1:
            raise MicroprobeAddressTranslationError(
                "No translation maps found for address '%s'" % hex(address)
            )
        else:
            return tmap[0].address_translate(address)

    def raw_parse(self, raw_str):
        """ """
        raise NotImplementedError(
            "DAT mechanisms and parameters are target dependent. Target: '%s'"
            " does not implement them. " % self._target
        )

    def raw_decorate(self, raw_str):
        """ """
        raise NotImplementedError(
            "DAT mechanisms and parameters are target dependent. Target: '%s'"
            " does not implement them. " % self._target
        )

    def required_register_values(self):
        """ """
        return []

    def required_memory_values(self):
        """ """
        return []

    def update_dat(self, **kwargs):
        """ """
        for key, value in kwargs.items():
            if key not in self._control_keys:
                warnings.warn(
                    "DAT Control key '%s' specified but not supported. "
                    "Ignoring it." % key
                )
                continue
            self._control[key] = value['value']


class DATmap(object):
    """ """

    def __init__(self, source, target, mask):
        self._source = source
        self._target = target
        self._mask = mask

    @property
    def mask(self):
        return self._mask

    @property
    def source(self):
        return self._source

    @property
    def target(self):
        return self._target

    def address_in_map(self, address):
        return self.source & self.mask == address & self.mask

    def address_translate(self, address):
        if not self.address_in_map(address):
            raise MicroprobeAddressTranslationError(
                "Unable to translate address '%s' in map: %s" % (
                    hex(address), str(self)
                )
            )

        address &= (~self.mask)
        address |= (self.target & self.mask)
        return address

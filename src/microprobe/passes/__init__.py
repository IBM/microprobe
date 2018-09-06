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
""":mod:`microprobe.passes` package

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import abc

# Third party modules

# Own modules
from microprobe.utils.logger import get_logger
import six

# Local modules

# Constants
__all__ = ["Pass"]
LOG = get_logger(__name__)

# Functions


# Classes
class Pass(six.with_metaclass(abc.ABCMeta, object)):
    """Class to represent a benchmak transformation pass.

    This object represents a transformation pass. Passes are applied on
    building blocks, modifying/checking their contents as needed.
    """

    @abc.abstractmethod
    def __init__(self):
        """Create a Pass object.

        :return: A new pass object
        :type: :class:`~.Pass`
        """
        self._description = "Description not provided"

    @abc.abstractmethod
    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        raise NotImplementedError

    def info(self):
        """Te"""
        return "%s - %s" % (self.__class__.__name__, self._description)

    def check(self, dummy_building_block, dummy_target):
        """

        :param dummy_building_block:
        :param dummy_target:

        """
        LOG.warning("Not implemented in %s", self.__class__.__name__)
        raise NotImplementedError

    def report(self):
        """ """
        LOG.warning("Not implemented in %s", self.__class__.__name__)
        return ""

    def requires(self):
        """ """
        LOG.warning("Not implemented in %s", self.__class__.__name__)
        return []

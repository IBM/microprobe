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
""":mod:`microprobe.utils.logger` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import logging
import os
import sys

# Own modules
import microprobe


# Constants
__all__ = ["get_logger", "set_log_level"]

ROOT_LOG = None
CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG
NOTSET = logging.NOTSET
DISABLE = logging.CRITICAL + 10

_MYDATEFMT = '%Y-%m-%d %H:%M:%S'

if len(sys.argv) == 0:

    _FORMATTER_DEBUG = logging.Formatter(
        fmt="%(asctime)s : %(name)40s : %(levelname)8s : %(funcName)s :"
        " %(lineno)5s : %(message)s",
        datefmt=_MYDATEFMT
    )
    _FORMATTER_DEFAULT = logging.Formatter(
        fmt="%(levelname)s : %(name)s :"
        " %(message)s",
        datefmt=_MYDATEFMT
    )
else:

    _PNAME = os.path.basename(sys.argv[0])
    _FORMATTER_DEBUG = logging.Formatter(
        fmt=_PNAME +
        ": %(asctime)s : %(name)40s : %(levelname)8s : %(funcName)s :"
        " %(lineno)5s : %(message)s",
        datefmt=_MYDATEFMT
    )
    _FORMATTER_DEFAULT = logging.Formatter(
        fmt=_PNAME + ": %(levelname)s : %(name)s :"
        " %(message)s",
        datefmt=_MYDATEFMT
    )


# Functions
def get_logger(name):
    """

    :param name:

    """

    global ROOT_LOG  # pylint: disable=global-statement

    if ROOT_LOG is None:
        ROOT_LOG = _create_base_logger()

    logger = logging.getLogger("program." + name)
    return logger


def set_log_level(level):
    """

    :param level:

    """

    global ROOT_LOG  # pylint: disable=global-statement

    if ROOT_LOG is None:
        ROOT_LOG = _create_base_logger()

    ROOT_LOG.setLevel(level)

    # Change formatter accordingly
    if level == DEBUG:
        formatter = _FORMATTER_DEBUG
    else:
        formatter = _FORMATTER_DEFAULT

    for handler in ROOT_LOG.handlers:
        handler.setFormatter(formatter)


def _create_base_logger():
    """ """

    logger = logging.getLogger("program")

    if microprobe.MICROPROBE_RC['debug'] is True:
        formatter = _FORMATTER_DEBUG
        logger.setLevel(logging.DEBUG)
    else:
        formatter = _FORMATTER_DEFAULT
        logger.setLevel(
            max(
                (CRITICAL - (microprobe.MICROPROBE_RC['verbosity'] * 10)), INFO
            )
        )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

# Classes

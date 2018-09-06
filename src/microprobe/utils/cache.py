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
""":mod:`microprobe.utils.cache` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os.path

# Third party modules
import six.moves.cPickle as pickle  # pylint: disable=E0401,E0611

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobeCacheError
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = [
    "update_cache_needed", "read_default_cache_data", "read_cache_data",
    "write_default_cache_data", "write_cache_data", "cache_file",
    "rm_default_cache_data", "rm_cache_data"
]


# Functions
def update_cache_needed(filenames, cachefile=None):
    """Returns True if the cache file needs to be updated.

    :param filenames:
    :param cachefile:  (Default value = None)

    """

    for filename in filenames:

        if cachefile is None:
            current_cachename = cache_file(filename)
        else:
            current_cachename = cachefile

        if not os.path.isfile(current_cachename):
            return True

        file_time = os.path.getmtime(filename)
        cache_time = os.path.getmtime(current_cachename)

        if file_time > cache_time:
            return True

    if MICROPROBE_RC['no_cache']:
        LOG.info("Cache disabled")
        return True

    if MICROPROBE_RC['debug']:
        LOG.warning("Cache disabled for debugging")
        return True

    return False


def read_default_cache_data(filename):
    """Reads data from a default cache file.

    :param filename:

    """
    cachename = cache_file(filename)
    return read_cache_data(cachename)


def read_cache_data(cachename):
    """Reads data from a cache file.

    :param cachename:

    """
    LOG.debug("Reading cache file: %s", cachename)
    with open(cachename, 'rb') as cache_fd:
        try:
            return pickle.load(cache_fd)
        except pickle.PickleError as exc:
            raise MicroprobeCacheError(exc)
        except EOFError as exc:
            raise MicroprobeCacheError(exc)
        except AttributeError as exc:
            raise MicroprobeCacheError(exc)
        except TypeError as exc:
            raise MicroprobeCacheError(exc)
        except ValueError as exc:
            raise MicroprobeCacheError(exc)


def write_default_cache_data(filename, data):
    """Writes data to a cache file.

    :param filename:
    :param data:

    """
    cachename = cache_file(filename)
    write_cache_data(cachename, data)


def write_cache_data(filename, data):
    """Writes data to a cache file.

    :param filename:
    :param data:

    """
    LOG.debug("Writing cache file: %s", filename)

    try:
        with open(filename, 'wb') as cache_fd:
            pickle.dump(data, cache_fd, protocol=pickle.HIGHEST_PROTOCOL)
    except IOError:
        # Unable to create cache files, disabling cache
        MICROPROBE_RC['no_cache'] = True
    except pickle.PickleError as exc:
        raise MicroprobeCacheError(exc)
    except EOFError as exc:
        raise MicroprobeCacheError(exc)


def cache_file(filename):
    """Given a file, returns it's cache file name.

    :param filename:

    """
    dirname = os.path.dirname(filename)
    basename = os.path.basename(filename)
    my_cache_file = os.path.join(
        os.path.normpath(dirname), ".%s.cache" % basename
    )
    return my_cache_file


def rm_default_cache_data(filename):
    """Removes default cache file.

    :param filename:

    """
    cachename = cache_file(filename)
    rm_cache_data(cachename)


def rm_cache_data(cachename):
    """Removes a cache file.

    :param cachename:

    """
    LOG.debug("Removing cache file: %s", cachename)
    os.remove(cachename)

# Classes

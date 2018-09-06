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
""":mod:`microprobe.utils.yaml` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os

# Third party modules
import yaml
from rxjson.Rx import Error, Factory  # @UnresolvedImport

# Own modules
from microprobe.exceptions import MicroprobeCacheError, \
    MicroprobeYamlFormatError
from microprobe.utils.cache import read_default_cache_data, \
    update_cache_needed, write_default_cache_data
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["read_yaml"]


# Functions
def _read_yaml(filename):
    """Reads a YAML file

    :param filename:

    """

    result = update_cache_needed([filename])
    if not result:
        try:
            return read_default_cache_data(filename)
        except MicroprobeCacheError:
            LOG.debug("Unable to read cache data for '%s'", filename)

    if not os.path.isfile(filename):
        raise MicroprobeYamlFormatError(
            "File '%s' referenced in YAML definition not found" % filename
        )

    with open(filename, 'r') as yaml_fd:
        raw_data = yaml_fd.read()
        try:
            data = yaml.load(raw_data)
        except yaml.composer.ComposerError as exc:
            raise MicroprobeYamlFormatError(
                "YAML parsing error while processing "
                "file '%s'. Error reported: '%s'" % (filename, str(exc))
            )

        except yaml.scanner.ScannerError as exc:
            raise MicroprobeYamlFormatError(
                "YAML parsing error while processing "
                "file '%s'. Error reported: '%s'" % (filename, str(exc))
            )

        except yaml.parser.ParserError as exc:
            raise MicroprobeYamlFormatError(
                "YAML parsing error while processing "
                "file '%s'. Error reported: '%s'" % (filename, str(exc))
            )
        except yaml.scanner.ScannerError as exc:
            raise MicroprobeYamlFormatError(
                "YAML parsing error while processing "
                "file '%s'. Error reported: '%s'" % (filename, str(exc))
            )

        try:
            write_default_cache_data(filename, data)
        except MicroprobeCacheError:
            LOG.debug("Unable to update cache data for '%s'", filename)

    return data


def _create_yaml_schema(filename):
    """Creates a YAML schema

    :param filename:

    """
    yaml_schema = _read_yaml(filename)
    rx_obj = Factory({"register_core_types": True})

    try:
        schema = rx_obj.make_schema(yaml_schema)
    except Error as error:
        raise MicroprobeYamlFormatError(
            "Invalid schema definition in '%s'.\n"
            "Error message:%s" % (filename, error)
        )

    return schema


def read_yaml(data_file, schema_file):
    """Reads a file and checks it against the schema file. Returns
    the data

    :param data_file:
    :param schema_file:

    """

    LOG.debug("Start")
    LOG.debug("Data file: %s", data_file)
    LOG.debug("Schema file: %s", schema_file)

    result = update_cache_needed([data_file])
    result = result or update_cache_needed([schema_file])

    readed = False
    if not result:
        LOG.debug("Using cache contents for '%s'", data_file)
        try:
            data = read_default_cache_data(data_file)
            readed = True
        except MicroprobeCacheError:
            LOG.debug("Unable to read cache data for '%s'", data_file)
            readed = False

    if not readed:
        data = _read_yaml(data_file)

    if data is None:
        LOG.warning("No data found in file: %s", data_file)
        LOG.debug("End")
        return data

    schema = _create_yaml_schema(schema_file)

    if not schema.check(data):

        LOG.info("Schema not validated")

        if isinstance(data, list):

            LOG.info("Check each element to provide a nice hint to the error")

            for cdata in data:
                if not schema.check([cdata]):
                    LOG.info("Element failing:")
                    for line in yaml.dump(
                        cdata, default_flow_style=False
                    ).split('\n'):
                        LOG.info(line)
                    raise MicroprobeYamlFormatError(
                        "YAML definition file in"
                        "'%s' does not follow the "
                        "schema definition in '%s'" % (data_file, schema_file)
                    )
        else:
            raise MicroprobeYamlFormatError(
                "YAML definition file in"
                "'%s' does not follow the "
                "schema definition in '%s'" % (data_file, schema_file)
            )

    LOG.debug("End")
    return data

# Classes

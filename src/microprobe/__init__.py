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
""":mod:`microprobe` package.

This is the main package of the Microprobe microbenchmark generation
framework. The sub-packages are the following:

- :mod:`~.code`: Code generation package.
- :mod:`~.driver`: Design space exploration package.
- :mod:`~.model`: Analytical modeling package.
- :mod:`~.passes`: Code transformation passes package.
- :mod:`~.schemas`: Schema definition package.
- :mod:`~.target`: Target definition package.
- :mod:`~.utils`: Utilities package.

and the modules in this package are the following:

- :mod:`~.exceptions`: Exception definition module.
- :mod:`~.property`: Property definition module.

Visit their respective documentation for further details.

In this package, the :data:`~.MICROPROBE_RC`
(:class:`~.MicroprobeDefaultConfiguration`) attribute is defined. This
attribute contains the framework-wide configuration options, which are
set to the default values or the values set in environment variables
when this package is imported. One can access this attribute in order
to change the framework configuration.

Configuration options
---------------------

- **verbosity** (:class:`~.int`): Verbosity level. It controls the verbosity
  level of the logger (Default: 0). Valid values are:

  - 0 : quiet
  - 1 : critical messages
  - 2 : error messages
  - 3 : warning messages
  - 4 : info messages

- **debug** (:class:`bool`): Enable debug mode (Default: False). If enabled,
  lots of output is generated, useful for developers.

- **default_paths** (:class:`list` of :class:`str`): List of paths
  to search for :any definitions. (Default: None).

- **architecture_paths** (:class:`~.list` of :class:`~.str`): List of paths
  to search for :class:`~.ISA` definitions. (Default: **default_paths**
  option value).

- **microarchitecture_paths** (:class:`~.list` of :class:`~.str`): List of
  paths to search for :class:`~.Microarchitecture` definitions. (Default:
  **default_paths** option value).

- **environments_paths** (:class:`~.list` of :class:`~.str`): List of paths
  to search for :class:`~.Environment` definitions. (Default: **default_paths**
  option value).

- **template_paths** (:class:`~.list` of :class:`~.str`): List of paths
  to search for template files.

- **wrappers_paths** (:class:`~.list` of :class:`~.str`): List of paths
  to search for :class:`~.Wrapper` definitions.

- **hex_all** (:class:`~.bool`): Use hexadecimal representation for all the
  integers in an instruction assembly string (Default: False). This option
  is mutually exclusive with **hex_address** and **hex_none**.

- **hex_address** (:class:`~.bool`): Use hexadecimal representation for the
  integers in an instruction assembly string that are used in address
  generation arithmetic, such as displacements (Default: True). This option
  is mutually exclusive with **hex_all** and **hex_none**.

- **hex_none** (:class:`~.bool`): Use integer representation for all the
  integers in an instruction assembly string (Default: False). This option
  is mutually exclusive with **hex_address** and **hex_all**.

Environment variables
---------------------

Environment variables can be set to override default configuration options
or the options provided by the configuration files. These are the environ
variable that can be defined:

- **MICROPROBERC**: Extends the default paths to search for the default
  microprobe configuration file. It should be a list of paths separated by
  colons.
- **MICROPROBEDATA**: Extends the default paths to search for target
  definitions (**default_paths** options). It should be a list of paths
  separated by colons.
- **MICROPROBETEMPLATES**: Extends the default base paths for templates.
- **MICROPROBEWRAPPERS**: Extends the default base paths for wrappers.
- **MICROPROBEDEBUG**: If defined, enables the debug mode, i.e. **debug**
  option set to True.
- **MICROPROBEDEBUGPASSES**: If defined, enables the debug mode only for
  passes. i.e. **debug** option set to True while benchmark generation passes
  are being applied.
- **MICROPROBEASMHEXFMT**: Overrides the assembly hex mode format. Valid
  values are: ``hex_all``, ``hex_address``, ``hex_none``. It sets to true
  the corresponding option.
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import ast
import os
import warnings

# Third party modules
import six.moves.configparser as configparser

# Own modules
from microprobe.utils.config import MicroprobeDefaultConfiguration

# Local modules


# Constants

#: Microprobe global configuration dictionary that map configuration options
#: to their values (:class:`~.MicroprobeDefaultConfiguration`).
MICROPROBE_RC = MicroprobeDefaultConfiguration()

#: Default configuration file name (:class:`~.str`).
_DEFAULT_CONFIG_FILE_NAME = "microprobe.cfg"

#: Default locations where to look for the default microprobe configuration
#: file (:class:`~.str`). By default configuration file is search in the
#: installation directory, at the user home directory or in the current
#: execution directory.
_DEFAULT_CONFIG_FILE_LOCATIONS = [
    os.path.join(
        os.path.dirname(__file__), _DEFAULT_CONFIG_FILE_NAME
    ),
    os.path.expanduser('~/.%s' % _DEFAULT_CONFIG_FILE_NAME),
    os.path.join(os.getcwd(), _DEFAULT_CONFIG_FILE_NAME)
]

#: Generic configparser to support the reading of configuration files
#: (:class:`~.ConfigParser`).
_CONFIG = configparser.ConfigParser()

__all__ = ["MICROPROBE_RC"]

# Functions

# Classes

# Initialization
if "MICROPROBERC" in os.environ:
    _DEFAULT_CONFIG_FILE_LOCATIONS = os.environ["MICROPROBERC"].split(":") \
        + _DEFAULT_CONFIG_FILE_LOCATIONS

_CONFIG.read(_DEFAULT_CONFIG_FILE_LOCATIONS)

for section in ["DEFAULT"] + _CONFIG.sections():
    for option, value in _CONFIG.items(section):
        value = value.strip()
        if option in MICROPROBE_RC:
            value = value.replace("MICROPROBE_INSTALL_DIR",
                                  os.path.dirname(__file__))
            if ((value.endswith(']') and value.startswith('[')) or
                    value.replace("0x", "").replace(".", "").isdigit() or
                    value in ['True', 'False']):
                MICROPROBE_RC[option] = ast.literal_eval(value)
            else:
                MICROPROBE_RC[option] = value
        else:
            warnings.warn("Ignoring option: %s" % option)

# Environment configuration
if "MICROPROBEDATA" in os.environ:
    MICROPROBE_RC["default_paths"] += [
        os.path.abspath(path)
        for path in os.environ["MICROPROBEDATA"].split(":")
        if path != ''
    ]
    MICROPROBE_RC["architecture_paths"] += MICROPROBE_RC["default_paths"][:]
    MICROPROBE_RC["microarchitecture_paths"] += \
        MICROPROBE_RC["default_paths"][:]
    MICROPROBE_RC["environment_paths"] += MICROPROBE_RC["default_paths"][:]

if "MICROPROBETEMPLATES" in os.environ:
    MICROPROBE_RC['template_paths'] += [
        os.path.abspath(elem)
        for elem in os.environ["MICROPROBETEMPLATES"].split(":")
        if elem != ''
    ]

if "MICROPROBEWRAPPERS" in os.environ:
    MICROPROBE_RC["wrapper_paths"] += [
        os.path.abspath(elem)
        for elem in os.environ["MICROPROBEWRAPPERS"].split(":")
        if elem != ''
    ]

if "MICROPROBEDEBUG" in os.environ:
    MICROPROBE_RC["debug"] = True

if "MICROPROBEDEBUGPASSES" in os.environ:
    MICROPROBE_RC["debugpasses"] = True

if "MICROPROBEDEBUGWRAPPER" in os.environ:
    MICROPROBE_RC["debugwrapper"] = True

if "MICROPROBEASMHEXFMT" in os.environ:
    if os.environ["MICROPROBEASMHEXFMT"].strip() == "all":
        MICROPROBE_RC["hex_all"] = True
    elif os.environ["MICROPROBEASMHEXFMT"].strip() == "address":
        MICROPROBE_RC["hex_address"] = True
    elif os.environ["MICROPROBEASMHEXFMT"].strip() == "none":
        MICROPROBE_RC["hex_none"] = True
    else:
        warnings.warn("Ignoring option: %s in env var MICROPROBEASMHEXFMT" %
                      os.environ["MICROPROBEASMHEXFMT"])

if "MICROPROBEPARALLELTHRESHOLD" in os.environ:
    try:
        MICROPROBE_RC["parallel_threshold"] = \
            int(os.environ["MICROPROBEPARALLELTHRESHOLD"].strip())
    except ValueError:
        warnings.warn(
            "Ignoring option: %s in env var MICROPROBEPARALLELTHRESHOLD" %
            os.environ["MICROPROBEPARALLELTHRESHOLD"])

if "MICROPROBECPUS" in os.environ:
    try:
        MICROPROBE_RC["cpus"] = \
            int(os.environ["MICROPROBECPUS"].strip())
    except ValueError:
        warnings.warn(
            "Ignoring option: %s in env var MICROPROBECPUS" %
            os.environ["MICROPROBECPUS"])

if "MICROPROBENOCACHE" in os.environ:
    MICROPROBE_RC['no_cache'] = True

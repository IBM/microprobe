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
""":mod:`microprobe.utils.info` module

"""

# Futures
from __future__ import absolute_import

# Own modules
from microprobe import MICROPROBE_RC

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2018 IBM Corporation"
__credits__ = []
__license__ = "Apaceh Version 2.0"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"

# Constants
__all__ = ["AUTHOR",
           "COPYRIGHT",
           "LICENSE",
           "VERSION",
           "MAINTAINER",
           "EMAIL",
           "STATUS",
           "REVISION",
           "WEBSITE",
           "PACKAGEURL",
           "CLASSIFIERS",
           "KEYWORDS"
           ]
AUTHOR = "Ramon Bertran"
COPYRIGHT = "Copyright 2018 IBM Corporation"
LICENSE = "Apache Version 2.0"
VERSION = "0.5"
MAINTAINER = "Ramon Bertran"
EMAIL = "rbertra@us.ibm.com"
STATUS = "Development"
REVISION = MICROPROBE_RC['revision_core']

WEBSITE = "https://github.com/IBM/microprobe"
PACKAGEURL = "https://pypi.org/project/microprobe/",
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: Apache Software License",
    "Natural Language :: English",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python :: 2.7",
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    "Topic :: Scientific/Engineering",
    "Topic :: Scientific/Engineering :: Electronic Design Automation (EDA)",
    "Topic :: Software Development",
    "Topic :: Software Development :: Code Generators",
    "Topic :: Utilities",
]
KEYWORDS = "microprobe microbenchmarks code generation stresstests "\
    "characterization computer architecture microarchitecture"

# Functions

# Classes

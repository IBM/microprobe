#!/usr/bin/env python
# Copyright 2011-2021 IBM Corporation
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
"""
isa_power_v206_info.py

Example module to show how to access to isa definitions.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import os

# Own modules
from microprobe.target.isa import find_isa_definitions, import_isa_definition

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
ISANAME = "power_v206"

# Functions

# Classes

# Main

# Search and import definition
ISADEF = import_isa_definition(
    os.path.dirname(
        [isa for isa in find_isa_definitions()
         if isa.name == ISANAME][0].filename
        )
    )

# Print definition
print((ISADEF.full_report()))
exit(0)

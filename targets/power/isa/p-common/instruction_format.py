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
Docstring
"""
# Futures
from __future__ import absolute_import

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.target.isa.instruction_format import GenericInstructionFormat

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"


# Constants
__all__ = ["PowerInstructionFormat"]

# Functions


# Classes
class PowerInstructionFormat(GenericInstructionFormat):

    """
    Power Instruction Format Class
    """

    def __init__(self, fname, descr, fields, assembly):
        super(PowerInstructionFormat, self).__init__(fname,
                                                     descr,
                                                     fields,
                                                     assembly)

        if self.length != 4:
            raise MicroprobeArchitectureDefinitionError(
                "Instruction format '%s' length: %d is not 4 bytes "
                % (self.name, self.length)
            )

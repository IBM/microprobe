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

# Built-in modules
import imp
import os

# Own modules
from microprobe.utils.logger import get_logger
from microprobe.code.address import Address, InstructionAddress

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.6"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants

_POWERISA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "p-common", "isa.py"
)
_POWERISA_MODULE = imp.load_source(
    '_POWERISA_MODULE', _POWERISA_PATH
)
_MODULE_DIR = os.path.dirname(_POWERISA_PATH)

POWERISACOMMON = __import__(
    "_POWERISA_MODULE",
    globals(),
    locals(),
    [],
    0
).PowerISA

__all__ = ["POWERISAV310"]
LOG = get_logger(__name__)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


# Functions


# Classes
class POWERISAV310(POWERISACOMMON):

    def set_register(self, register, value, context, opt=True):

        LOG.debug("Begin setting '%s' to value '%s'", register, value)
        instrs = []

        current_value = context.get_register_value(register)

        force_reset = False
        if isinstance(current_value, Address):
            force_reset = True

        closest_register = context.get_register_closest_value(register)

        if closest_register is not None:
            closest_value = context.get_register_value(closest_register)
        else:
            closest_value = None

        if context.register_has_value(value):
            present_reg = context.registers_get_value(value)[0]

            if present_reg.type.name != register.type.name:
                present_reg = None

        else:
            present_reg = None

        if register.type.name == "ACC":

            if len(str(value).split("_")) == 2:
                # check for zero case optimization
                item_value = int(str(value).split("_")[0], base=0)
                if item_value == 0:
                    value = 0

            if value == 0:
                xxsetaccz_ins = self.new_instruction("XXSETACCZ_V0")
                xxsetaccz_ins.set_operands([register])
                return [xxsetaccz_ins]

            tregs = [
                self.registers['VSR%d' % (int(register.representation)+i)]
                for i in range(0, 4)
            ]
            for reg in tregs:
                instrs += \
                    super(POWERISAV310, self).set_register(reg, value, context)

            xxmtacc_ins = self.new_instruction("XXMTACC_V0")
            xxmtacc_ins.set_operands([register])
            instrs.append(xxmtacc_ins)

            return instrs

        else:

            return super(POWERISAV310, self).set_register(
                register, value, context
            )

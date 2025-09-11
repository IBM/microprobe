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
from __future__ import absolute_import, annotations

# Built-in modules
import imp
import os
from typing import TYPE_CHECKING, Dict, List

# Own modules
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import Instruction
from microprobe.code.var import Variable, VariableArray
from microprobe.exceptions import MicroprobeCodeGenerationError
from microprobe.target.isa import GenericISA
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import int_to_twocs, twocs_to_int

# This party modules


# Type hints
if TYPE_CHECKING:
    # Own modules
    from microprobe.code.context import Context
    from microprobe.target import Target
    from microprobe.target.isa.instruction import InstructionType
    from microprobe.target.isa.register import Register

_RISCVISA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "riscv-common", "isa.py"
)
_RISCVISA_MODULE = imp.load_source("_RISCVISA_MODULE", _RISCVISA_PATH)
_MODULE_DIR = os.path.dirname(_RISCVISA_PATH)

RISCVISA = __import__("_RISCVISA_MODULE", globals(), locals(), [], 0).RISCVISA

# Constants
LOG = get_logger(__name__)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_RISCV_PCREL_LABEL = 0

# Functions


# Classes
class RISCVISA_BOOM(RISCVISA):

    def get_context(self, variable=None, tmpl_path=None):
        """ """

        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(RISCVISA_BOOM, self).get_context(
            variable=variable, tmpl_path=tmpl_path
        )

    def set_context(self, variable=None, tmpl_path=None):
        """ """
        if tmpl_path is None:
            tmpl_path = _MODULE_DIR

        return super(RISCVISA_BOOM, self).set_context(
            variable=variable, tmpl_path=tmpl_path
        )

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

# Third party modules
import imp
import os

# Own modules
from microprobe.utils.logger import get_logger

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"


# Constants
__all__ = [
    "check_acc_overlap",
    "check_load_string_overlap",
    "POWERInstructionV310"
]
LOG = get_logger(__name__)

_POWERBASELINE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "p-common", "instruction.py"
)
_POWERBASELINE_MODULE = imp.load_source(
    '_POWERBASELINE_MODULE', _POWERBASELINE_PATH
)

PowerInstruction = _POWERBASELINE_MODULE.PowerInstruction
check_load_string_overlap = _POWERBASELINE_MODULE.check_load_string_overlap


# Functions
def check_acc_overlap(instruction, condition):

    def get_latest_operands():
        acc_operands = {}
        vsr_operands = {}

        for idx, operand in enumerate(instruction.operands()):
            if operand.type.name == "ACC_regs":
                acc_operands[idx] = (
                    operand, operand.type.copy(), operand.descriptor.copy()
                )
            elif operand.type.name in ["VSR_regs", "VSR_regpairs"]:
                vsr_operands[idx] = (
                    operand, operand.type.copy(), operand.descriptor.copy()
                )
            else:
                raise NotImplementedError

        assert(len(acc_operands.keys()) == 1)
        return acc_operands, vsr_operands

    orig_acc_operands, orig_vsr_operands = get_latest_operands()

    def get_vsr_func(idx, unset=False):

        def function_set_operand_vsr(value):

            acc_operands, vsr_operands = get_latest_operands()
            operand, otype, odescr = vsr_operands[idx]

            if value is not None:
                assert operand.value == value

            for acc_index in acc_operands:
                acc_operand, acc_type, acc_descr =\
                    acc_operands[acc_index]
                oacc_operand, oacc_type, oacc_descr =\
                    orig_acc_operands[acc_index]

                acc_descr = oacc_descr.copy()
                acc_type = oacc_type.copy()

                acc_operand.set_descriptor(acc_descr)
                acc_descr.set_type(acc_type)

                overlap = []
                for operand, _, _ in vsr_operands.values():
                    if operand.value is None:
                        continue
                    overlap.extend(operand.uses())
                    overlap.extend(operand.sets())
                operlap = set(overlap)

                valid_values = [
                    val for val in acc_type.values()
                    if (val in overlap) == condition
                ]
                acc_type.set_valid_values(valid_values)

                if acc_operand.value is not None:
                    assert acc_operand.value in valid_values

        def function_unset_operand_vsr():
            function_set_operand_vsr(None)

        if unset:
            return function_unset_operand_vsr

        return function_set_operand_vsr

    def get_acc_func(idx, unset=False):

        def function_set_operand_acc(value):

            acc_operands, vsr_operands = get_latest_operands()
            operand, otype, odescr = acc_operands[idx]
            if value is not None:
                assert operand.value == value

            for vsr_index in vsr_operands:
                vsr_operand, vsr_type, vsr_descr = vsr_operands[vsr_index]
                ovsr_operand, ovsr_type, ovsr_descr =\
                    orig_vsr_operands[vsr_index]

                vsr_descr = ovsr_descr.copy()
                vsr_type = ovsr_type.copy()

                vsr_operand.set_descriptor(vsr_descr)
                vsr_descr.set_type(vsr_type)

                if operand.value is not None:
                    overlap = set(operand.uses() + operand.sets())
                else:
                    overlap = set()

                valid_values = [
                    val for val in vsr_type.values()
                    if (val in overlap) == condition
                ]
                vsr_type.set_valid_values(valid_values)

                if vsr_operand.value is not None:
                    assert vsr_operand.value in valid_values

        def function_unset_operand_acc():
            function_set_operand_acc(None)

        if unset:
            return function_unset_operand_acc

        return function_set_operand_acc

    for operand_idx in orig_acc_operands:
        operand, _, _ = orig_acc_operands[operand_idx]

        operand.register_operand_callbacks(
            get_acc_func(operand_idx),
            get_acc_func(operand_idx, unset=True)
        )

    for operand_idx in orig_vsr_operands:
        operand, _, _ = orig_vsr_operands[operand_idx]

        operand.register_operand_callbacks(
            get_vsr_func(operand_idx),
            get_vsr_func(operand_idx, unset=True)
        )


# Classes
class POWERInstructionV310(PowerInstruction, object):

    """
    POWER Instruction v3.10 Class
    """

    pass

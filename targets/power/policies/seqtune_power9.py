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
docstring
"""
# Futures
from __future__ import absolute_import

# Own modules
import microprobe.code
import microprobe.passes.address
import microprobe.passes.branch
import microprobe.passes.decimal
import microprobe.passes.float
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.memory
import microprobe.passes.register
import microprobe.passes.structure
import microprobe.passes.switch
import microprobe.passes.symbol
from microprobe.exceptions import MicroprobePolicyError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RNDINT

__author__ = "Ramon Bertran"
__copyright__ = "Copyright 2011-2021 IBM Corporation"
__credits__ = []
__license__ = "IBM (c) 2011-2021 All rights reserved"
__version__ = "0.5"
__maintainer__ = "Ramon Bertran"
__email__ = "rbertra@us.ibm.com"
__status__ = "Development"  # "Prototype", "Development", or "Production"

# Constants
LOG = get_logger(__name__)
__all__ = ["NAME", "DESCRIPTION", "SUPPORTED_TARGETS", "policy"]

NAME = "seqtune"
DESCRIPTION = "Sequence tune generation policy"
SUPPORTED_TARGETS = [
    "power_v300-power9-ppc64_cronus",
    "power_v300-power9-ppc64_linux_gcc",
    "power_v300-power9-ppc64_mesa"
]


# Functions
def policy(target, wrapper, **kwargs):
    """
    Benchmark generation policy.

    A benchmark generation policy. Given a *target* and a *synthesizeresizer*
    object, this functions adds a predefined set of transformation passes to
    generate microbenchmarks with certain characteristics.

    Extra arguments can be passed to the policy via *kwargs* in order to
    modify the default behavior.

    :param target: Target object
    :type target: :class:`Target`
    :param wrapper: wrapper object
    :type wrapper: :class:`wrapper`
    """

    if target.name not in SUPPORTED_TARGETS:
        raise MicroprobePolicyError(
            "Policy '%s' not valid for target '%s'. Supported targets are:"
            " %s" % (NAME, target.name, ",".join(SUPPORTED_TARGETS))
        )

    sequence = kwargs['instructions']

    floating = False
    vector = False
    for minstr in sequence:
        minstruction = microprobe.code.ins.Instruction()
        minstruction.set_arch_type(minstr)

        for operand in minstruction.operands():
            if operand.type.immediate:
                continue

            if operand.type.float:
                floating = True

            if operand.type.vector:
                vector = True

    synthesizer = microprobe.code.Synthesizer(
        target, wrapper, value=0b01010101
    )

    synthesizer.add_pass(
        microprobe.passes.initialization.ReserveRegistersPass(
            ["GPR0"]
        )
    )

    synthesizer.add_pass(
        microprobe.passes.initialization.InitializeRegisterPass(
            "GPR0", 0
        )
    )

    synthesizer.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=RNDINT
        )
    )

    if vector and floating:
        synthesizer.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                v_value=(1.000000000000001, 64)
            )
        )
    elif vector:
        synthesizer.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                v_value=(RNDINT(), 64)
            )
        )
    elif floating:
        synthesizer.add_pass(
            microprobe.passes.initialization.InitializeRegistersPass(
                fp_value=1.000000000000001
            )
        )

    synthesizer.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(
            kwargs['benchmark_size']
        )
    )

    synthesizer.add_pass(
        microprobe.passes.instruction.SetInstructionTypeBySequencePass(
            sequence,
            # prepend=[target.instructions["ADDI_V0"]] * 12
        )
    )

    for repl in kwargs["replace_every"]:
        synthesizer.add_pass(
            microprobe.passes.instruction.ReplaceInstructionByTypePass(*repl)
        )

    for addl in kwargs["add_every"]:
        synthesizer.add_pass(
            microprobe.passes.instruction.InsertInstructionSequencePass(
                addl[0], every=addl[1])
        )

    synthesizer.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass()
    )

    # cmp 3, 0, reg, reg
    # not taken: test bit should be 1 --> 00100 --> 4
    # take: test bit should be 1 --> 01100 --> 12

    br_list = []
    for elem in kwargs['branch_pattern']:
        if elem == "0":
            br_list.append(4)
        else:
            br_list.append(12)

    synthesizer.add_pass(
        microprobe.passes.instruction.SetInstructionOperandsByOpcodePass(
            ["BC_V0", "BCL_V0", "BCA_V0", "BCLA_V0"],
            0,
            br_list
        )
    )

    synthesizer.add_pass(
        microprobe.passes.initialization.AddInitializationAssemblyPass(
            "cmp 3, 0, 16, 16"
        )
    )
    cr_bit = 14
    synthesizer.add_pass(
        microprobe.passes.instruction.SetInstructionOperandsByOpcodePass(
            ["BC_V0", "BCL_V0", "BCA_V0", "BCLA_V0"],
            1,
            [cr_bit]
        )
    )

    if kwargs["branch_switch"]:
        synthesizer.add_pass(
            microprobe.passes.initialization.AddFinalizationAssemblyPass(
                "crnor %d, %d, %d" % (cr_bit, cr_bit, cr_bit)
            )
        )

    synthesizer.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass()
    )

    synthesizer.add_pass(
        microprobe.passes.memory.GenericMemoryStreamsPass(
            kwargs['memory_streams'],
            switch_stores=kwargs["mem_switch"],
            shift_streams=16,
            warmstores=True
        )
    )

    synthesizer.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass()
    )

    synthesizer.add_pass(
        microprobe.passes.float.InitializeMemoryFloatPass(
            value=1.000000000000001
        )
    )

    synthesizer.add_pass(
        microprobe.passes.decimal.InitializeMemoryDecimalPass(
            value=1
        )
    )

    synthesizer.add_pass(microprobe.passes.branch.BranchNextPass())

    if kwargs["data_switch"]:
        synthesizer.add_pass(
            microprobe.passes.switch.SwitchingInstructions()
        )

    if kwargs['dependency_distance'] < 1:
        synthesizer.add_pass(
            microprobe.passes.register.NoHazardsAllocationPass())

    synthesizer.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=kwargs['dependency_distance']
        )
    )

    synthesizer.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass()
    )

    for minstr in sequence:
        if minstr.disable_asm:
            synthesizer.add_pass(
                microprobe.passes.symbol.ResolveSymbolicReferencesPass(
                    instructions=[minstr])
            )

    fix_branches = False
    for minstr in sequence:
        if minstr.mnemonic in ['BLA', 'BA', 'BCLA', 'BCA']:
            fix_branches = True
            break

    if target.name in [

            "power_v300-power9-ppc64_cronus",
            "power_v300-power9-ppc64_mesa"]:
        synthesizer.add_pass(
            microprobe.passes.initialization.AutoAlignPass(
                [target.instructions["ORI_V1"]],
                [[target.registers["GPR0"],
                  target.registers["GPR0"],
                  0]],
                64
            )
        )

        synthesizer.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass()
        )

    elif target.name == "power_v300-power9-ppc64_linux_gcc":
        pass
    else:
        raise MicroprobePolicyError(
            "Unsupported alignment target: %s" % target.name
        )

    if (not synthesizer.wrapper.context().symbolic or fix_branches):

        synthesizer.add_pass(
            microprobe.passes.address.UpdateInstructionAddressesPass(
                force=True)
        )

        synthesizer.add_pass(
            microprobe.passes.symbol.ResolveSymbolicReferencesPass(
            )
        )

    return synthesizer

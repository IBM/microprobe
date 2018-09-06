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
"""
docstring
"""
# Futures
from __future__ import absolute_import

# Own modules
import microprobe.code
import microprobe.passes.address
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.register
import microprobe.passes.structure
import microprobe.passes.symbol
from microprobe.exceptions import MicroprobePolicyError
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["NAME", "DESCRIPTION", "SUPPORTED_TARGETS", "policy"]

NAME = "debug"
DESCRIPTION = "Debug generation policy"
SUPPORTED_TARGETS = [
    "all"
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

    if (target.name not in SUPPORTED_TARGETS and
            "all" not in SUPPORTED_TARGETS):
        raise MicroprobePolicyError(
            "Policy '%s' not valid for target '%s'. Supported targets are:"
            " %s" % (NAME, target.name, ",".join(SUPPORTED_TARGETS))
        )

    sequence = [kwargs['instruction']]
    synth = microprobe.code.Synthesizer(target, wrapper)
    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=0b0101010
        )
    )
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(
            kwargs['benchmark_size']
        )
    )
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeBySequencePass(
            sequence
        )
    )

    synth.add_pass(microprobe.passes.register.NoHazardsAllocationPass())
    synth.add_pass(
        microprobe.passes.register.DefaultRegisterAllocationPass(
            dd=99, relax=True))
    synth.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass())
    synth.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass())

    return synth

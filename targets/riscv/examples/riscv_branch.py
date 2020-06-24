#!/usr/bin/env python
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

"""Example RISC-V IPC microbenchmark generator

This generates RISC-V microbenchmarks with different branch
patterns.

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser

# Own modules
from microprobe.code import Synthesizer, get_wrapper
from microprobe.exceptions import MicroprobeException
from microprobe.passes import initialization, instruction, register,\
    structure, memory, branch, address, symbol
from microprobe.target import import_definition
from microprobe.utils.misc import RNDINT


class RiscvIpcTest(object):
    """RiscvIpc

    Constructs microbenchmarks with different branch patterns

    """

    def _parse_options(self):
        parser = ArgumentParser(
            description="Example RISC-V IPC microbenchmark generator",
            formatter_class=ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            '--output-dir',
            default='./riscv_ipc',
            help='Output directory to place files'
        )
        parser.add_argument(
            '--isa',
            default='riscv_v22',
            help='Instruction set architecture (and version) to use'
        )
        parser.add_argument(
            '--uarch',
            default='riscv_generic',
            help='Microarchitecture to use'
        )
        parser.add_argument(
            '--env',
            default='riscv64_linux_gcc',
            help='Environment to use'
        )
        parser.add_argument(
            '--loop-size',
            type=int,
            default=10,
            help='Number of instructions in each loop'
        )
        parser.add_argument(
            '--local-branch-pattern',
            default="01010101",
            help='Local branch pattern (string with 0 and 1s)'
        )
        parser.add_argument(
            '--global-branch-pattern',
            default="01010101",
            help='Global branch pattern (String with 0 and 1s)'
        )
        parser.add_argument(
            '--random-branch',
            default=4,
            type=float,
            help='Number specifying ratio of random branches'
                 '(not controlled). If > 1, every N branches will be '
                 'random. E.g. if 1 is specified all branches '
                 'will be random. If 2 is specified, 1 every 2 '
                 'branches will be random. If value < 1, it '
                 'specified the probability of a branch to be '
                 'randomized. Note, you need enough branches in the '
                 'to be able to generate a distribution matching the '
                 'probability specified.'
        )

        parser.add_argument(
            '--switch-pattern',
            default=False,
            action="store_true",
            help='Switch local branch pattern'
        )

        parser.add_argument(
            '--random-ins',
            default=False,
            action="store_true",
            help='Randomize instruction sequence (default: False)'
        )

        parser.add_argument(
            '--braid',
            default=False,
            action="store_true",
            help='Generate a braid of branches to maximize miss'
            'prediction penalty. Otherwise all branches branch to '
            'the next instruction. Default: False.'
        )

        return parser.parse_args()

    def __init__(self):
        self.args = self._parse_options()
        self.target = import_definition(
            str.format("{}-{}-{}",
                       self.args.isa, self.args.uarch, self.args.env)
        )

    def emit(self):

        # Reserve a couple of register to control
        # the branch behavior
        #
        # X0 reserved to avoid using constant 0
        # X5 will be used to store the local branch pattern
        # X6 will be used to store the loop count
        # X7 will be used to store current branch
        # X8 will be used to store constant 1 (we already have
        #    X0 with constant 0)
        reserved_registers = ["X0", "X5", "X6", "X7", "X8"]

        if not os.path.exists(self.args.output_dir):
            os.makedirs(self.args.output_dir)

        # Pick some instructions to add between branches
        valid_instrs = [
            i for i in self.target.isa.instructions.values()
            if i.name in ['ADD_V0', 'MUL_V0', 'LW_V0']]

        valid_instrs_names = [
            i.name for i in self.target.isa.instructions.values()
            if i.name in ['ADD_V0', 'MUL_V0', 'LW_V0']]

        # Add conditional branches
        branch_instrs_names = [
            i.name for i in self.target.isa.instructions.values()
            if i.branch_conditional]

        branch_instrs = [
            i for i in self.target.isa.instructions.values()
            if i.branch_conditional]

        microbenchmarks = []
        cwrapper = get_wrapper('RiscvTestsP')
        synth = Synthesizer(
            self.target,
            cwrapper(endless=True),
            value=0b01010101,
        )

        # Add a building block
        p = structure.SimpleBuildingBlockPass(self.args.loop_size)
        synth.add_pass(p)

        # Reserve registers
        p = initialization.ReserveRegistersPass(reserved_registers)
        synth.add_pass(p)

        # Set instruction type
        random = self.args.random_ins
        if not random:
            sequence = []
            for elem in branch_instrs:
                sequence.extend(valid_instrs)
                sequence.append(elem)
            p = instruction.SetInstructionTypeBySequencePass(
                sequence
            )
        else:
            p = instruction.SetRandomInstructionTypePass(
                   [self.target.isa.instructions[elem]
                    for elem in valid_instrs_names + branch_instrs_names]
            )

        synth.add_pass(p)

        p = initialization.InitializeRegistersPass(
            value=RNDINT,
            fp_value=RNDINT
        )
        synth.add_pass(p)

        # Initialize X5 to local branch pattern
        p = initialization.InitializeRegisterPass(
            "X5",
            int(self.args.local_branch_pattern, 2)
        )
        synth.add_pass(p)

        # Initialize X6 to 0 (loop count)
        p = initialization.InitializeRegisterPass("X6", 0)
        synth.add_pass(p)

        # Initialize X7 to current branch
        p = initialization.AddInitializationAssemblyPass(
            "andi x7, x5, 1"
        )
        synth.add_pass(p)

        # Initialize X8 to 1
        p = initialization.InitializeRegisterPass("X8", 1)
        synth.add_pass(p)

        #
        # Set operands of the conditional branch instructions
        #

        # Operand 1 of all branches will be X7, which contains the
        # current branch value (which changes every iteration)
        p = instruction.SetInstructionOperandsByOpcodePass(
               branch_instrs_names, 1, self.target.isa.registers["X7"],
        )
        synth.add_pass(p)

        # Operand 2 of all branches will be X0 (0) / X8 (1)
        # based on the global pattern provided
        global_pattern_regs = []
        for char in self.args.global_branch_pattern:
            if char == "0":
                global_pattern_regs.append(self.target.isa.registers["X0"])
            else:
                global_pattern_regs.append(self.target.isa.registers["X8"])

        p = instruction.SetInstructionOperandsByOpcodePass(
               branch_instrs_names, 2, global_pattern_regs
        )
        synth.add_pass(p)

        # Randomize branches for BGT 0 every N branches
        p = branch.RandomizeByTypePass(
            branch_instrs,  # instructions to replace
            self.target.isa.instructions['BGE_V0'],  # new instruction
            self.args.random_branch,  # every N instructions or if a value
                                      # between [0,1] the probability of a
                                      # branch to be random
            "slli @@BRREG@@, @@REG@@, @@COUNT@@",  # randomization code
                                                   # to add before branch
            distance=30,  # distance between randomization code and branch
            musage=62,  # max. time @@REG@@ can be used before reset. Do not
                        # set above 63
            reset=('rnd', (-0x7ff, 0x7ff))  # method to randomize register
            )
        synth.add_pass(p)

        # At the end of each iteration, update the loop count
        if not self.args.switch_pattern:
            p = initialization.AddFinalizationAssemblyPass(
                "addi x6, x6, 1 \n" +  # Add +1
                # Compare and reset based on pattern length
                "slti x7, x6, %d\n" % min(
                    64,
                    len(self.args.local_branch_pattern)
                ) +
                "bne x7, x0, 8 \n" +  #
                "addi x6, x0, 0 \n" +  # Reset to zero
                "addi x0, x0, 0"  # nop
            )
            synth.add_pass(p)
        else:
            p = initialization.AddFinalizationAssemblyPass(
                "addi x6, x6, 1 \n" +  # Add +1
                # Compare and reset based on pattern length
                "slti x7, x6, %d\n" % min(
                    64,
                    len(self.args.local_branch_pattern)
                ) +
                "bne x7, x0, 12 \n" +  #
                "addi x6, x0, 0 \n" +  # Reset to zero
                "xori x5, x5, -1 \n" +  # switch branch pattern
                "addi x0, x0, 0"  # nop
            )
            synth.add_pass(p)

        # At the end of each iteration, update the current
        # branch register based on loop count
        p = initialization.AddFinalizationAssemblyPass(
            "srl x7, x5, x6 \n" +
            "andi x7, x7, 1"
        )
        synth.add_pass(p)

        # Model memory operations to ensure correctness
        p = memory.GenericMemoryStreamsPass([[0, 1024, 1, 32, 1, 0, (1, 0)]])
        synth.add_pass(p)

        # Model dependency distance (no dependencies)
        p = register.DefaultRegisterAllocationPass(dd=0)
        synth.add_pass(p)

        # Set target of branches (regarless of taken not taken,
        # branch to next instruction)
        p = address.UpdateInstructionAddressesPass()
        synth.add_pass(p)

        braid = self.args.braid
        if braid:
            p = branch.BranchBraidNextPass(force=True)
            synth.add_pass(p)
        else:
            p = branch.BranchNextPass(force=True)
            synth.add_pass(p)

        microbenchmark = "branch_%s_%s_%d" % (
            self.args.global_branch_pattern,
            self.args.local_branch_pattern,
            self.args.switch_pattern
        )

        print("Generating %s ..." % microbenchmark)
        bench = synth.synthesize()
        synth.save(
            str.format('{}/{}', self.args.output_dir, microbenchmark),
            bench=bench
        )
        print(cwrapper().outputname(
            str.format('{}/{}', self.args.output_dir, microbenchmark)
            ) + " saved!"
        )
        microbenchmarks += [microbenchmark]

        # Emit a Makefile fragment (tests.d) that identifies all tests
        # created
        f = open(str.format('{}/tests.d', self.args.output_dir), 'w')
        f.write(str.format('# Autogenerated by {}\n', sys.argv[0]) +
                'tests = \\\n\t' + '\\\n\t'.join([m for m in microbenchmarks]))
        f.close()


if __name__ == '__main__':
    RiscvIpcTest().emit()

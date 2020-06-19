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

This generates RISC-V microbenchmarks with a range of dependency distances
(the read-after-write distance between registers).

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import math
import os
import sys
import itertools as it
import random
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser

# Own modules
from microprobe.code import Synthesizer, get_wrapper
from microprobe.exceptions import MicroprobeException
from microprobe.passes import initialization, instruction, register,\
    structure, memory, branch
from microprobe.target import import_definition

# Random seed
rs = 0

# Max instruction length for which all permutations are to be computed
MAX_INSTR_PERM_LENGTH = 10


class RiscvIpcTest(object):
    """RiscvIpc

    Constructs microbenchmarks with variable dependency distance

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
            '--dependency-distances',
            '-d',
            type=int,
            nargs='+',
            default=[1, 2, 3, 4, 5],
            help='RAW dependency distances to sweep'
        )
        parser.add_argument(
            '--instructions',
            '-i',
            nargs='+',
            default=['ADD_V0', 'DIV_V0', 'MUL_V0',
                     'FADD.S_V0', 'FDIV.S_V0', 'FMUL.S_V0',
                     'FADD.D_V0', 'FDIV.D_V0', 'FMUL.D_V0'],
            help='An instruction to use'
        )
        parser.add_argument(
            '--loop-size',
            type=int,
            default=10,
            help='Number of instructions in each loop'
        )
        parser.add_argument(
            '--num_permutations',
            type=int,
            required=False,
            default=1,
            help='Number of permutations of instruction sequence (optional)'
        )
        parser.add_argument(
            '--microbenchmark_name',
            type=str,
            required=False,
            help='Microbenchmark name (optional)'
        )
        return parser.parse_args()

    def __init__(self):
        self.args = self._parse_options()
        self.target = import_definition(
            str.format("{}-{}-{}",
                       self.args.isa, self.args.uarch, self.args.env)
        )

    def emit(self):
        # Do not touch pointer registers
        reserved_registers = ["X0", "X1", "X2", "X3", "X4", "X8"]

        instructions_not_found = [
            i for i in self.args.instructions
            if i not in [
                    ix.name for ix in self.target.isa.instructions.values()]]
        if instructions_not_found:
            raise MicroprobeException(
                str.format('Instructions {} not available',
                           instructions_not_found))

        if not os.path.exists(self.args.output_dir):
            os.makedirs(self.args.output_dir)

        valid_instrs = [
            i for i in self.target.isa.instructions.values()
            if i.name in self.args.instructions]

        # Generate permutations of instruction sequences and randomize order
        random.seed(rs)
        instr_seq_count = len(valid_instrs)
        print("Instruction sequence count: "+str(instr_seq_count))

        # Select instruction sequence permutations
        if (self.args.num_permutations > math.factorial(
           min(instr_seq_count, MAX_INSTR_PERM_LENGTH))):
            print("ERROR: Selected sequences cannot exceed num. permutations")
            sys.exit()

        # Check if number of instructions exceeds maximum permutation length
        # -- Fix to prevent permutation function from hanging
        if (instr_seq_count > MAX_INSTR_PERM_LENGTH):
            print("WARNING: Instruction sequence is too long...\
                   Selecting from reduced number of permutations!!")
            reduced_instrs = valid_instrs[0:MAX_INSTR_PERM_LENGTH]
            reduced_instr_seq = list(
                it.permutations(reduced_instrs, len(reduced_instrs)))
            random.shuffle(reduced_instr_seq)
            selected_valid_instr_seq = reduced_instr_seq[:][
                0:self.args.num_permutations]

            # Append remaining instructions to each of the sequences in list
            rem_instr_seq = valid_instrs[MAX_INSTR_PERM_LENGTH:instr_seq_count]
            for s in range(0, len(selected_valid_instr_seq)):
                selected_valid_instr_seq[s] = list(
                    selected_valid_instr_seq[s]) + rem_instr_seq
        else:
            # Generate complete list of permutations
            valid_instr_seq = list(it.permutations(valid_instrs))
            random.shuffle(valid_instr_seq)
            selected_valid_instr_seq = valid_instr_seq[:][
                0:self.args.num_permutations]

        microbenchmarks = []

        # Loop over selected sequence permutations
        for vi in range(0, len(selected_valid_instr_seq)):
            vi_seq = selected_valid_instr_seq[:][vi]
            for d in self.args.dependency_distances:
                microbenchmark = ''
                cwrapper = get_wrapper('RiscvTestsP')
                synth = Synthesizer(
                    self.target,
                    # Remove the endless parameter to not generate
                    # an endless loop
                    cwrapper(endless=True),
                    value=0b01010101,
                )
                passes = [
                    structure.SimpleBuildingBlockPass(self.args.loop_size),
                    instruction.SetInstructionTypeBySequencePass(vi_seq),
                    initialization.ReserveRegistersPass(reserved_registers),
                    branch.BranchNextPass(),
                    memory.GenericMemoryStreamsPass(
                        [[0, 1024, 1, 32, 1, 0, (1, 0)]]
                    ),
                    register.DefaultRegisterAllocationPass(dd=d)
                ]

                for p in passes:
                    synth.add_pass(p)

                if (not self.args.microbenchmark_name):
                    for instr in vi_seq:
                        microbenchmark = microbenchmark
                        + instr.name + '_DD' + str(d)
                else:
                    microbenchmark = self.args.microbenchmark_name \
                        + '_DD' + str(d) + '_' + str(vi)

                print("Generating %s ..." % microbenchmark)
                bench = synth.synthesize()
                synth.save(
                    str.format(
                        '{}/{}',
                        self.args.output_dir,
                        microbenchmark
                    ),
                    bench=bench
                )
                print(cwrapper().outputname(
                    str.format('{}/{}', self.args.output_dir, microbenchmark)
                    ) + " saved!"
                )
                microbenchmarks += [microbenchmark]

        # Print out microbenchmark names
        print("Generating microbenchmarks named:")
        print(microbenchmarks)

        # Emit a Makefile fragment (tests.d) that identifies all tests
        # created
        f = open(str.format('{}/'
                 + self.args.microbenchmark_name
                 + '_tests.d', self.args.output_dir), 'w')
        f.write(str.format('# Autogenerated by {}\n', sys.argv[0]) +
                'tests = \\\n\t' + '\\\n\t'.join([m for m in microbenchmarks]))
        f.close()


if __name__ == '__main__':
    RiscvIpcTest().emit()

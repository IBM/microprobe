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
import os
import sys
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser

# Own modules
from microprobe.code import Synthesizer, get_wrapper
from microprobe.exceptions import MicroprobeException
from microprobe.passes import initialization, instruction, register,\
    structure, memory, branch
from microprobe.target import import_definition


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
                     'FADD.D_V0', 'FDIV.D_V0', 'FMUL.D_V0',
                     'LD_V0', 'LW_V0', 'SD_V0', 'SW_V0'],
            help='An instruction to use'
        )
        parser.add_argument(
            '--loop-size',
            type=int,
            default=10,
            help='Number of instructions in each loop'
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

        microbenchmarks = []
        for instr in valid_instrs:
            for d in self.args.dependency_distances:
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
                    instruction.SetRandomInstructionTypePass([instr]),
                    initialization.ReserveRegistersPass(reserved_registers),
                    branch.BranchNextPass(),
                    memory.GenericMemoryStreamsPass([[0, 1024, 1, 32, 1]]),
                    register.DefaultRegisterAllocationPass(dd=d)
                ]

                for p in passes:
                    synth.add_pass(p)

                microbenchmark = instr.name + '_' + str(d)
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

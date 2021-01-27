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
from __future__ import absolute_import
from __future__ import print_function
import sys
from microprobe.target import import_definition
from microprobe.utils.bin import interpret_bin
from microprobe.code.ins import instruction_from_definition
from microprobe.utils.asm import interpret_asm

target = import_definition(sys.argv[1])
print(sys.argv[2:])

for elem in sys.argv[2:]:
    instr_def = interpret_bin(elem, target)[0]
    instr = instruction_from_definition(instr_def)
    codification = int(instr.binary(), 2)
    assembly = instr.assembly()
    instr_def2 = interpret_asm(assembly, target, [])[0]
    print(hex(codification))
    instr_def3 = interpret_bin(hex(codification)[2:], target)[0]
    instr2 = instruction_from_definition(instr_def2)
    instr3 = instruction_from_definition(instr_def3)
    assert instr.assembly() == instr2.assembly()
    assert instr2.assembly() == instr3.assembly()
    assert instr.binary() == instr2.binary()
    assert instr2.binary() == instr3.binary()
    print(instr3.assembly())

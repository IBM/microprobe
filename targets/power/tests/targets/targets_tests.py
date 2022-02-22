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
from __future__ import absolute_import, print_function

# Built-in modules
import copy
import os
import random
import types
from tempfile import SpooledTemporaryFile, mkstemp
from unittest import TestCase, TestSuite, main, skipIf, skipUnless

# Third party modules
import six
from six.moves import range, zip

# Own modules
import microprobe.code
import microprobe.passes.address
import microprobe.passes.initialization
import microprobe.passes.instruction
import microprobe.passes.register
import microprobe.passes.structure
import microprobe.passes.symbol
from microprobe.target import Target
from microprobe.target.env import import_env_definition
from microprobe.target.isa import import_isa_definition
from microprobe.utils.asm import interpret_asm
from microprobe.utils.bin import interpret_bin
from microprobe.utils.logger import get_logger, set_log_level

if six.PY2:
    import subprocess32 as subprocess  # @UnresolvedImport @UnusedImport
    from exceptions import AssertionError  # pylint: disable=import-error
else:
    import subprocess  # @Reimport


# Constants
LOG = get_logger(__name__)
set_log_level(50)

MP_TESTING_ARCH = os.environ.get("MP_TESTING_ARCH", None)
MP_TESTING_INSTR = os.environ.get("MP_TESTING_INSTR", None)
MP_CI = os.environ.get("TRAVIS", None)

if MP_TESTING_ARCH is None and MP_TESTING_INSTR is None:
    SKIPGENERATION = False
    SKIPCOMPILATION = True
    SKIPCODIFICATION = True
    SKIPSELFBINARY = False
    SKIPSELFASSEMBLY = False
    BENCH_SIZE = 5
    REPETITIONS = 5
    TRIALS = 1
else:
    SKIPGENERATION = False
    SKIPCOMPILATION = False
    SKIPCODIFICATION = False
    SKIPSELFBINARY = False
    SKIPSELFASSEMBLY = False
    BENCH_SIZE = 50
    REPETITIONS = 50
    TRIALS = 3


# Functions
def copy_func(f, name=None):
    return types.FunctionType(f.__code__, copy.copy(f.__globals__),
                              name or f.__name__,
                              f.__defaults__, f.__closure__)


def _rnd():
    """

    """
    return random.randint(0, (2**32))


def subins(instructions):
    """

    :param instructions:
    :type instructions:
    """

    if MP_TESTING_INSTR is not None:
        return [ins for ins in instructions
                if ins.name == MP_TESTING_INSTR]

    if MP_TESTING_ARCH is not None and MP_CI is None:
        return instructions

    myins = []

    for instr in instructions:

        if instr.format not in [ins.format for ins in myins]:
            myins.append(instr)
            continue

        continue

    #    if str(instr.instruction_checks) not in [
    #            str(ins.instruction_checks) for ins in myins]:

    #        myins.append(instr)
    #        continue

    #    if str(instr.target_checks) not in [
    #            str(ins.target_checks) for ins in myins]:

    #        myins.append(instr)
    #        continue

    #    if str(instr.operands) not in [
    #            str(ins.operands) for ins in myins]:

    #        myins.append(instr)
    #        continue

    return myins


def power_v206_function(self):
    """
    power_v206_function
    """

    target = self.target
    instr = target.instructions[self.instr_name]
    sequence = [instr]

    instruction = microprobe.code.ins.Instruction()
    instruction.set_arch_type(instr)

    cwrapper = microprobe.code.get_wrapper("DebugBinaryDouble")

    synth = microprobe.code.Synthesizer(target, cwrapper(), value=_rnd)
    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=_rnd
        )
    )
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(
            BENCH_SIZE
        )
    )
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeBySequencePass(
            sequence
        )
    )
    # synth.add_pass(microprobe.passes.branch.BranchNextPass())
    synth.add_pass(microprobe.passes.register.RandomAllocationPass())
    # synth.add_pass(microprobe.passes.register.NoHazardsAllocationPass())
    # synth.add_pass(
    #     microprobe.passes.register.DefaultRegisterAllocationPass(
    #        dd=99))
    synth.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass())
    synth.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass())
    bench = synth.synthesize()

    filename = self.filename[0][:-2]
    synth.save(filename, bench=bench)


def power_v300_function(self):
    """
    power_v300_function
    """

    target = self.target
    instr = target.instructions[self.instr_name]
    sequence = [instr]

    instruction = microprobe.code.ins.Instruction()
    instruction.set_arch_type(instr)

    cwrapper = microprobe.code.get_wrapper("DebugBinaryDouble")

    synth = microprobe.code.Synthesizer(target, cwrapper(), value=_rnd)
    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=_rnd
        )
    )
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(
            BENCH_SIZE
        )
    )
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeBySequencePass(
            sequence
        )
    )
    # synth.add_pass(microprobe.passes.branch.BranchNextPass())
    synth.add_pass(microprobe.passes.register.RandomAllocationPass())
    # synth.add_pass(microprobe.passes.register.NoHazardsAllocationPass())
    # synth.add_pass(
    #    microprobe.passes.register.DefaultRegisterAllocationPass(
    #        dd=99))
    synth.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass())
    synth.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass())
    bench = synth.synthesize()

    filename = self.filename[0][:-2]
    synth.save(filename, bench=bench)


def power_v310_function(self):
    """
    power_v310_function
    """

    target = self.target
    instr = target.instructions[self.instr_name]
    sequence = [instr]

    instruction = microprobe.code.ins.Instruction()
    instruction.set_arch_type(instr)

    cwrapper = microprobe.code.get_wrapper("DebugBinaryDouble")

    synth = microprobe.code.Synthesizer(target, cwrapper(), value=_rnd)
    synth.add_pass(
        microprobe.passes.initialization.InitializeRegistersPass(
            value=_rnd
        )
    )
    synth.add_pass(
        microprobe.passes.structure.SimpleBuildingBlockPass(
            BENCH_SIZE
        )
    )
    synth.add_pass(
        microprobe.passes.instruction.SetInstructionTypeBySequencePass(
            sequence
        )
    )
    # synth.add_pass(microprobe.passes.branch.BranchNextPass())
    synth.add_pass(microprobe.passes.register.RandomAllocationPass())
    # synth.add_pass(microprobe.passes.register.NoHazardsAllocationPass())
    # synth.add_pass(
    #    microprobe.passes.register.DefaultRegisterAllocationPass(
    #        dd=99))
    synth.add_pass(
        microprobe.passes.address.UpdateInstructionAddressesPass())
    synth.add_pass(
        microprobe.passes.symbol.ResolveSymbolicReferencesPass())
    bench = synth.synthesize()

    filename = self.filename[0][:-2]
    synth.save(filename, bench=bench)


def compile_benchmark(self, function):
    """

    :param function:
    :type function:
    """

    getattr(self, function)()

    # Compile
    compiler = os.environ[self.compiler_bin]
    if self.compiler_flags in os.environ:
        flags = os.environ[self.compiler_flags].split(" ")
    else:
        flags = []

    flags.append("-c")
    flags.append(self.filename[0])
    flags.append("-o")
    flags.append(self.filename[0].replace(".s", ".o"))

    cmd = [compiler] + flags

    tfile = SpooledTemporaryFile()

    try:
        error_code = subprocess.check_call(
            cmd, stdout=tfile,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as exc:
        error_code = exc.returncode

    if error_code == 0:
        self.filename.append(self.filename[0].replace(".s", ".o"))
        return
    else:
        tfile.seek(0)
        print("Compiler output:")
        print(tfile.read(0))

    # Assemble directly (it might be needed for some situations, where
    # the gcc is not updated but GNU gas is updated

    # Assemble
    assembler = os.environ[self.compiler_bin].replace("gcc", "as")
    if self.asm_flags in os.environ:
        flags = os.environ[self.asm_flags].split(" ")
    else:
        flags = []

    flags.append(self.filename[0])
    flags.append("-o")
    flags.append(self.filename[0].replace(".s", ".o"))

    cmd = [assembler] + flags
    print(" ".join(cmd))

    error_code = 0
    try:
        cmd_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        error_code = exc.returncode
        cmd_output = exc.output

    if six.PY3:
        cmd_output = cmd_output.decode()

    if error_code == 0:
        self.filename.append(self.filename[0].replace(".s", ".o"))
        return

    # Analyze the output to check if this fail is related to microprobe
    # or related to the tool-chain used
    if cmd_output.find("Error: unrecognized opcode:") > -1:
        # Compiler not new enough or check compilation options
        # DO NOT REPORT FAILURE but not PASS
        self.fail(
            msg="Update your toolchain: %s not supported\n%s" % (
                self.instr_name, _process_as_output(cmd_output)
            )
        )

    self.fail(
        msg="Error compiling using cmd: %s. Output: %s" % (
            cmd, _process_as_output(cmd_output)
        )
    )


def binary_benchmark(self, function):
    """

    :param function:
    :type function:
    """

    getattr(self, function)()

    # Strip
    stripper = os.environ[self.compiler_bin].replace("gcc", "strip")

    flags = []
    flags.append(self.filename[1])

    cmd = [stripper] + flags

    tfile = SpooledTemporaryFile()

    error_code = subprocess.check_call(
        cmd, stdout=tfile,
        stderr=subprocess.STDOUT
    )

    if error_code != 0:
        tfile.seek(0)
        print(tfile.read())

    self.assertEqual(error_code, 0)

    # Disassemble
    disassembler = os.environ[self.compiler_bin].replace("gcc", "objdump")

    if self.dump_flags in os.environ:
        flags = os.environ[self.dump_flags].split(" ")
    else:
        flags = []

    flags.append("-w")
    flags.append("-d")
    flags.append(self.filename[1])

    cmd = [disassembler] + flags
    output = subprocess.check_output(cmd)
    if six.PY3:
        output = output.decode()
    output_lines = output.split("\n")

    asmline = ""
    asmline_bin = ""
    for idx, line in enumerate(output_lines[6:]):

        if line.strip() == "":
            continue

        line = line.split(":")[1].strip()
        line_bin = line.split("\t")[0]

        if idx % 2 == 1:
            asmline = line
            asmline_bin = line_bin
        else:
            print(self.filename[1])
            print("'%s' <-> '%s'" % (line, asmline))
            print("'%s' = '%s' ?" % (line_bin, asmline_bin))
            self.assertEqual(line_bin, asmline_bin)


def self_codification_function(self):
    """
    self_codification_function
    """

    target = self.target
    instr = target.instructions[self.instr_name]

    repetition = 0
    while repetition < REPETITIONS:

        values = []
        for trial in range(0, TRIALS):

            try:

                print("Trial: %s" % trial)

                instruction = microprobe.code.ins.Instruction()
                instruction.set_arch_type(instr)

                for idx, operand in enumerate(instruction.operands()):
                    if idx >= len(values):
                        values.append(operand.type.random_value())
                    operand.set_value(values[idx])

                print("Operands to set: %s" % values)

                codification = int(instruction.binary(), 2)
                code_len = len(instruction.binary())
                codefmt = "%%0%dX" % (code_len / 4)
                codification = codefmt % codification

                print("Codification: 0x%s" % codification)
                print("Assembly: %s" % instruction.assembly())

                instr_def = interpret_bin(
                    codification,
                    target,
                    single=True
                )[0]
                print("%s == %s ?" % (instr, instr_def.instruction_type))

                self.assertEqual(instr.mnemonic,
                                 instr_def.instruction_type.mnemonic)

                for orig_operand, new_operand in zip(
                        instruction.operands(), instr_def.operands
                        ):

                    print("%s == %s ?" % (orig_operand.value, new_operand))
                    print("%s == %s ?" % (type(orig_operand.value),
                                          type(new_operand)))
                    self.assertEqual(orig_operand.value, new_operand)

                print("CODE OK")
                break

            except (NotImplementedError, AssertionError) as exc:
                print(exc)
                if trial == TRIALS - 1:
                    raise exc

        repetition += 1

    self.assertEqual(repetition, REPETITIONS)


def self_assembly_function(self):
    """
    self_assembly_function
    """

    target = self.target
    instr = target.instructions[self.instr_name]

    repetition = 0
    while repetition < REPETITIONS:
        instruction = microprobe.code.ins.Instruction()
        instruction.set_arch_type(instr)

        print(instruction)

        for operand in instruction.operands():
            operand.set_value(operand.type.random_value())
            print(operand)

        assembly = instruction.assembly()
        print("Assembly: %s" % instruction.assembly())

        instr_def = interpret_asm([assembly], target, [])[0]

        print("%s == %s ?" % (instr, instr_def.instruction_type))

        for trial in range(0, TRIALS):

            print("Trial: %s" % trial)
            try:

                if instr == instr_def.instruction_type:
                    break

            except NotImplementedError:

                if trial == TRIALS - 1:
                    self.assertEqual(instr, instr_def.instruction_type)

        for orig_operand, new_operand in zip(
            instruction.operands(), instr_def.operands
        ):

            print("%s == %s ?" % (orig_operand.value, new_operand))
            self.assertEqual(orig_operand.value, new_operand)

        repetition += 1

    self.assertEqual(repetition, REPETITIONS)


def _check_env(env_name):
    """

    :param env_name:
    :type env_name:
    """
    return env_name in os.environ


def _check_executable(env_name):
    """

    :param env_name:
    :type env_name:
    """

    if not _check_env(env_name):
        return False

    fpath = os.environ[env_name]

    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


def _process_as_output(input_str):
    """

    :param input_str:
    :type input_str:
    """

    input_lines = input_str.split("\n")
    output_lines = []
    for idx, line in enumerate(input_lines):
        if idx == 0:
            asm_file = line.split(":")[0]
            asm_fd = open(asm_file, 'r')
            asm_lines = asm_fd.readlines()
            continue

        if line == "":
            continue

        split_line = line.split(":")
        print("%s" % split_line)

        asm_file = split_line[0]
        number = split_line[1]
        as_type = split_line[2]
        as_string = ":".join(split_line[3:])

        asm_line = asm_lines[int(number) - 1][:-1]

        output_lines.append(
            " : ".join(
                [
                    asm_file, number, as_type, as_string, asm_line
                ]
            )
        )

    return "\n".join(output_lines)


def load_tests(loader, dummy_tests, dummy_pattern):
    """

    :param loader:
    :type loader:
    :param dummy_tests:
    :type dummy_tests:
    :param dummy_pattern:
    :type dummy_pattern:
    """

    suite = TestSuite()

    for test_class in TEST_CLASSES:

        target_suite = TestSuite()
        target_tests = loader.loadTestsFromTestCase(test_class)
        target_suite.addTests(target_tests)
        suite.addTest(target_suite)

    return suite


# Classes
TARGETS = []

if MP_TESTING_ARCH == "POWER7":
    TARGETS = [(
        'power_v206',
        power_v206_function,
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "isa", "p-v2_06"
        ),
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "env", "powerpc64_linux_gcc.py"
        ),
        # ['SLBFEEx_V0', 'TLBIE_V0']
        ['MTCRF_V0'],
        ['LSWX_V0', 'LMW_V0', 'LSWI_V0', 'BA_V0', 'BCA_V0',
            'BCCTR_V0', 'BCLA_V0', 'BCLRL_V0', 'BCLR_V0',
            'BCCTRL_V0', 'BC_V0', 'BCL_V0']
    )]
elif MP_TESTING_ARCH == "POWER8":
    TARGETS = [(
        'power_v207', power_v206_function, os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "isa", "p-v2_07"
        ), os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "env", "powerpc64_linux_gcc.py"
        ), ['MTCRF_V0'],
        ['LSWX_V0', 'LMW_V0', 'LSWI_V0', 'LQARX_V0',
            'BA_V0', 'BCA_V0', 'BCTAR_V0', 'BCTARL_V0',
            'BCCTR_V0', 'BCLA_V0', 'BCLRL_V0', 'BCLR_V0',
            'BCCTRL_V0', 'BC_V0', 'BCL_V0']
    )
    ]
elif MP_TESTING_ARCH == "POWER9":
    TARGETS = [(
        'power_v300', power_v300_function, os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "isa", "p-v3_00"
        ), os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "env", "powerpc64_linux_gcc.py"
        ), ['MTCRF_V0'],
        ['LSWX_V0', 'LMW_V0', 'LSWI_V0', 'LQARX_V0',
            'BA_V0', 'BCA_V0', 'BCTAR_V0', 'BCTARL_V0',
            'BCCTR_V0', 'BCLA_V0', 'BCLRL_V0', 'BCLR_V0',
            'BCCTRL_V0', 'BC_V0', 'BCL_V0']
        + ['LFDPX_V0', 'LFDP_V0', 'RFSCV_V0', 'SCV_V0',
           'SLBIAG_V0', 'STFDPX_V0']
    )
    ]
elif MP_TESTING_ARCH == "POWER10":
    TARGETS = [(
        'power_v310', power_v310_function, os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "isa", "p-v3_10"
        ), os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "env", "powerpc64_linux_gcc.py|ppc64le_linux_gcc"
        ), ['MTCRF_V0', 'STMW_V0', 'STSWI_V0', 'STSWX_V0'],
        ['LSWX_V0', 'LMW_V0', 'LSWI_V0', 'LQARX_V0',
            'BA_V0', 'BCA_V0', 'BCTAR_V0', 'BCTARL_V0',
            'BCCTR_V0', 'BCLA_V0', 'BCLRL_V0', 'BCLR_V0',
            'BCCTRL_V0', 'BC_V0', 'BCL_V0']
        # Toolchain unsupported
        + ['LFDPX_V0', 'LFDP_V0', 'RFSCV_V0', 'SCV_V0',
           'SLBIAG_V0', 'STFDPX_V0']
        + ['MSGCLRU_V0', 'MSGSNDU_V0', 'STFDP_V0']
    )
    ]
elif MP_TESTING_ARCH is None:
    TARGETS = [(
        'power_v310', power_v310_function, os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "isa", "p-v3_10"
        ), os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "env", "powerpc64_linux_gcc.py|ppc64le_linux_gcc"
        ), ['MTCRF_V0', 'STMW_V0', 'STSWI_V0', 'STSWX_V0'],
        ['LSWX_V0', 'LMW_V0', 'LSWI_V0']
    )
    ]


TEST_CLASSES = []
for name, gen_function, isa_path, env_path, \
        expected_fails, unsupported in TARGETS:

    # py2lint: disable=cell-var-from-loop
    isa_obj = import_isa_definition(isa_path)

    if len(env_path.split("|")) > 1:
        env_name = env_path.split("|")[1]
        env_path = env_path.split("|")[0]
    else:
        env_path = env_path.split("|")[0]
        env_name = None

    class TestTarget(TestCase):  # pylint: disable=too-many-public-methods
        """
        TestTarget Test Class.
        """

        name = name
        isa_path = isa_path
        env_path = env_path
        gen_function = gen_function
        compiler_bin = "MP_TESTING_COMPILER_%s" % (name.upper())
        compiler_flags = "MP_TESTING_CFLAGS_%s" % (name.upper())
        asm_flags = "MP_TESTING_AFLAGS_%s" % (name.upper())
        dump_flags = "MP_TESTING_DFLAGS_%s" % (name.upper())

        _multiprocess_can_split_ = True

        description = name

        def __init__(self, methodName='runTest'):
            # pylint: disable=E1003
            super(self.__class__, self).__init__(methodName=methodName)
            self.instr_name = getattr(self, methodName).__doc__.split(" ")[1]

        @classmethod
        def setUpClass(cls):
            cls.isa_obj = import_isa_definition(cls.isa_path)
            cls.env_obj = import_env_definition(
                cls.env_path, cls.isa_obj, definition_name=env_name
            )
            cls.target = Target(cls.isa_obj, env=cls.env_obj)

        @classmethod
        def tearDownClass(cls):
            pass

        def setUp(self):
            tempfile = mkstemp(
                prefix="microprobe_%s_%s_" % (
                    self.name, self.instr_name
                ),
                suffix=".s"
            )
            os.close(tempfile[0])
            self.filename = [tempfile[1]]

        def tearDown(self):
            for filename in self.filename:
                os.unlink(filename)

    newclass = type(
        "isa_%s" % name, TestTarget.__bases__, dict(TestTarget.__dict__)
    )

    globals().pop("TestTarget")

    for instr_name in [
            elem.name for elem in subins(
            list(isa_obj.instructions.values()))]:

        if not SKIPGENERATION:
            #
            # Generation function
            #
            f1name = "test_%s_instruction_%s_001_generation" % (
                name, instr_name.replace(".", "_")
            )

            @skipIf(
                instr_name in unsupported,
                "Unsupported instruction (implement in microprobe when time "
                "permits)"
            )
            def function_1(self):
                """
                function_1
                """
                return self.gen_function()

            setattr(newclass, f1name, copy_func(function_1, f1name))

            if six.PY2:
                mfunc = getattr(getattr(newclass, f1name), "__func__")
            else:
                mfunc = getattr(newclass, f1name)

            setattr(mfunc, "__doc__", "%s %s Generation" % (
                    name, instr_name
                    )
                    )
            mfunc.__name__ = f1name

            globals().pop("mfunc")
            globals().pop("f1name")
            globals().pop("function_1")

        if not SKIPCOMPILATION:
            #
            # Compilation function
            #
            f2name = "test_%s_instruction_%s_002_compilation" % (
                name, instr_name.replace(".", "_")
            )

            @skipUnless(
                _check_env(
                    newclass.compiler_bin  # pylint: disable=no-member
                ),
                "Requires environment variable %s to be set" %
                newclass.compiler_bin  # pylint: disable=no-member
            )
            @skipUnless(
                _check_executable(
                    newclass.compiler_bin  # pylint: disable=no-member
                ),
                "Environment variable %s not set to a correct executable" %
                newclass.compiler_bin  # pylint: disable=no-member
            )
            @skipIf(
                instr_name in expected_fails,
                "Tool-chain does not support this instruction. Update it or "
                "send a bug report"
            )
            def function_2(xinstr):
                """

                :param xinstr:
                :type xinstr:
                """
                return compile_benchmark(
                    xinstr, "test_%s_instruction_%s_001_generation" %
                    (xinstr.name, xinstr.instr_name.replace(".", "_"))
                )

            setattr(newclass, f2name, copy_func(function_2, f2name))

            if six.PY2:
                mfunc = getattr(getattr(newclass, f2name), "__func__")
            else:
                mfunc = getattr(newclass, f2name)

            setattr(mfunc, "__doc__", "%s %s Compilation" % (
                    name, instr_name
                    )
                    )
            mfunc.__name__ = f2name

            globals().pop("mfunc")
            globals().pop("f2name")
            globals().pop("function_2")

        if not SKIPCODIFICATION:
            #
            # Codification function
            #
            f3name = "test_%s_instruction_%s_003_codification" % (
                name, instr_name.replace(".", "_")
            )
            setattr(
                newclass, f3name, lambda x: binary_benchmark(
                    x, "test_%s_instruction_%s_002_compilation" %
                    (x.name, x.instr_name.replace(".", "_"))))

            if six.PY2:
                mfunc = getattr(getattr(newclass, f3name), "__func__")
            else:
                mfunc = getattr(newclass, f3name)

            setattr(mfunc, "__doc__", "%s %s Codification" % (
                    name, instr_name
                    )
                    )

            mfunc.__name__ = f3name
            globals().pop("f3name")
            globals().pop("mfunc")

        if not SKIPSELFBINARY:
            #
            # Self codification function
            #
            f4name = "test_%s_instruction_%s_004_self_codification" % (
                name, instr_name.replace(".", "_")
            )

            @skipIf(
                instr_name in unsupported,
                "Unsupported instruction (implement in microprobe when time "
                "permits)"
            )
            def function_4(self):
                """
                function_4
                """
                return self_codification_function(self)

            setattr(newclass, f4name, copy_func(function_4, f4name))

            if six.PY2:
                mfunc = getattr(getattr(newclass, f4name), "__func__")
            else:
                mfunc = getattr(newclass, f4name)

            setattr(mfunc, "__doc__", "%s %s Self-Codification" % (
                    name, instr_name
                    )
                    )
            mfunc.__name__ = f4name

            globals().pop("f4name")
            globals().pop("function_4")
            globals().pop("mfunc")

        if not SKIPSELFASSEMBLY:
            #
            # Self assembly function
            #
            f5name = "test_%s_instruction_%s_005_self_assembly" % (
                name, instr_name.replace(".", "_")
            )

            @skipIf(
                instr_name in unsupported,
                "Unsupported instruction (implement in microprobe when time "
                "permits)"
            )
            def function_5(self):
                """
                function_5
                """
                return self_assembly_function(self)

            setattr(newclass, f5name, copy_func(function_5, f5name))

            if six.PY2:
                mfunc = getattr(getattr(newclass, f5name), "__func__")
            else:
                mfunc = getattr(newclass, f5name)

            setattr(mfunc, "__doc__", "%s %s Self-Assembly" % (
                    name, instr_name
                    )
                    )
            mfunc.__name__ = f5name

            globals().pop("mfunc")
            globals().pop("f5name")
            globals().pop("function_5")

    TEST_CLASSES.append(
        type(
            "isa_%s" % name, newclass.__bases__, dict(newclass.__dict__)
        )
    )
    globals().pop("newclass")

for test_class in TEST_CLASSES:
    globals()[test_class.__name__] = test_class

if "test_class" in globals():
    globals().pop("test_class")

if __name__ == '__main__':
    main()

globals().pop("TEST_CLASSES")

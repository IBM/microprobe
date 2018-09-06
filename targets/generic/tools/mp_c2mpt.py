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
"""
File: mp_c2mpt

This script processes a C file and generates the corresponding
mpt file. The C file should follow a set of conventions, which are documented
in the templace provided as well as in the web documentation.
"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import ast
import io
import os
import shutil
import sys
from tempfile import mkstemp

# Third party modules
import six
from six.moves import range

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address
from microprobe.code.ins import instruction_to_definition
from microprobe.target import import_definition
from microprobe.utils.cmdline import CLI, existing_file_ext, \
    int_type, new_file_ext, print_error, print_info, print_warning
from microprobe.utils.misc import findfiles
from microprobe.utils.mpt import MicroprobeTestVariableDefinition, \
    mpt_configuration_factory, mpt_parser_factory, \
    variable_to_test_definition
from microprobe.utils.objdump import interpret_objdump
from microprobe.utils.run import run_cmd, \
    run_cmd_output, run_cmd_output_redirect


# Constants
_RM_FILES = []


# Functions
def c2mpt(target, arguments):
    """

    :param target:
    :type target:
    :param arguments:
    :type arguments:
    """

    input_file = arguments["input_c_file"]
    data_init = None
    if "no_data_initialization" not in arguments:
        data_init = c2mpt_local_run(input_file, arguments)

    objdump_file = c2mpt_objdump(input_file, arguments)
    dump_mpt(objdump_file, target, data_init, arguments)


def c2mpt_local_run(input_file, arguments):
    """

    :param input_file:
    :type input_file:
    :param arguments:
    :type arguments:
    """

    print_info("Compiling program for host")

    cprog = arguments["host_c_compiler"]
    cflags = " -std=c99"
    cflags += " -DMPT_BASE_ADDRESS=%d" % arguments.get("host_displacement",
                                                       0)
    cflags += " ".join([" -I \"" + elem + "\""
                        for elem in MICROPROBE_RC['template_paths']])
    cflags += " \"%s\"" % findfiles(MICROPROBE_RC['template_paths'],
                                    "c2mpt.c$")[0]
    cflags += " -Wl,--section-start,microprobe.text="
    cflags += hex(arguments["default_code_address"])
    cflags += " -Wl,--section-start,microprobe.data="
    cflags += hex(arguments["default_data_address"])
    cflags += " " + arguments["host_c_compiler_flags"]

    suffix = ".host.bin"
    if "save_temps" in arguments:
        compile_file = input_file.rstrip(".c") + suffix
    else:
        compile_file = _temp_file(suffix=suffix)
        _RM_FILES.append(compile_file)

    cmd = "\"%s\" %s \"%s\" -o \"%s\"" % (
        cprog, cflags, input_file, compile_file
    )

    print_info("Executing compilation command")
    run_cmd(cmd)

    print_info("Executing the compiled program")
    vardefinitions = run_cmd_output("%s" % compile_file)

    return vardefinitions


def c2mpt_objdump(input_file, arguments):
    """

    :param input_file:
    :type input_file:
    :param arguments:
    :type arguments:
    """

    print_info("Compiling program for target")

    cprog = arguments["target_c_compiler"]
    cflags = " -std=c99"
    cflags += " ".join([" -I \"" + elem + "\""
                        for elem in MICROPROBE_RC['template_paths']])
    cflags += " \"%s\"" % findfiles(MICROPROBE_RC['template_paths'],
                                    "c2mpt.c$")[0]
    cflags += " -Wl,--section-start,microprobe.text="
    cflags += hex(arguments["default_code_address"])
    cflags += " -Wl,--section-start,microprobe.data="
    cflags += hex(arguments["default_data_address"])
    cflags += " " + arguments["target_c_compiler_flags"]

    suffix = ".target.bin"
    if "save_temps" in arguments:
        compile_file = input_file.rstrip(".c") + suffix
    else:
        compile_file = _temp_file(suffix=suffix)
        _RM_FILES.append(compile_file)

    cmd = "\"%s\" %s \"%s\" -o \"%s\"" % (
        cprog, cflags, input_file, compile_file
    )
    print_info("Executing compilation command")
    run_cmd(cmd)

    objdumpprog = arguments["target_objdump"]
    objdumpflags = " -D -z -j microprobe.data -j microprobe.text"

    suffix = ".target.dump"
    if "save_temps" in arguments:
        objdump_file = input_file.rstrip(".c") + suffix
    else:
        objdump_file = _temp_file(suffix=suffix)
        _RM_FILES.append(objdump_file)

    cmd = "\"%s\" %s \"%s\"" % (objdumpprog, objdumpflags, compile_file)
    run_cmd_output_redirect(cmd, objdump_file)
    print_info("Executing objdump command")
    return objdump_file


def dump_mpt(input_file, target, init_data, arguments):
    """

    :param input_file:
    :type input_file:
    :param target:
    :type target:
    :param init_data:
    :type init_data:
    :param arguments:
    :type arguments:
    """

    input_file_fd = io.open(input_file, 'r')
    contents = input_file_fd.read()

    if six.PY2:
        contents = contents.encode("ascii")
    elif six.PY3:
        pass

    print_info("Parsing input file...")

    var_defs, req_defs, instr_defs = \
        interpret_objdump(contents, target,
                          strict=arguments.get('strict', False),
                          sections=["microprobe.text"])

    print_info("Input file parsed")

    print_info(
        "%d instructions processed from the input file" % len(instr_defs)
    )

    if var_defs != []:
        print_info(
            "Variables referenced and detected in the dump: %s" %
            ','.join([var.name for var in var_defs])
        )

    if req_defs != []:
        print_warning(
            "Variables referenced and *NOT* detected in the dump: %s" %
            ','.join([var.name for var in req_defs])
        )
        print_warning(
            "You might need to edit the generated MPT to fix the"
            " declaration of such variables"
        )

    print_info("Generating the MPT contents...")

    mpt_config = mpt_configuration_factory()

    mpt_config.set_default_code_address(arguments['default_code_address'])
    mpt_config.set_default_data_address(arguments['default_data_address'])

    kwargs = {}
    if "stack_name" in arguments:
        kwargs["stack_name"] = arguments["stack_name"]
    if "stack_address" in arguments:
        kwargs["stack_address"] = Address(
            base_address="code",
            displacement=arguments["stack_address"]
        )

    variables, instructions = target.elf_abi(
        arguments["stack_size"], "c2mpt_function", **kwargs
    )

    for variable in variables:
        req_defs.append(variable_to_test_definition(variable))

    address = instr_defs[0].address
    for instr in reversed(instructions):
        instr_defs = [instruction_to_definition(instr)] + instr_defs
        address -= instr.architecture_type.format.length

    if address.displacement < 0:
        print_error(
            "Default code address is below zero after"
            " adding the initialization code."
        )
        print_error(
            "Check/modify the objdump provided or do not use"
            " the elf_abi flag."
        )
        _exit(-1)

    if "end_branch_to_itself" in arguments:
        instr = target.branch_to_itself()
    else:
        instr = target.nop()

    instr.set_label("ELF_ABI_EXIT")
    instr_defs.append(instruction_to_definition(instr))

    mpt_config.set_default_code_address(address.displacement)

    initialized_variables = {}

    mindisplacement = None
    print(type(init_data))
    for data in init_data.split('\n'):

        if data.strip() == "":
            continue

        if data.startswith("WARNING"):
            print_warning(data.split(":")[1].strip())
            continue

        name = data.split("=")[0].strip()
        values = ast.literal_eval(data.split("=")[1].strip())
        initialized_variables[name] = values

        if mindisplacement is None:
            mindisplacement = values[2]
            # TODO: this is unsafe. We should compute the real size
            maxdisplacement = values[2] + (values[1] * 8)
        else:
            mindisplacement = min(values[2],
                                  mindisplacement)
            maxdisplacement = max(values[2] + (values[1] * 8),
                                  maxdisplacement)

    if "host_displacement" in arguments:
        mindisplacement = arguments.get("host_displacement",
                                        mindisplacement)

    for name, values in initialized_variables.items():
        values[2] = values[2] - mindisplacement + \
            arguments['default_data_address']

    if 'fix_displacement' in arguments:
        for name, values in initialized_variables.items():
            if "*" in values[0] and isinstance(values[4], list):
                new_values = []
                for value in values[4]:
                    if value <= maxdisplacement and value >= mindisplacement:
                        value = value - mindisplacement + \
                            arguments['default_data_address']
                    new_values.append(value)
                values[4] = new_values
            elif "*" in values[0] and isinstance(values[4], int):
                if (values[4] <= maxdisplacement and
                        values[4] >= mindisplacement):
                    values[4] = values[4] - mindisplacement + \
                        arguments['default_data_address']
            elif values[0] == "uint8_t" and isinstance(values[4], list):
                if len(values[4]) > 8:
                    new_values = "".join(
                        ["%02x" % elem for elem in values[4]]
                    )

                    # Enable this for testing switched endianness
                    # new_values = [new_values[idx:idx + 2]
                    #              for idx in range(0, len(new_values), 2)]
                    # new_values = new_values[::-1]
                    # new_values = "".join(new_values)

                    new_values = _fix_displacement(new_values,
                                                   mindisplacement,
                                                   maxdisplacement,
                                                   arguments)

                    values[4] = [int(new_values[idx:idx + 2], 16)
                                 for idx in range(0, len(new_values), 2)]

    for name, values in initialized_variables.items():

        mpt_config.register_variable_definition(
            MicroprobeTestVariableDefinition(
                name, *values
            )
        )
        print_info("Init values for variable '%s' parsed" % name)

    for var in var_defs + req_defs:
        if var.name in list(initialized_variables.keys()):
            continue
        if var.name != arguments["stack_name"]:
            print_warning(
                "Variable '%s' not registered in the C file "
                "using the macros provided!" % var.name
            )
        mpt_config.register_variable_definition(var)

    mpt_config.register_instruction_definitions(instr_defs)

    print_info("Dumping MPT to '%s'" % arguments['output_mpt_file'])
    mpt_parser = mpt_parser_factory()
    mpt_parser.dump_mpt_config(mpt_config, arguments['output_mpt_file'])


def _fix_displacement(value_str, mindisp, maxdisp, arguments):
    next_idx = None
    for idx in range(0, len(value_str) - 16):

        if next_idx is not None:
            if idx < next_idx:
                continue
            if idx == next_idx:
                next_idx = None

        value = int(value_str[idx:idx + 16], 16)
        if value >= mindisp and value <= maxdisp:
            value = value - mindisp + \
                arguments['default_data_address']
            next_idx = idx + 16
            value = "%016x" % value
            value_str = list(value_str)
            value_str[idx:idx + 16] = value
            value_str = "".join(value_str)
        else:
            continue

    return value_str


def dump_c2mpt_template(arguments):
    """

    :param arguments:
    :type arguments:
    """

    print_info("Creating a c2mpt C file template...")
    template_file = findfiles(MICROPROBE_RC['template_paths'],
                              "c2mpt_template.c$")[0]

    if not os.path.isfile(template_file):
        print_error("Unable to find base template file: %s" % template_file)
        _exit(-1)

    output_file = arguments['output_mpt_file'].rstrip(".mpt") + ".c"
    print_info("Output file name: %s" % output_file)

    if os.path.isfile(output_file):
        print_error("Output file '%s' already exists" % output_file)
        _exit(-1)

    try:
        shutil.copy(template_file, output_file)
    except IOError:
        print_error(
            "Something wron when copying '%s' to '%s'\nError: %s " %
            (template_file, output_file, IOError)
        )
        _exit(-1)

    print_info("Done! You can start editing %s " % output_file)


def _exit(value):

    if len(_RM_FILES) > 0:
        print_info("Cleaning temporary files")

    for rmfile in [fname for fname in _RM_FILES if os.path.isfile(fname)]:
        os.unlink(rmfile)

    exit(value)


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe C to MPT tool",
        compilation_options=True,
        default_config_file="mp_c2mpt.cfg",
        force_required=['target'],
    )

    groupname = "C to MPT arguments"

    cmdline.add_group(groupname, "Command arguments related to C to MPT tool")

    cmdline.add_option(
        "input-c-file",
        "i",
        None,
        "C file to process",
        group=groupname,
        opt_type=existing_file_ext(".c"),
        required=False
    )

    cmdline.add_option(
        "output-mpt-file",
        "O",
        None,
        "Output file name",
        group=groupname,
        opt_type=new_file_ext(".mpt"),
        required=True
    )

    cmdline.add_flag(
        "strict",
        "S",
        "Be strict when parsing objdump input, if not set, silently skip "
        "unparsed elements",
        group=groupname
    )

    cmdline.add_option(
        "default-code-address",
        "X",
        0x10030000,
        "Default code address (default: 0x10030000)",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "default-data-address",
        "D",
        0x10040000,
        "Default data address (default: 0x10040000)",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "stack-size",
        None,
        4096,
        "Stack size in bytes (Default: 4096)",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_option(
        "host-displacement",
        None,
        None,
        "Displacement between static objdump code and loaded image on the "
        "host. Default computed automatically",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_flag(
        "fix-displacement",
        None,
        "If data contains addresses (such as pointers) to code or data "
        "regions, the tool will try to fix them adding the necessary "
        "displacement",
        group=groupname,
    )

    cmdline.add_option(
        "stack-name",
        None,
        "microprobe_stack",
        "Stack name (Default: microprobe_stack)",
        group=groupname,
        opt_type=str,
        required=False
    )

    cmdline.add_option(
        "stack-address",
        None,
        None,
        "Stack address (Default: allocated in the data area)",
        group=groupname,
        opt_type=int_type(0, float('+inf')),
        required=False
    )

    cmdline.add_flag(
        "no-data-initialization",
        None,
        "Do not run the compiled code locally to get the contents of"
        " registered variables before executing the *c2mpt_function*. Only "
        "statically specified variable contents will be dumped in the MPT"
        " generated",
        group=groupname
    )

    cmdline.add_flag(
        "save-temps",
        None,
        "Store the generated intermediate files permanently; place them in "
        "the input source file directory and name them based on the source "
        "file",
        group=groupname
    )

    cmdline.add_flag(
        "dump-c2mpt-template",
        None,
        "Dump a template C file, which can be used afterwards as an input "
        "file",
        group=groupname
    )

    cmdline.add_flag(
        "end-branch-to-itself",
        None,
        "A branch to itself instruction will be added at the end of the test",
        group=groupname
    )

    print_info("Processing input arguments...")
    cmdline.main(args, _main)


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """

    if "dump_c2mpt_template" in arguments:
        dump_c2mpt_template(arguments)
        _exit(0)

    if "input_c_file" not in arguments:
        print_error("argument -i/--input-c-file is required")
        _exit(-1)

    print_info("Arguments processed!")
    print_info("Importing target definition...")
    target = import_definition(arguments['target'])

    c2mpt(target, arguments)


def _temp_file(suffix=None):
    tempfile = mkstemp(prefix="microprobe_c2mpt_", suffix=suffix)
    os.close(tempfile[0])
    os.unlink(tempfile[1])
    return tempfile[1]


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        _exit(0)

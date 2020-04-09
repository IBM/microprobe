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
This is the cpapi module documentation
"""
# Futures
from __future__ import absolute_import, print_function

# Built-in modules
from time import localtime, strftime

# Third party modules
from six.moves import range
import six

# Own modules
import microprobe.code.var
import microprobe.code.wrapper
import microprobe.utils.info as mp_info
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = ["CPAPIWrapper", "CPAPIInfGen", "CPAPILoopGen"]

# Functions

# Classes


class CPAPIWrapper(microprobe.code.wrapper.Wrapper):
    """A wrapper for the C language with PAPI calls to measure hardware
    counters.
    """

    def __init__(self, counters=None):
        """ """
        super(CPAPIWrapper, self).__init__()
        self._max_array_var = None
        self._max_array_var_value = None
        self._loop = 0
        self._vars = []
        self._extra_headers = ["#include <papi.h>\n"]
        # Events to be read
        if counters is None:
            counters = ["PAPI_TOT_CYC", "PAPI_TOT_INS"]
        self._counters = counters

        self._vars.append(microprobe.code.var.VariableSingle("retval", "int"))
        self._vars.append(
            microprobe.code.var.VariableArray(
                "Events", "int", len(
                    self._counters
                )
            )
        )
        self._vars.append(
            microprobe.code.var.VariableArray(
                "values", "long long", len(
                    self._counters
                )
            )
        )

    def outputname(self, name):
        """

        :param name:

        """
        if not name.endswith(".c"):
            return "%s.c" % name
        return name

    def infinite(self):
        """ """
        return False

    def post_var(self):
        """ """
        return ""

    def required_global_vars(self):
        """ """
        return []

    def reserved_registers(self, dummy_reserved, target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """

        return [
            target.registers["GPR1"], target.registers["GPR2"],
            target.registers["GPR13"], target.registers["GPR31"]
        ]

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        return ""

    def headers(self):
        """ """
        header = []
        header.append("#include <stdio.h>")
        header.append("#include <string.h>")
        header.append("#include <stdlib.h>")
        header.append("#include <unistd.h>\n")
        for elem in self._extra_headers:
            header.append(elem)
        return "\n".join(header)

    def declare_global_var(self, var):
        """

        :param var:

        """

        align = var.align
        if align is None:
            align = 1

        if var.array():
            var_size = var.size
            if isinstance(var, microprobe.code.var.VariableArray):
                var_size = var.elems

            return "%s %s[%d]  __attribute__ ((aligned (%d)));\n" % (
                var.type, var.name, var_size, align
            )
        elif var.value is not None:
            return "%s %s __attribute__ ((aligned (%d))) = %s;\n" % (
                var.type, var.name, align, str(var.value)
            )
        else:
            return "%s %s __attribute__ ((aligned (%d)));\n" % (
                var.type, var.name, align
            )

    def init_global_var(self, var, value):
        """

        :param var:
        :param value:

        """

        if var.array():
            if var.type == "char":
                if self._max_array_var is None:
                    if value == "random":
                        string = "{FILE *devrandom = fopen(\"/dev/urandom\","\
                            " \"r\");\n"
                        string = string + "fread(&%s, sizeof(%s), %d , "\
                            "devrandom);\n" % (var.name, var.type, var.size)
                        string = string + "fclose(devrandom);}\n"
                        self._max_array_var = var
                        self._max_array_var_value = value
                        return string
                    elif isinstance(value, six.integer_types):
                        return "{memset(&%s, %d, %d);}\n" % (
                            var.name, value, var.size
                        )
                    else:
                        raise NotImplementedError
                else:
                    if value == self._max_array_var_value:
                        varant = self._max_array_var
                        if var.size > varant.size:
                            self._max_array_var = var
                            self._max_array_var_value = value
                            size = varant.size
                        else:
                            size = var.size

                        return "{for (int i=0;i<%d;i=i+%d) "\
                            "memcpy(&%s[i], &%s" ", %d);}\n" % (
                                var.size, varant.size,
                                var.name, varant.name, size)
                    elif isinstance(value, six.integer_types):
                        return "{memset(&%d, %d, %d);}\n" % (
                            var.name, value, var.size
                        )
                    else:
                        raise NotImplementedError
            elif (
                var.type == "int" or var.type == "long" or
                var.type == "float" or var.type == "double" or
                var.type == "long long"
            ):

                initialization = ""
                for xsize in range(var.elems):
                    initialization += "%s[%d] = " % (var.name, xsize)
                    if var.value is None:
                        initialization += "0"
                    else:
                        initialization += str(var.value)

                    initialization += ";\n"
                return initialization
            else:
                raise NotImplementedError

        else:
            if isinstance(value, six.integer_types):
                return "%s = %d;\n" % (var.name, value)
            else:
                raise NotImplementedError

    def start_main(self):
        """ """
        main = []

        # TODO: improve this and provide an easy interface to add
        # command line option from the passes
        main.append("void usage(void)")
        main.append("{")
        main.append("printf(\"Usage:\\n\");")
        main.append("printf(\"  -h  Print this help\\n\");")
        main.append("printf(\"  -d  Print micro-benchmark description\\n\");")
        main.append("exit(-1);")
        main.append("}")
        main.append("\n")
        main.append("void description(void)")
        main.append("{")
        main.append("int exit_code = 0;")
        main.append("\n")

        main.append("printf(\"%s\\n\");" % ("=" * 80))
        main.append(
            "printf(\"Microprobe framework general information:\\n\")"
            ";"
        )
        main.append("printf(\"%s\\n\");" % ("-" * 80))
        main.append(
            "printf(\"  Microprobe version: %s\\n\");" % mp_info.VERSION
        )
        main.append("printf(\"  Copyright: %s\\n\");" % mp_info.COPYRIGHT)
        main.append("printf(\"  License: %s\\n\");" % mp_info.LICENSE)
        main.append("printf(\"  Authors: %s\\n\");" % mp_info.AUTHOR)
        main.append("printf(\"  Maintainers: %s\\n\");" % mp_info.MAINTAINER)
        main.append("printf(\"  Email: %s\\n\");" % mp_info.EMAIL)
        main.append("printf(\"  Software status: %s\\n\");" % mp_info.STATUS)
        main.append("printf(\"\\n\");")

        if mp_info.STATUS == "Development":
            main.append("printf(\"Development information:\\n\");")
            main.append("printf(\"%s\\n\");" % ("-" * 80))
            main.append("printf(\"  %s\\n\");" % mp_info.REVISION)
            main.append("printf(\"\\n\");")

        main.append("printf(\"%s\\n\");" % ("=" * 80))
        main.append("printf(\"MICRO-BENCHMARK DESCRIPTION\\n\");")
        main.append("printf(\"%s\\n\");" % ("-" * 80))
        main.append(
            "printf(\"Generation time: %s\\n\");" % strftime(
                "%x %X %Z", localtime()
            )
        )
        # main.append("printf(\"\\n\");")
        main.append("printf(\"Generation policy:\\n\");")
        # main.append("printf(\"%s\\n\");" % ("*"*80))

        for index, info in enumerate(self.benchmark.pass_info):
            sinfo = info.split("-", 1)
            sinfo2 = [sinfo[1][i:i + 45] for i in range(0, len(sinfo[1]), 45)]

            main.append(
                "printf(\"  Step:%2s %24s %40s\\n\");" % (
                    index, sinfo[0], sinfo2[0]
                )
            )
            for line in sinfo2[1:]:
                main.append("printf(\"%s%s\\n\");" % (" " * 36, line.strip()))

        main.append("printf(\"\\n\");")
        main.append("printf(\"Configured target:\\n\");")
        # main.append("printf(\"%s\\n\");" % ("*"*80))
        for description in self.target.description.split("\n"):
            main.append("printf(\"  %s\\n\");" % description)
        main.append("printf(\"\\n\");")

        main.append("printf(\"Target requirements:\\n\");")
        # main.append("printf(\"%s\\n\");" % ("*"*80))
        for index, requirement in enumerate(self.benchmark.requirements):
            main.append(
                "printf(\"  Requirement %2s - %s\\n\");" % (index, requirement)
            )

        main.append("printf(\"\\n\");")
        main.append(
            "printf(\"Warnings (includes not checkable requirements)"
            ":\\n\");"
        )
        # main.append("printf(\"%s\\n\");" % ("*"*80))

        num_warnings = 0
        for index, warning in enumerate(self.benchmark.warnings):
            main.append(
                "printf(\"  Warning %2s - %s\\n\");" % (
                    index, warning
                )
            )
            num_warnings += 1
        main.append("printf(\"\\n\");")

        main.append("printf(\"Other Information\\n\");")
        # main.append("printf(\"%s\\n\");" % ("*"*80))
        for info in enumerate(self.benchmark.info):
            main.append("printf(\"%s\\n\");" % (info))
        main.append("printf(\"\\n\");")

        main.append("\n")
        main.append("exit(%d);" % num_warnings)
        main.append("}")
        main.append("\n")
        main.append(
            "void process_parameters("
            "int argc, char **argv, char **envp)"
        )
        main.append("{")
        main.append(
            "if (argc == 1) {printf(\"Running micro-benchmark...\\n\")"
            "; return;}"
        )
        main.append("if (argc > 2) {usage();}")
        main.append("if (argv[1][0] != '-') {usage();}")
        main.append("if (argv[1][1] == 'h') {usage();}")
        main.append("else if (argv[1][1] == 'd') {description();}")
        main.append("else {usage();}")
        main.append("}")
        main.append("\n")
        main.append("int main(int argc, char **argv, char **envp)")
        main.append("{")

        for var in self._vars:
            main.append(self.declare_global_var(var))

        main.append("process_parameters(argc, argv, envp);\n")
        return "\n".join(main)

    def wrap_ins(self, instr):
        """

        :param instr:

        """
        LOG.debug(instr)
        LOG.debug(type(instr))

        rstrl = []
        rstrl.append("__asm__(\"")
        if isinstance(instr, str):
            rstrl.append(instr)
        else:
            rstrl.append(instr.assembly())
        rstrl.append("\");")
        rstr = " ".join(rstrl)

        rstr_len = len(rstr)

        cstrl = []
        if not isinstance(instr, str):
            for idx, comment in enumerate(instr.comments):

                if idx == 0:
                    cstrl.append(" // " + comment)
                    continue

                cstrl.append((" " * rstr_len) + " // " + comment)

        cstr = "\n".join(cstrl)
        rstr = rstr + cstr + "\n"
        return rstr

    def end_loop(self, dummy_ins):
        """

        :param dummy_ins:

        """
        loop = []
        loop.append("}")
        return "\n".join(loop)

    def end_main(self):
        """ """
        main = []
        main.append("}")
        return "\n".join(main)

    def footer(self):
        """ """
        return ""


class CPAPIInfGen(CPAPIWrapper):
    """A wrapper for the C language with an infinite loop and HWC value
    accesses on each loop

    """

    def __init__(self, counters=None):
        """

        :param counters: (Default value = [PAPI_TOT_INS, PAPI_TOT_CYC])

        """
        super(CPAPIInfGen, self).__init__(counters=counters)

        # Variables to
        self._vars.append(
            microprobe.code.var.VariableSingle(
                "iteration", "long long"
            )
        )

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)
        """
        loop = []

        # Initialize PAPI
        loop.append("/* Initialize the PAPI library */")
        loop.append("retval = PAPI_library_init(PAPI_VER_CURRENT);")
        loop.append("if (retval != PAPI_VER_CURRENT && retval > 0) {")
        loop.append("  fprintf(stderr,\"PAPI library version mismatch!\\n\");")
        loop.append("  exit(EXIT_FAILURE);")
        loop.append("}\n")

        # Print name of the counters
        counters_print = ""
        counters_print += "printf(\"Iteration, "
        for counter in self._counters[:-1]:
            counters_print += counter
        counters_print += ", "
        counters_print += self._counters[-1]
        counters_print += "\n\""

        loop.append(counters_print)

        # Initialize events to be read

        # 1. The array containg the event list
        init = ""

        for idx, counter in enumerate(self._counters):
            init += "Events[%d] = %s;\n" % (idx, counter)

        loop.append(init)
        loop.append("\n")

        # 2. PAPI call
        init = ""
        init += "if ( (retval = PAPI_start_counters(Events, "
        init += str(len(self._counters))
        init += ")) != PAPI_OK) {\n"
        init += "  fprintf(stderr, \"Error starting PAPI counters: %s\\n\"," \
            "PAPI_strerror(retval));\n"
        init += "  exit(EXIT_FAILURE);\n"
        init += "}\n"

        loop.append(init)

        loop.append("while(1)")
        loop.append("{")
        return "\n".join(loop)

    def end_loop(self, dummy_ins):
        """

        :param dummy_ins:

        """
        loop = []

        # Read the events

        read = ""
        read += "if ((retval = PAPI_read_counters(values, "
        read += str(len(self._counters))
        read += ")) != PAPI_OK) {\n"
        read += "  fprintf(stderr, \"PAPI failed to start counters: %s\\n\", "\
            "PAPI_strerror(retval));\n"
        read += "  exit(1);\n"
        read += "}\n"

        loop.append(read)

        # Print the values to the std output
        print_hwc = ""
        print_hwc += "printf(\"%lld"
        for dummy_counter in self._counters:
            print_hwc += ", %lld"
        print_hwc += "\\n\", ++iteration"
        for i in range(len(self._counters)):
            print_hwc += ", values["
            print_hwc += str(i)
            print_hwc += "]"
        print_hwc += ");\n"

        loop.append(print_hwc)

        # Close the loop
        loop.append("}")
        return "\n".join(loop)

    def infinite(self):
        """ """
        return True

    def required_global_vars(self):
        """ """
        return []


class CPAPILoopGen(CPAPIWrapper):
    """A wrapper for the C language with a loop with the given number of
    operations and HWC value accesses at the end of the loop


    """

    def __init__(self, counters=None, size=10):
        super(CPAPILoopGen, self).__init__(counters=counters)

        self._size = size
        self._vars.append(microprobe.code.var.VariableSingle("i", "int"))
        self._vars.append(
            microprobe.code.var.VariableSingle(
                "iterations", "long long",
                value=size
            )
        )

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        loop = []

        # Initialize PAPI
        loop.append("iterations = %d;" % self._size)
        loop.append("/* Initialize the PAPI library */")
        loop.append("retval = PAPI_library_init(PAPI_VER_CURRENT);")
        loop.append("if (retval != PAPI_VER_CURRENT && retval > 0) {")
        loop.append("  fprintf(stderr,\"PAPI library version mismatch!\\n\");")
        loop.append("  exit(EXIT_FAILURE);")
        loop.append("}\n")

        # Print name of the counters
        counters_print = ""
        counters_print += "printf(\"Iterations, "
        for counter in self._counters[:-1]:
            counters_print += counter
            counters_print += ", "
        counters_print += self._counters[-1]
        counters_print += "\\n\");\n"

        loop.append(counters_print)

        # Initialize events to be read

        # 1. The array containg the event list
        init = ""

        for idx, counter in enumerate(self._counters):
            init += "Events[%d] = %s;\n" % (idx, counter)

        loop.append(init)
        loop.append("\n")

        # 2. PAPI call
        init = ""
        init += "if ( (retval = PAPI_start_counters(Events, "
        init += str(len(self._counters))
        init += ")) != PAPI_OK) {\n"
        init += "  fprintf(stderr, \"Error starting PAPI counters: %s\\n\","\
            "PAPI_strerror(retval));\n"
        init += "  exit(EXIT_FAILURE);\n"
        init += "}\n"

        loop.append(init)

        loop.append("for(i = 0; i < iterations; i++)")
        loop.append("{")
        return "\n".join(loop)

    def end_loop(self, dummy_ins):
        """

        :param dummy_ins:

        """
        loop = []

        # Close the loop
        loop.append("}")
        loop.append("\n")

        # Read the events
        read = ""
        read += "if ((retval = PAPI_read_counters(values, "
        read += str(len(self._counters))
        read += ")) != PAPI_OK) {\n"
        read += "  fprintf(stderr, \"PAPI failed to start counters: %s\\n\","\
            " PAPI_strerror(retval));\n"
        read += "  exit(1);\n"
        read += "}\n"

        loop.append(read)

        # Print the values to the std output
        print_hwc = ""
        print_hwc += "printf(\"%lld"
        for dummy_counter in self._counters:
            print_hwc += ", %lld"
        print_hwc += "\\n\", iterations"
        for i in range(len(self._counters)):
            print_hwc += ", values["
            print_hwc += str(i)
            print_hwc += "]"
        print_hwc += ");\n"

        loop.append(print_hwc)

        return "\n".join(loop)

    def infinite(self):
        """ """
        return False

    def required_global_vars(self):
        """ """
        return self._vars

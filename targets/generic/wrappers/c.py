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
This is the c module documentation
"""
# Futures
from __future__ import absolute_import, division

# Built-in modules
import itertools
from fractions import gcd
from time import localtime, strftime

# Third party modules
import six
from six.moves import range

# Own modules
import microprobe.code.var
import microprobe.code.wrapper
import microprobe.utils.info as mp_info
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import getnextf


# Constants
LOG = get_logger(__name__)
__all__ = ["CWrapper", "CInfGen", "CLoopGen"]

# Functions


# Classes
class CWrapper(microprobe.code.wrapper.Wrapper):
    """A wrapper for the C language."""

    def __init__(self, reset=False):
        """ """
        super(CWrapper, self).__init__()
        self._max_array_var = None
        self._max_array_var_value = None
        self._loop = 0
        self._vars = []
        self._extra_headers = []
        self._reset = reset

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

    def required_global_vars(self):
        """ """
        return [self.target.context_var]

    def reserved_registers(self, dummy_reserved, dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

    def post_var(self):
        """ """

        mstr = [self.wrap_ins(ins) for ins in self.target.get_context()]
        if self._reset:
            mstr.append("__asm__(\".balign 64\");\n")
            mstr.append("while(1){\n")
        return "".join(mstr)

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
        header.append("#include <stdint.h>")
        header.append("#include <unistd.h>\n")
        for elem in self._extra_headers:
            header.append(elem)
        return "\n".join(header)

    def declare_global_var(self, var):
        """

        :param var:

        """

        align = var.align
        if align is None or align is 0:
            align = ""
        else:
            align = " __attribute__ ((aligned (%d)))" % align

        if var.array():

            if var.value is not None:

                valuestr = ""

                value = var.value
                if not isinstance(value, list):
                    value = [value]

                get_value = getnextf(itertools.cycle(value))

                for dummy_idx in range(var.elems):
                    value = get_value()
                    if callable(value):
                        value = value()
                    valuestr = "%s%s," % (valuestr, value)

                return "%s %s[%d] %s = {%s};\n" % (
                    var.type, var.name, var.size, align, valuestr
                )

            else:

                return "%s %s[%d] %s;\n" % (
                    var.type, var.name, var.size, align
                )

        else:

            if var.value is not None:

                return "%s %s %s = %s;\n" % (
                    var.type, var.name, align, var.value
                )

            else:
                return "%s %s %s;\n" % (var.type, var.name, align)

    def init_global_var(self, var, value):
        """

        :param var:
        :param value:

        """

        if var.array():
            if var.type == "char" or var.type == "uint8_t":
                if self._max_array_var is None:

                    if callable(value):
                        value = value()

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
                        value = min(value, 2**31)
                        value = max(value, -2**31)
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

                            rstr = []
                            rstr.append(
                                "{for (int i=0;i<%d;i=i+%d) "
                                "memcpy(&%s[i], &%s" ", %d);}" % (
                                    (var.size // varant.size) * varant.size,
                                    varant.size,
                                    var.name, varant.name, varant.size)
                            )
                            rstr.append(
                                "{for (int i=%d;i<%d;i=i+%d) "
                                "memcpy(&%s[i], &%s" ", %d);}" % (
                                    (var.size // varant.size) * varant.size,
                                    var.size,
                                    (var.size % varant.size),
                                    var.name, varant.name,
                                    (var.size % varant.size))
                            )
                            return "\n".join(rstr) + '\n'

                        else:

                            return "{for (int i=0;i<%d;i=i+%d) "\
                                "memcpy(&%s[i], &%s" ", %d);}\n" % (
                                    var.size, var.size,
                                    var.name, varant.name, var.size)

                        #    size = varant.size
                        # else:
                        #    size = var.size

                        cgdc = gcd(var.size, varant.size)

                        return "{for (int i=0;i<%d;i=i+%d) "\
                            "memcpy(&%s[i], &%s" ", %d);}\n" % (
                                var.size, cgdc,
                                var.name, varant.name, cgdc)

                    elif isinstance(value, int):
                        value = min(value, 2**31)
                        value = max(value, -2**31)
                        return "{memset(&%d, %d, %d);}\n" % (
                            var.name, value, var.size
                        )
                    else:
                        raise NotImplementedError
            else:
                raise NotImplementedError

        else:

            if isinstance(value, int):
                return "%s = %d;\n" % (var.name, value)
            elif value == 'random':
                return "%s = %d;\n" % (var.name, 0)
            else:
                raise NotImplementedError(
                    "Init support for value '%s' not implemented yet" % value
                )

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
            "printf(\"Generation time: %s\\n\");" %
            strftime("%x %X %Z", localtime())
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
        elif instr.disable_asm:
            if instr.label is not None:
                rstrl.append(instr.label + ":")

            hstr = hex(int(instr.binary(), 2)).replace("L", "")[2:]

            rstrl.append(".byte " +
                         ",".join(["0x%s" % hstr[idx:idx + 2]
                                   for idx in range(0, len(hstr), 2)])
                         )

        else:
            rstrl.append(instr.assembly())

        rstrl.append("\");")
        rstr = " ".join(rstrl)

        rstr_len = len(rstr)
        cstrl = []

        if not isinstance(instr, str):

            comments = instr.comments
            if instr.disable_asm:
                comments = [instr.assembly()] + comments

            for idx, comment in enumerate(comments):

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
        return "\n"

    def end_main(self):
        """ """
        main = [
            "".join(
                [
                    self.wrap_ins(ins) for ins in self.target.set_context()
                ]
            )
        ]
        main.append("}")
        return "\n".join(main)

    def footer(self):
        """ """
        return ""


class CInfGen(CWrapper):
    """A wrapper for the C language with an infinite loop."""

    def __init__(self, reset=False, dithering=0, delay=0):
        super(CInfGen, self).__init__(reset=reset)
        self._dithering = dithering
        self._delay = delay

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """

        loop = []
        for dummy in range(0, self._delay):
            loop.append(self.wrap_ins(self.target.nop()))

        if self._reset:
            return "".join(loop)

        loop.append("__asm__(\".balign 64\");\n")
        loop.append("while(1)\n")
        loop.append("{\n")
        return "".join(loop)

    def infinite(self):
        """ """
        return True

    def reserved_registers(self, dummy_reserved, dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

    def end_loop(self, dummy_ins):
        """

        :param dummy_ins:

        """
        loop_list = []
        for dummy in range(0, self._dithering):
            loop_list.append(self.wrap_ins(self.target.nop()))

        loop = "".join(loop_list)
        loop += "}\n"
        return loop


class CLoopGen(CInfGen):
    """A wrapper for the C language with a loop with the given number of
    operations.


    """

    def __init__(self, size, reset=False, dithering=0, delay=0):
        """

        :param size:

        """
        super(CLoopGen, self).__init__(
            reset=reset, dithering=dithering,
            delay=delay
        )
        self._size = int(size)
        self._vars = [microprobe.code.var.VariableSingle("i", "int")]

    def start_loop(self, dummy_instr, dummy_instr_reset, dummy_aligned=False):
        """

        :param dummy_instr:
        :param dummy_aligned:  (Default value = False)

        """
        loop = []
        for dummy in range(0, self._delay):
            loop.append(self.wrap_ins(self.target.nop()))
        loop.append("for(i = 0; i < %d; i++)\n" % self._size)
        loop.append("{\n")
        return "".join(loop)

    def infinite(self):
        """ """
        return False

    def required_global_vars(self):
        """ """
        return self._vars + [self.target.context_var]

    def reserved_registers(self, dummy_reserved, dummy_target):
        """

        :param dummy_reserved:
        :param dummy_target:

        """
        return []

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
""":mod:`microprobe.utils.cmdline` module

"""

# Futures
from __future__ import absolute_import, print_function

# Built-in modules
import argparse
import ast
import os
import re
import sys
import textwrap
from gettext import gettext as _

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobeException
from microprobe.target.env import find_env_definitions
from microprobe.target.isa import find_isa_definitions
from microprobe.target.uarch import find_microarchitecture_definitions
from microprobe.utils.bin import interpret_bin
from microprobe.utils.config import DEFAULTSECT, DuplicateConfigParser
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import range_to_sequence, range_to_sequence_float
from microprobe.utils.mpt import mpt_parser_factory


# Constants
LOG = get_logger(__name__)
__all__ = [
    "dict_key",
    "new_file",
    "new_file_ext",
    "existing_file",
    "existing_file_ext",
    "existing_dir",
    "file_with",
    "float_type",
    "int_type",
    "int_range",
    "ParagraphFormatterML",
    "LazyArgumentError",
    "LazyArgumentParser",
    "CLI",
    "parse_instruction_list",
    "print_info",
    "print_error",
    "print_warning",
    "string_with_fields",
    "csv_with_integer",
    "csv_with_ranges"
]


# Functions
def dict_key(dictionary):
    """

    :param dictionary:
    :type dictionary:
    """

    def dict_key_check(argument):
        """

        :param argument:
        :type argument:
        """
        try:
            return dictionary[argument]
        except KeyError:
            msg = "'%s' not in the valid values set: %s" % (
                argument, list(dictionary.keys())
            )
            raise argparse.ArgumentTypeError(msg)

    return dict_key_check


def new_file(argument, internal=False):
    """

    :param argument:
    :type argument:
    """

    excep = argparse.ArgumentTypeError
    if internal:
        excep = MicroprobeException

    if os.path.isdir(argument):
        msg = "'%s' is a directory" % argument
        raise excep(msg)

    if os.path.exists(argument):
        msg = "'%s' file already exists" % argument
        raise excep(msg)

    if (
        os.path.dirname(argument) != "" and
        not os.path.isdir(os.path.dirname(argument))
    ):

        msg = "'%s' does not exist" % os.path.dirname(argument)
        raise excep(msg)

    return os.path.abspath(argument)


def new_file_ext(extension):
    """

    :param extension:
    :type extension:
    """

    if not isinstance(extension, list):
        extension = [extension]

    def function(argument):
        """

        :param argument:
        :type argument:
        """

        value = new_file(argument)

        valid = False
        for ext in extension:
            if value.endswith(ext):
                valid = True
                break

        if not valid:
            raise argparse.ArgumentTypeError(
                "File name does not finish with any of the valid extensions."
                " Valid extensions: %s" %
                ", ".join(extension))

        return value

    return function


def file_with(base_function):
    """

    """

    def function(argument):
        if os.path.isfile(argument):
            with open(argument, 'r') as filename_fd:
                contents = filename_fd.read()
                if contents.endswith("\n"):
                    contents = contents[:-1]
                argument = contents.replace("\n", ",")

        return base_function(argument)

    return function


def existing_file_ext(extension):
    """

    :param extension:
    :type extension:
    """

    if not isinstance(extension, list):
        extension = [extension]

    def function(argument):
        """

        :param argument:
        :type argument:
        """

        value = existing_file(argument)

        for ext in extension:
            if value.endswith(ext):
                return value

        raise argparse.ArgumentTypeError(
            "File name does not finish with '%s' extension" % extension
        )

    return function


def existing_file(argument):
    """

    :param argument:
    :type argument:
    """

    if not os.path.isfile(argument):
        msg = "'%s' file does not exist" % argument
        raise argparse.ArgumentTypeError(msg)

    return os.path.abspath(argument)


def existing_dir(argument):
    """

    :param argument:
    :type argument:
    """

    if not os.path.isdir(argument):
        msg = "'%s' directory does not exist" % argument
        raise argparse.ArgumentTypeError(msg)

    return os.path.abspath(argument)


def existing_cmd(argument):
    """

    :param argument:
    :type argument:
    """

    def is_exe(fpath):
        """

        :param fpath:
        :type fpath:
        """
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, dummy_fname = os.path.split(argument)
    if fpath:
        if is_exe(argument):
            return argument
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, argument)
            if is_exe(exe_file):
                return exe_file
    msg = "'%s' not found in the PATH" % argument
    raise argparse.ArgumentTypeError(msg)


def int_type(min_val, max_val):
    """

    :param min_val:
    :type min_val:
    :param max_val:
    :type max_val:
    """

    def function1(argument):
        """

        :param argument:
        :type argument:
        """

        try:
            argument = int(argument, base=0)
        except ValueError:
            msg = "'%s' is not valid positive integer" % argument
            raise argparse.ArgumentTypeError(msg)

        if argument < min_val or argument > max_val:
            msg = "'%s' is not within the [%d, %d] range" % (
                argument, min_val, max_val
            )
            raise argparse.ArgumentTypeError(msg)

        return argument

    def function2(argument):
        """

        :param argument:
        :type argument:
        """

        try:
            argument = int(argument, base=0)
        except ValueError:
            msg = "'%s' is not valid positive integer" % argument
            raise argparse.ArgumentTypeError(msg)

        if argument < min_val:
            msg = "'%s' is not within the [%d, %s] range" % (
                argument, min_val, "+inf"
            )
            raise argparse.ArgumentTypeError(msg)

        return argument

    if (max_val == "+inf"):
        return function2

    return function1


def int_range(min_val, max_val):
    """

    :param min_val:
    :type min_val:
    :param max_val:
    :type max_val:
    """

    def function(argumentall):
        """

        :param argument:
        :type argument:
        """

        rangedef = []

        for argument in argumentall.split("-"):

            try:
                argument = int(argument, base=0)
            except ValueError:
                msg = "'%s' is not a valid integer range." % argument
                raise argparse.ArgumentTypeError(msg)

            if argument < min_val or argument > max_val:
                msg = "'%s' is not within the [%d, %d] range" % (
                    argument, min_val, max_val
                )
                raise argparse.ArgumentTypeError(msg)

            rangedef.append(argument)

        if len(rangedef) > 1:
            if rangedef[0] > rangedef[1]:
                msg = "'%s' range is reversed. Change it to " \
                    "low to high value." % (
                        argumentall
                    )
                raise argparse.ArgumentTypeError(msg)

        return range_to_sequence(rangedef[0], *rangedef[1:])

    return function


def float_range(min_val, max_val):
    """

    :param min_val:
    :type min_val:
    :param max_val:
    :type max_val:
    """

    def function(argumentall):
        """

        :param argument:
        :type argument:
        """

        rangedef = []

        for argument in argumentall.split("/"):

            try:
                argument = float(argument)
            except ValueError:
                msg = "'%s' is not a valid float range." % argument
                raise argparse.ArgumentTypeError(msg)

            if argument < min_val or argument > max_val:
                msg = "'%s' is not within the [%f, %f] range" % (
                    argument, min_val, max_val
                )
                raise argparse.ArgumentTypeError(msg)

            rangedef.append(argument)

        if len(rangedef) > 1:
            if rangedef[0] > rangedef[1]:
                msg = "'%s' range is reversed. Change it to " \
                    "low to high value." % (
                        argumentall
                    )
                raise argparse.ArgumentTypeError(msg)

        return range_to_sequence_float(rangedef[0], *rangedef[1:])

    return function


def string_with_fields(sep, min_elem, max_elem, fmt):

    def function(argument):

        sargument = argument.split(sep)
        if len(sargument) < min_elem:

            msg = "'%s' definition is invalid. Need at least %d " \
                "elements separated by '%s' character." % (argument,
                                                           min_elem, sep)
            raise argparse.ArgumentTypeError(msg)

        if len(sargument) > max_elem:
            msg = "'%s' definition is invalid. Need at most %d " \
                "elements separated by '%s' character." % (argument,
                                                           max_elem, sep)
            raise argparse.ArgumentTypeError(msg)

        rargument = []
        for idx, elem in enumerate(sargument):
            rargument.append(fmt[idx](elem))

        return rargument

    return function


def float_type(min_val, max_val):
    """

    :param min_val:
    :type min_val:
    :param max_val:
    :type max_val:
    """

    def function(argument):
        """

        :param argument:
        :type argument:
        """

        try:
            argument = float(argument)
        except ValueError:
            msg = "'%s' is not valid float value" % argument
            raise argparse.ArgumentTypeError(msg)

        if argument < min_val or argument > max_val:
            msg = "'%s' is not within the [%f, %f] range" % (
                argument, min_val, max_val
            )
            raise argparse.ArgumentTypeError(msg)

        return argument

    return function


def string_with_chars(chars):
    """

    """

    def function(argument):
        """

        :param argument:
        :type argument:
        """

        for char in list(argument):
            if char not in chars:
                msg = "'%s' contains a character not in '%s'" % \
                    (argument, chars)
                raise argparse.ArgumentTypeError(msg)

        return argument

    return function


def csv_with_integer(argument):
    """

    :param argument:
    :type argument:
    """

    arguments = argument.split(",")
    parguments = []
    for argument in arguments:

        msg = "'%s' is not valid integer value" % argument
        argument = argument.replace(" ", "").upper()

        try:
            if argument.isdigit():
                argument = int(argument)
            elif argument.startswith("0X"):
                argument = int(argument, 16)
            else:
                raise argparse.ArgumentTypeError(msg)

            parguments.append(argument)

        except ValueError:

            raise argparse.ArgumentTypeError(msg)

    return parguments


def csv_with_ranges(min_value, max_value):
    """

    :param argument:
    :type argument:
    """

    check_int_range = int_range(min_value, max_value)

    def function(argument):
        arguments = argument.split(",")
        parguments = []
        for argument in arguments:
            parguments.extend(check_int_range(argument))

        return parguments

    return function


def print_info(string):
    """

    :param string:
    :type string:
    """
    progname = os.path.basename(sys.argv[0])
    print("%s: INFO: %s" % (progname, string), file=sys.stderr)


def print_error(string):
    """

    :param string:
    :type string:
    """
    progname = os.path.basename(sys.argv[0])
    print("%s: ERROR: %s" % (progname, string), file=sys.stderr)


def print_warning(string):
    """

    :param string:
    :type string:
    """
    progname = os.path.basename(sys.argv[0])
    print("%s: WARNING: %s" % (progname, string), file=sys.stderr)


def parse_instruction_list(target, sequence):
    """

    :param target:
    :type target:
    :param sequence:
    :type sequence:
    """

    try:
        instructions = []
        for instr in sequence.split(","):
            if (instr.upper().startswith("0X")):
                instr = interpret_bin(
                    instr[2:], target, safe=True, single=True
                )
                assert len(instr) == 1
                instr = instr[0].instruction_type
            else:
                instr = target.instructions[instr]
            instructions.append(instr)
    except KeyError as err:
        print_error("Instruction '%s' not found" % err.args[0])
        exit(-1)

    if len(instructions) == 0:
        print_error("Sequence '%s' is empty" % (sequence))
        exit(-1)

    return instructions


# Classes
class ParagraphFormatterML(argparse.HelpFormatter):
    """ A support class for nicer CLI help output.
    """

    def _split_lines(self, text, width):
        return self._para_reformat(text, width, multiline=True)

    def _fill_text(self, text, width, indent):
        lines = self._para_reformat(text, width, indent, True)
        return '\n'.join(lines)

    def _para_reformat(self, text, width, indent='', multiline=False):
        """

        :param text:
        :type text:
        :param width:
        :type width:
        :param indent:
        :type indent:
        :param multiline:
        :type multiline:
        """
        new_lines = list()
        main_indent = len(re.match(r'( *)', text).group(1))

        def blocker(text):
            '''On each call yields 2-tuple consisting of a boolean
            and the next block of text from 'text'.  A block is
            either a single line, or a group of contiguous lines.
            The former is returned when not in multiline mode, the
            text in the line was indented beyond the indentation
            of the first line, or it was a blank line (the latter
            two jointly referred to as "no-wrap" lines).
            A block of concatenated text lines up to the next no-
            wrap line is returned when in multiline mode.  The
            boolean value indicates whether text wrapping should
            be done on the returned text.'''

            block = list()
            for line in text.splitlines():
                line_indent = len(re.match(r'( *)', line).group(1))
                isindented = line_indent - main_indent > 0
                isblank = re.match(r'\s*$', line)
                if isblank or isindented:  # A no-wrap line.
                    # Yield previously accumulated block .
                    if block:
                        # of text if any, for wrapping.
                        yield True, ''.join(block)
                        block = list()
                    # And now yield our no-wrap line.
                    yield False, line
                else:  # We have a regular text line.
                    # In multiline mode accumulate it.
                    if multiline:
                        block.append(line)
                    # Not in multiline mode, yield it
                    else:
                        yield True, line  # for wrapping.
            # Yield any text block left over.
            if block:
                yield (True, ''.join(block))

        for wrap, line in blocker(text):
            if wrap:
                # We have either a single line or a group of concatenated
                # lines.  Either way, we treat them as a block of text and
                # wrap them (after reducing multiple whitespace to just
                # single space characters).
                line = self._whitespace_matcher.sub(' ', line).strip()
                # Textwrap will do all the hard work for us.
                new_lines.extend(
                    textwrap.wrap(
                        text=line,
                        width=width,
                        initial_indent=indent,
                        subsequent_indent=indent
                    )
                )
            else:
                # The line was a no-wrap one so leave the formatting alone.
                new_lines.append(line[main_indent:])

        return new_lines


class LazyArgumentError(Exception):
    """An exception class to report argument error.

    """
    pass


class LazyArgumentParser(argparse.ArgumentParser):
    """A Lazy argument parser.

    An argument parser that first parses all the arguments provided and if
    any of them is not correct, an argument error is raided. This differs
    from the base class where parser stops right after the first argument
    error is reported.
    """

    def __init__(self, **kwargs):

        super(LazyArgumentParser, self).__init__(**kwargs)
        self._error_msg = None

    def error(self, message):

        if self._error_msg is None:
            self._error_msg = message

        if not ("-T/--target" in message and "required" in message):
            self.force_error(message)

        return  # TODO: is this safe?

    def check_argument_errors(self):
        """Check for argument errors. """

        if self._error_msg:
            self.force_error(self._error_msg)

    def force_error(self, msg):
        """

        :param msg:
        :type msg:
        """

        self.print_usage(sys.stderr)
        self.exit(2, _('%s: error: %s\n') % (self.prog, msg))


class CLI(object):
    """Object to define a Command Line Interface.

    """

    def __init__(self, description, **kwargs):
        """ Create a new command line parser.

        """

        self._config_options = kwargs.pop('config_options', True)
        self._target_options = kwargs.pop('target_options', True)
        self._debug_options = kwargs.pop('debug_options', True)
        self._mpt_options = kwargs.pop('mpt_options', False)
        self._avp_options = kwargs.pop('avp_options', False)
        self._compilation_options = kwargs.pop('compilation_options', False)
        self._default_config_file = kwargs.pop('default_config_file', None)
        self._required = kwargs.pop('force_required', [])

        self._arg_parser = LazyArgumentParser(
            formatter_class=ParagraphFormatterML,
            **kwargs
        )
        self._options = None
        self._groups = {}
        self._groupoptions = {"default": []}
        self._multi = {}
        # self._debug = False
        # self._config_file = None
        # self._config_parser = None
        kwargs['description'] = description
        self._kwargs = kwargs
        self._arguments = {}

        self._add_default_options()

        if self._config_options:
            self._add_config_options()

        if self._target_options:
            self._add_target_options()

        if self._debug_options:
            self._add_debug_options()

        if self._mpt_options:
            self._add_mpt_options()

        if self._avp_options:
            self._add_avp_options()

        if self._compilation_options:
            self._add_compilation_options()

        self._add_environment_variables()

    @property
    def arg_parser(self):
        """

        """
        return self._arg_parser

    @property
    def arguments(self):
        """Dictionary mapping arguments to values. """
        return self._arguments

    def _add_environment_variables(self):
        """Register the environment variables options to the parser. """

        self.add_epilog("Environment variables:\n\n")
        self.add_epilog(
            "  MICROPROBETEMPLATES    Default path for microprobe"
            " templates\n"
        )
        self.add_epilog("  MICROPROBEDEBUG        If set, enable debug\n")
        self.add_epilog(
            "  MICROPROBEDEBUGPASSES  If set, enable debug during passes\n"
        )
        self.add_epilog(
            "  MICROPROBEASMHEXFMT    Assembly hexadecimal format. Options:\n"
            "                         'all' -> All immediates in hex format\n"
            "                         'address' -> Address immediates in hex "
            "format (default)\n"
            "                         'none' -> All immediate in integer "
            "format\n"
        )

        if self._compilation_options:
            self.add_epilog(
                "  CC                     Default C compiler\n"
                "  CPP                    Default C++ compiler\n"
                "  TARGET_OBJDUMP         Default target objdump utility\n"
                "  CFLAGS                 Default C compiler flags\n"
                "  CXFLAGS                Default C++ compiler flags\n"
            )

    def _add_default_options(self):
        """Register the default options to the parser. """

        self.add_option(
            "default_paths",
            "P",
            None,
            "Default search paths for microprobe target definitions",
            opt_type=existing_dir,
            nargs='+',
            metavar='SEARCH_PATH'
        )

        self.add_flag(
            "version", 'V',
            "Show Microprobe version and exit"
        )

        self.add_option(
            "verbosity",
            "v",
            None,
            "Verbosity level (Values: [0,1,2,3,4]). "
            "Each time this argument is specified the "
            "verbosity level is increased. By default, no logging "
            " messages are shown. These are the four levels available:\n\n"
            "  -v (1): critical messages\n"
            "  -v -v (2): critical and error messages\n"
            "  -v -v -v (3): critical, error and warning messages\n"
            "  -v -v -v -v (4): critical, error, warning and info messages\n\n"
            "Specifying more than four verbosity flags, will default to "
            "the maximum of four. If you need extra information, enable "
            " the debug mode (--debug or -d flags).",
            action="count"
        )

        self.add_flag(
            "debug", 'd', "Enable debug mode in Microprobe framework. Lots of "
            "output messages will be generated"
        )

    def _add_config_options(self):
        """Register the configuration options to the parser."""

        groupname = "Configuration arguments"

        self.add_group(
            groupname, "Command arguments related to configuration file "
            "handling"
        )

        self.add_option(
            "configuration",
            "c",
            None,
            "Configuration file. The configuration files will be readed in "
            "order of appearance. Values are reset by the last configuration"
            " file in case of non-list values. List values will be "
            "appended (not reset)",
            group=groupname,
            opt_type=existing_file,
            nargs="+",
            metavar="CONFIG_FILE",
            configfile=False
        )

        self.add_option(
            "force-configuration",
            "C",
            None,
            "Force configuration file. Use this configuration file as the "
            "default start configuration. This disables any system-wide, "
            "or user-provided configuration.",
            group=groupname,
            opt_type=existing_file,
            metavar="FORCE_CONFIG_FILE",
            configfile=False
        )

        self.add_option(
            "dump-configuration-file",
            None,
            None,
            "Dump a configuration file with the actual configuration used",
            group=groupname,
            opt_type=new_file,
            metavar="OUTPUT_CONFIG_FILE",
            configfile=False
        )

        self.add_option(
            "dump-full-configuration-file",
            None,
            None,
            "Dump a configuration file with the actual configuration used plus"
            " all the configuration options not set",
            group=groupname,
            opt_type=new_file,
            metavar="OUTPUT_CONFIG_FILE",
            configfile=False
        )

    def _add_target_options(self):
        """Register the target options to the parser. """

        groupname = "Target path arguments"

        self.add_group(groupname, "Command arguments related to target paths")

        self.add_option(
            "architecture-paths",
            "A",
            None,
            "Search path for architecture definitions. Microprobe will search"
            " in these paths for architecture definitions",
            action="append",
            opt_type=existing_dir,
            group=groupname
        )

        self.add_option(
            "microarchitecture-paths",
            "M",
            None,
            "Search path for microarchitecture definitions. Microprobe will "
            "search in these paths for microarchitecture definitions",
            action="append",
            opt_type=existing_dir,
            group=groupname
        )

        self.add_option(
            "environment-paths",
            "E",
            None,
            "Search path for environment definitions. Microprobe will search"
            " in these paths for environment definitions",
            action="append",
            opt_type=existing_dir,
            group=groupname
        )

        groupname = "Target arguments"

        self.add_group(
            groupname, "Command arguments related to target specification"
            " and queries"
        )

        self.add_option(
            "target",
            "T",
            None,
            "Target tuple. Microprobe follows a GCC-like target definition "
            "scheme, where a target is defined by a tuple as following:\n\n"
            "  <arch-name>-<uarch-name>-<env-name>"
            "\n\nwhere:\n\n"
            "  <arch-name>: is the name of the architecture\n"
            "  <uarch-name>: is the name of the microarchitecture\n"
            "  <env-name>: is the name of the environment\n\n"
            "One can use --list-* options to get the list of definitions "
            "available in the default search paths or the paths specified "
            "by the different --*-paths options",
            action=None,
            group=groupname
        )

        self.add_flag(
            "list-architectures",
            None,
            "Generate a list of architectures available in the "
            "defined search paths and exit",
            groupname,
            configfile=False
        )

        self.add_flag(
            "list-microarchitectures",
            None,
            "Generate a list of microarchitectures available in "
            "the defined search paths and "
            "exit",
            groupname,
            configfile=False
        )

        self.add_flag(
            "list-environments",
            None,
            "Generate a list of environments available in the "
            "defined search paths and exit",
            groupname,
            configfile=False
        )

    def _add_mpt_options(self):
        """Register the MicroprobeTest format file options to the parser. """

        groupname = "Microprobe Test arguments"

        self.add_group(
            groupname, "Command arguments related to Microprobe Test (mpt) "
            "generation"
        )

        self.add_option(
            "mpt-definition-file",
            "t",
            None,
            "Microprobe test (mpt) definition file",
            group=groupname,
            opt_type=existing_file_ext([".mpt", ".mpt.gz", ".mpt.bz2"]),
            required=True
        )

        # self.add_option(
        #    "mpt-output-file",
        #    "O",
        #    None,
        #    "Microprobe test (mpt) definition file",
        #    group=groupname,
        #    opt_type=new_file,
        #    required=True)

    def _add_compilation_options(self):
        """Register the MicroprobeTest compilation options to the parser. """

        groupname = "Compilation arguments"

        self.add_group(
            groupname, "Command arguments related to compilation options"
        )

        self.add_option(
            "host-c-compiler",
            None,
            os.environ.get("CC", "cc"),
            "Local C compiler (Default:'%s')" % os.environ.get("CC", "cc"),
            group=groupname,
            opt_type=existing_cmd,
            required=False
        )

        self.add_option(
            "host-cxx-compiler",
            None,
            os.environ.get("CXX", "c++"),
            "Local C++ compiler (Default:'%s')" % os.environ.get("CXX", "c++"),
            group=groupname,
            opt_type=existing_cmd,
            required=False
        )

        self.add_option(
            "target-c-compiler",
            None,
            os.environ.get("CC", "cc"),
            "Target C compiler (Default:'%s')" % os.environ.get("CC", "cc"),
            group=groupname,
            opt_type=existing_cmd,
            required=False
        )

        self.add_option(
            "target-cxx-compiler",
            None,
            os.environ.get(
                "CXX", "c++"
            ),
            "Target C++ compiler (Default:'%s')" % os.environ.get(
                "CXX", "c++"
            ),
            group=groupname,
            opt_type=existing_cmd,
            required=False
        )

        self.add_option(
            "target-objdump",
            None,
            os.environ.get(
                "TARGET_OBJDUMP", "objdump"
            ),
            "Target objdump utility (Default:'%s')" % os.environ.get(
                "TARGET_OBJDUMP", "objdump"
            ),
            group=groupname,
            opt_type=existing_cmd,
            required=False
        )

        self.add_option(
            "host-c-compiler-flags",
            None,
            os.environ.get(
                "CFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            "Local C compiler flags (Default:'%s')" % os.environ.get(
                "CFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            group=groupname,
            opt_type=str,
            required=False
        )

        self.add_option(
            "host-cxx-compiler-flags",
            None,
            os.environ.get(
                "CXXFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            "Local C++ compiler flags (Default:'%s')" % os.environ.get(
                "CXXFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            group=groupname,
            opt_type=str,
            required=False
        )

        self.add_option(
            "target-c-compiler-flags",
            None,
            os.environ.get(
                "CFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            "Target C compiler flags (Default:'%s')" % os.environ.get(
                "CFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            group=groupname,
            opt_type=str,
            required=False
        )

        self.add_option(
            "target-cxx-compiler-flags",
            None,
            os.environ.get(
                "CXXFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            "Target C++ compiler flags (Default:'%s')" % os.environ.get(
                "CXXFLAGS", "-Wall -Werror -m64 -O3 "
                "-pedantic -pedantic-errors -std=c99"
            ),
            group=groupname,
            opt_type=str,
            required=False
        )

    def _add_avp_options(self):
        """Register AVP/TST related option to the parser. """

        groupname = "AVP/TST format arguments"

        self.add_group(
            groupname, "Command arguments related to the format of the AVP/TST"
            " files generated"
        )

        self.add_option(
            "data-string-length",
            None,
            32,
            "Length of the data strings generated in the AVP/TST file",
            group=groupname,
            choices=[8, 16, 32],
            opt_type=int
        )

    def _add_debug_options(self):
        """Register the debug options to the parser."""

        groupname = "Debug arguments"

        self.add_group(
            groupname, "Command arguments related to debugging facilities"
        )

        self.add_flag(
            "traceback",
            None,
            "show a traceback and starts a python debugger (pdb) "
            "when an error occurs. 'pdb' is an interactive python "
            "shell that facilitates the debugging of errors",
            group=groupname
        )
        self.add_option(
            "profile",
            None,
            None,
            "dump profiling information into given "
            "file (see 'pstats' module)",
            opt_type=new_file,
            metavar="PROFILE_OUTPUT",
            group=groupname
        )

    def add_description(self, text):
        """Add more text to the description.

        :arg text: Additional description text.
        :type text: str
        """
        if self._arg_parser.description is None:
            self._arg_parser.description = text
        else:
            self._arg_parser.description += text

    def add_epilog(self, text):
        """Add an epilog to the help message.

        :arg text: Additional description text.
        :type text: str
        """
        if self._arg_parser.epilog is None:
            self._arg_parser.epilog = text
        else:
            self._arg_parser.epilog += text

    def add_group(self, name, description):
        """Add an option group.

        Allows the organization of options into groups.

        :arg name: Name of the group.
        :type name: :class:`~.str`

        :arg description: Short description.
                          This is shown in the extended help.
        :type description: :class:`~.str`

        """
        assert name not in self._groups, \
            "A command line option group named '%s' already exists" % name

        group = self._arg_parser.add_argument_group(name, "\n" + description)
        self._groups[name] = group
        self._groupoptions[name] = []

    def add_flag(self, name, short, descr, group=None, configfile=True):
        """Add a boolean flag.

        :arg name: Name of the option.
        :type name: str

        :arg short: Single-char name of the option.
        :type short: str or None

        :arg descr: Description of the option.
        :type descr: str

        :arg group: Name of the option group of this option.
        :type group: str
        """
        self.add_option(
            name,
            short,
            None,
            descr,
            opt_type=None,
            action="store_true",
            group=group,
            configfile=configfile
        )

    def add_option(
        self,
        name,
        short,
        default,
        descr,
        opt_type=str,
        action=None,
        choices=None,
        group=None,
        metavar=None,
        required=False,
        nargs=None,
        configfile=True
    ):
        """Add an option that takes an argument.

        See :mod:`argparse` for extended help.

        :arg name: Name of the option. If ``None``, uses `short` as the name
                   for :meth:`get`.
        :type name: str or ``None``

        :arg short: Single-char name of the option.
        :type short: str or ``None``

        :arg default: Default value.

        :arg descr: Description of the option.
        :type descr: str

        :arg type: Option type (see python's :mod:`argparse` documentation).

        :arg action: Action when flag is given (see python's :mod:`argparse`
                     documentation).

        :arg choices: Valid option values if type is ``choice``.

        :arg group: Name of the option group of this option.
        :type group: str

        You cannot have both `name` and `short` with a ``None`` value.
        """

        LOG.debug("Adding option:")
        LOG.debug("    - Name: %s", name)
        LOG.debug("    - Short: %s", short)
        LOG.debug("    - Default: %s", default)
        LOG.debug("    - Description: %s", descr)
        LOG.debug("    - Option_type: %s", opt_type)
        LOG.debug("    - Action: %s", action)
        LOG.debug("    - Choices: %s", choices)
        LOG.debug("    - Group: %s", group)
        LOG.debug("    - Metavar: %s", metavar)
        LOG.debug("    - Required: %s", required)
        LOG.debug("    - Nargs: %s", nargs)

        if choices is not None:

            descr = descr + ". Valid values: " + ", ".join(
                [str(elem) for elem in choices]
            )

            if callable(opt_type) and hasattr(opt_type, "func_name"):
                # pylint: disable=no-member
                if opt_type.__name__ == "dict_key_check":
                    # pylint: enable=no-member
                    descr = descr + ". Valid values: " + ", ".join(
                        [str(elem) for elem in choices.keys()]
                    )
                    choices = list(choices.values())

        groupname = group

        if group is None:
            group = self._arg_parser
            groupname = 'default'
        else:
            assert group in self._groups, \
                "Unknown option group name: %s" % group
            group = self._groups[group]

        if name is None and short is None:
            raise ValueError("cannot have both 'name' and 'short' as None")

        if name is None:
            argname = None
            name = short
        else:
            argname = "--" + name

        if short is None:
            argshort = None
        else:
            argshort = "-" + short

        LOG.debug("Argument name: %s", argname)
        LOG.debug("Short argument name: %s", argshort)

        # if required and name not in self._required:
        #    self._required.append(name)
        #    required = False

        if name in self._required:
            required = True

        kwargs = {}
        kwargs['help'] = descr
        kwargs['action'] = action
        kwargs['required'] = required
        kwargs['default'] = default

        if action not in ['store_true', 'store_false', 'store_const', 'count']:
            kwargs['type'] = opt_type
            kwargs['nargs'] = nargs
            kwargs['metavar'] = metavar
            kwargs['choices'] = choices

        if argname is None:
            arg = group.add_argument(argshort, **kwargs)
        elif argshort is None:
            arg = group.add_argument(argname, **kwargs)
        else:
            arg = group.add_argument(argshort, argname, **kwargs)

        if configfile:
            self._groupoptions[groupname].append(arg)

        self._arg_parser.set_defaults(**{name: default})

        # self._add_option_defaults(groupname, name, arg, action, type, descr)

    def _update_configuration(self):
        """Update the microprobe configuration based on current arguments. """

        # Update MICROPROBE configuration
        for option in MICROPROBE_RC:

            if option in self._arguments:

                new_value = self._arguments[option]

                if new_value is None:
                    # Option not set, skip
                    continue

                if isinstance(new_value, list):
                    MICROPROBE_RC[option] = new_value + MICROPROBE_RC[option]
                else:
                    MICROPROBE_RC[option] = new_value

        # Update tracing mechanism
        if self.get("traceback") is not None:
            try:
                from IPython.core import ultratb
                sys.excepthook = ultratb.FormattedTB(
                    mode='Verbose',
                    color_scheme='Linux',
                    call_pdb=1
                )
            except ImportError:
                LOG.warning(
                    "IPython python module is not installed in "
                    "the system. Unable to launch an interactive "
                    "python shell on errors (--traceback flag "
                    "disabled). "
                )

    def _parse(self, options, implicit=None):
        """Parse command line options.

        :arg options: Command line options to parse.
        :type options: list of strings

        :arg implicit: Option string to prepend when executing from script
                       header.
        :type implicit: str

        :arg debug: Enable debugging command line options.
        :type debug: boolean

        In the case of using ``implicit`` (e.g., with a value of `-foo`), if
        the python script is executed using the :ref:`hash-bang header
        <common-config-script>`, such execution would be equivalent to
        executing ``<program> -foo <script> ...``
        """

        LOG.debug("Parsing: %s", options)

        # assert implicit is None or self._opt_parser.has_option(implicit)

        if "_" in os.environ:
            # it seems that some shells do not have the '_'
            # environment variable

            if (len(options) > 0 and os.environ["_"] == options[0] and
                    implicit is not None):
                options.insert(0, implicit)

        self.add_description(self._kwargs['description'])

        try:
            self._arguments = vars(self._arg_parser.parse_args(args=options))
        except TypeError:
            pass

        # Fix the name space. Some arguments duplicated because the
        # usage of '-'
        for key in list(self._arguments.keys()):
            if key.find('-') >= 0:
                self._arguments.pop(key)

        # The following statement is done to update the debug flags
        # as soon as possible in case we are debugging configuration file
        # reading options
        if MICROPROBE_RC["debug"] is False:
            self._update_configuration()

        self._read_configuration_files()
        self._update_configuration()

        # Cleanup the name space (remove not set values)
        for key, value in self._arguments.copy().items():
            if value is None:
                self._arguments.pop(key)

        for elem in sorted(self._arguments):
            LOG.debug("Parameter: %s Value: %s", elem, self._arguments[elem])

        if self.get("version"):
            print_info(
                "Microprobe revision: %s" %
                MICROPROBE_RC['revision_core'])
            exit(0)

        # Check of list options (target lists)
        if self._target_options:

            if self.get("list-architectures"):

                definitions = find_isa_definitions()

                if len(definitions) == 0:
                    print("No isa definitions found! Check the paths...")
                else:
                    print(
                        "\n%s isa definitions detected. See table below:\n" %
                        len(definitions)
                    )
                    for definition in sorted(definitions):
                        print(definition)

            if self.get("list-microarchitectures"):

                definitions = find_microarchitecture_definitions()

                if len(definitions) == 0:
                    print(
                        "No microarchitecture definitions found! "
                        "Check the paths..."
                    )
                else:
                    print(
                        "\n%s microarchitecture definitions detected. "
                        "See table below:\n" % len(definitions)
                    )
                    for definition in sorted(definitions):
                        print(definition)

            if self.get("list-environments"):

                definitions = find_env_definitions()

                if len(definitions) == 0:
                    print(
                        "No environment definitions found!"
                        " Check the paths..."
                    )
                else:
                    print(
                        "\n%s environment definitions detected. "
                        "See table below:\n" % len(definitions)
                    )
                    for definition in sorted(definitions):
                        print(definition)

            if (
                self.get("list-architectures") or
                self.get("list-microarchitectures") or
                self.get("list-environments")
            ):
                exit(0)

        self._check_and_process_target_tuple()

        self._arg_parser.check_argument_errors()

        if self._mpt_options:
            # Parse mpt options and create the Microprobe Test Object
            mpt_parser = mpt_parser_factory()

            self._arguments['mpt_definition'] = mpt_parser.parse_filename(
                self.get('mpt-definition-file')
            )

        # Write configuration file if specified
        if self.get('dump-configuration-file'):
            self.save(self.get('dump-configuration-file'))

        if self.get('dump-full-configuration-file'):
            self.save(self.get('dump-full-configuration-file'), full=True)

    def _read_configuration_files(self):
        """Read the configuration files. """

        # Read configuration options
        config = DuplicateConfigParser()

        LOG.debug("Start reading configuration files")

        if self._default_config_file is not None:

            filenames = [
                '%s' % self._default_config_file, os.path.expanduser(
                    '~/.%s' % self._default_config_file
                )
            ]

            LOG.debug("Read default configuration files: %s", filenames)
            config.read(filenames)

        if self._config_options:

            filenames = []
            if self.get("force-configuration"):
                # it forces on only read this file
                filenames = [self.get("force-configuration")[-1]]

            elif self.get("configuration"):
                filenames += self.get("configuration")

            LOG.debug("Read specified configuration files: %s", filenames)

            for filename in filenames:
                LOG.debug("Reading file: %s", filename)
                config.readfp(open(filename))

        for section in ['DEFAULT'] + config.sections():
            for option, value in config.items(section):

                value = value.strip()
                option = option.replace("-", "_")

                if option in self._arguments:
                    if (
                        (value.endswith('[') and value.startswith(']')) or
                        value.replace(
                            "0x", ""
                        ).replace(".", "").isdigit() or
                        value in ['True', 'False']
                    ):
                        self._arguments[option] = ast.literal_eval(value)
                    else:
                        self._arguments[option] = value
                else:
                    LOG.warning("Ignoring option: %s", option)
                    # warnings.warn("Ignoring option: %s" % option)

        LOG.debug("End reading configuration files")

    def _check_and_process_target_tuple(self):
        """Validate the target string tuple provided. """

        if not self._target_options:
            return

        argument = self._arguments.get("target", None)

        if not argument:
            return

        try:
            isa_def, architecture_def, env_def = argument.split("-")
        except ValueError:
            msg = "Invalid format of '%s' target tuple" % argument
            self._arg_parser.force_error(msg)

        definitions = find_isa_definitions()
        if isa_def not in [definition.name for definition in definitions]:
            defstr = ",".join([defi.name for defi in definitions])
            msg = "ISA '%s' not available. "\
                "Use --list-architectures for full details of the ones "\
                "available. Available ones: %s" % (isa_def, defstr)
            self._arg_parser.force_error(msg)
        else:
            isa_def = [
                definition
                for definition in definitions if definition.name == isa_def
            ][0]

        definitions = find_microarchitecture_definitions()
        if architecture_def not in [
            definition.name for definition in definitions
        ]:
            defstr = ",".join([defi.name for defi in definitions])
            msg = "Microarchitecture '%s' not available. " \
                  "Use --list-microarchitectures for full details "\
                  "of the ones available. Available ones: %s"\
                  % (architecture_def, defstr)
            self._arg_parser.force_error(msg)
        else:
            architecture_def = [
                definition
                for definition in definitions
                if definition.name == architecture_def
            ][0]

        definitions = find_env_definitions()

        if env_def not in [definition.name for definition in definitions]:
            defstr = ",".join([defi.name for defi in definitions])
            msg = "Environment '%s' not available. "\
                  "Use --list-environments for full details of the ones "\
                  "available. Available ones: %s" % (env_def, defstr)
            self._arg_parser.force_error(msg)
        else:
            env_def = [
                definition
                for definition in definitions if definition.name == env_def
            ][0]

        self._arguments["target"] = (isa_def, architecture_def, env_def)

    def get(self, name):
        """

        :param name:
        :type name:
        """

        return self._arguments.get(name.replace("-", "_"))

    def main(self, options, main, *args, **kwargs):
        """Main wrapper with common error control.

        Parses command line options and then calls
        ``main``.

        :arg options: Command line options.
        :type options: :class:`list` of :class:`str`

        :arg main: User-defined main function.
        :type main: callable

        :arg implicit: Option string to prepend when executing from script
                       header (hash-bang syntax).
        :type implicit: str

        :arg skip: When given, skip stack trace until the given function.
        :type skip: callable

        :arg args: Extra arguments to ``main``.
        """
        LOG.debug("Options: %s", options)
        LOG.debug("Main: %s", main)

        implicit = kwargs.pop("implicit", None)

        def _local_main():
            """ _local_main function. """

            if self.get("profile"):
                import cProfile
                import pstats
                profiler = cProfile.Profile()
                profiler.runcall(main, self._arguments, *args, **kwargs)
                # profiler.dump_stats(self.get("profile"))

                with open(self.get("profile"), "w") as pfd:
                    sortby = 'tottime'
                    pss = pstats.Stats(profiler, stream=pfd).sort_stats(sortby)
                    pss.print_stats()

            else:
                main(self._arguments, *args, **kwargs)

        if MICROPROBE_RC["debug"] or MICROPROBE_RC["debugpasses"]:
            self._parse(options, implicit)
            _local_main()
        else:
            try:
                self._parse(options, implicit)
                _local_main()
            except MicroprobeException as exc:
                sys.stderr.write(
                    _("%s: ERROR: %s: %s\n") % (
                        self._arg_parser.prog, exc.__class__.__name__,
                        exc
                    )
                )
                sys.stderr.write(
                    _(
                        "%s: INFO: Increase verbosity level using "
                        "'-v' multiple times to obtain more"
                        " information\n" % self._arg_parser.prog
                    )
                )
                sys.exit(1)
            except NotImplementedError as exc:
                sys.stderr.write(
                    _("%s: ERROR: %s: %s\n") % (
                        self._arg_parser.prog, exc.__class__.__name__,
                        exc
                    )
                )
                sys.stderr.write(
                    _(
                        "%s: INFO: Contact developers for support\n" %
                        self._arg_parser.prog
                    )
                )
                sys.exit(1)

    def save(self, filename, full=False):  # @DontTrace
        """

        :param filename:
        :type filename:
        :param full:
        :type full:
        """

        if os.path.isfile(filename):
            LOG.warning("Overwriting previous file: '%s'", filename)

        # if self._config_parser is None:
        config_parser = DuplicateConfigParser()

        for option in self._groupoptions['default']:

            key = option.dest.replace("_", "-")
            value = self.get(key)

            LOG.debug("Default: %s", (key, value))

            config_parser.set(
                DEFAULTSECT, key,
                '%s ; %s' % (value, option.help.split(".")[0])
            )

        for section in self._groupoptions:

            if section == 'default':
                continue

            if not config_parser.has_section(section):
                config_parser.add_section(section)

            for option in self._groupoptions[section]:

                key = option.dest.replace("_", "-")
                value = self.get(key)

                LOG.debug("Default: %s", (key, value))

                config_parser.set(
                    section, key,
                    '%s ; %s' % (value, option.help.split(".")[0])
                )

        file_fd = open(filename, "w+")
        config_parser.write(file_fd, write_empty=full)
        file_fd.close()

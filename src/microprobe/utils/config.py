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
""":mod:`microprobe.utils.config` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import multiprocessing as mp
import os

# Third party modules
import six
import six.moves.configparser as configparser

# Own modules
from microprobe.utils.logger import DEBUG, DISABLE, INFO, set_log_level


# Constants
DEFAULTSECT = "DEFAULT"

__all__ = [
    "MicroprobeConfiguration", "MicroprobeDefaultConfiguration",
    "DuplicateConfigParser"
]

# Functions


# Classes
class MicroprobeConfiguration(dict):
    """
    Class to wrap generic configuration options. Update system-wide
    status/variables accordingly
    """

    def __setitem__(self, key, value):
        super(MicroprobeConfiguration, self).__setitem__(key, value)

        if key in ["debug", "verbosity"]:

            if "debug" in self:
                if self["debug"]:
                    loglevel = DEBUG
                elif "verbosity" in self:
                    loglevel = max((DISABLE - (self['verbosity'] * 10)), INFO)
                else:
                    raise NotImplementedError
            elif "verbosity" in self:
                loglevel = max((DISABLE - (self['verbosity'] * 10)), INFO)
            else:
                raise NotImplementedError

            if loglevel != DISABLE:
                self['verbose'] = True

            set_log_level(loglevel)

        if key in ["hex_all", "hex_address", "hex_none"] and value is True:

            if key is "hex_all":
                super(MicroprobeConfiguration, self).__setitem__(
                    'hex_address', False
                )
                super(MicroprobeConfiguration, self).__setitem__(
                    'hex_none', False
                )
            elif key is "hex_address":
                super(MicroprobeConfiguration, self).__setitem__(
                    'hex_all', False
                )
                super(MicroprobeConfiguration, self).__setitem__(
                    'hex_none', False
                )
            elif key is "hex_none":
                super(MicroprobeConfiguration, self).__setitem__(
                    'hex_all', False
                )
                super(MicroprobeConfiguration, self).__setitem__(
                    'hex_address', False
                )

        if key.endswith("_paths"):
            nvalue = []
            for path in value:
                if not os.path.isdir(path):
                    continue
                path = os.path.abspath(path)
                path = os.path.realpath(path)
                if path not in nvalue:
                    nvalue.append(path)

            super(MicroprobeConfiguration, self).__setitem__(
                key, nvalue
            )


class MicroprobeDefaultConfiguration(MicroprobeConfiguration):
    """
    Class to wrap default configuration options
    """

    def __init__(self):
        super(MicroprobeDefaultConfiguration, self).__init__()

        # pylint: disable=bad-super-call
        super(MicroprobeConfiguration, self).__setitem__('verbosity', 0)

        super(MicroprobeConfiguration, self).__setitem__('debug', False)
        # pylint: enable=bad-super-call

        self['default_paths'] = []
        self['architecture_paths'] = self['default_paths'][:]
        self['microarchitecture_paths'] = self['default_paths'][:]
        self['environment_paths'] = self['default_paths'][:]
        self['hex_address'] = True
        self['hex_all'] = False
        self['hex_none'] = False
        # self['debug'] = False
        self['debugpasses'] = False
        self['debugwrapper'] = False
        self['parallel_threshold'] = 200000000
        self['no_cache'] = False
        self['template_paths'] = ""
        self['wrapper_paths'] = []
        self['verbose'] = False
        self['cpus'] = mp.cpu_count()
        self['safe_bin'] = False
        self['revision_core'] = 'No packaged version. Use Git to find'\
            ' the current revision.'


class DuplicateConfigParser(configparser.ConfigParser, object):
    """A helper class to allow multiple configuration files.

    This class extends the base class behavior by allowing to read multiple
    config files instead of a single one. Configuration options are appended
    or reset depending on the configuration option type. Scalar values are
    reset, i.e. last configuration file setting the value is used. List
    values are appended.
    """

    # pylint: disable=arguments-differ

    def read(self, filenames, overwrite_first=False):
        """Read and parse a filename or a list of filenames.

        Files that cannot be opened are silently ignored; this is
        designed so that you can specify a list of potential
        configuration file locations (e.g. current directory, user's
        home directory, system wide directory), and all existing
        configuration files in the list will be read.  A single
        filename may also be given.

        Return list of successfully read files.
        """
        if isinstance(filenames, six.string_types):
            filenames = [filenames]
        read_ok = []
        for filename in filenames:
            try:
                file_fp = open(filename)
            except IOError:
                continue
            self._read_duplicate(
                file_fp,
                filename,
                dummy_overwrite_first=overwrite_first
            )
            file_fp.close()
            read_ok.append(filename)
        return read_ok

    def get(self, section, option, raw=False):
        """Get an option value for a given section.

        If *vars* is provided, it must be a dictionary. The option is looked up
        in *vars* (if provided), *section*, and in *defaults* in that order.

        All % interpolations are expanded in the return values, unless the
        optional argument *raw* is true. Values for interpolation keys are
        looked up in the same manner as the option.

        The section DEFAULT is special.
        """
        return super(DuplicateConfigParser, self).get(section, option, raw=raw)

    def items(self, section, raw=False):
        """Return a list of tuples with (name, value) for each option
        in the section.

        All % interpolations are expanded in the return values, based on the
        defaults passed into the constructor, unless the optional argument
        *raw* is true.  Additional substitutions may be provided using the
        *vars* argument, which must be a dictionary whose contents overrides
        any pre-existing defaults.

        The section DEFAULT is special.
        """
        return super(DuplicateConfigParser, self).items(section, raw=raw)

    def readfp(self, fp, filename=None, overwrite_first=False):
        """Like read() but the argument must be a file-like object.

        The `fp` argument must have a `readline` method.  Optional
        second argument is the `filename`, which if not given, is
        taken from fp.name.  If fp has no `name' attribute, `<???>` is
        used.

        """
        if filename is None:
            try:
                filename = fp.name
            except AttributeError:
                filename = '<???>'

        self._read_duplicate(
            fp, filename, dummy_overwrite_first=overwrite_first
        )

    def write(self, fp, write_empty=False):
        """Write an .ini-format representation of the configuration state."""

        if self._defaults:
            write_section_header = True
            for (key, value) in self._defaults.items():
                if isinstance(value, list):
                    for elem in value:

                        elem2 = elem.split(';', 1)[0].strip()
                        if str(elem2) != "" and str(elem2) != "None":
                            if write_section_header:
                                fp.write("[%s]\n" % DEFAULTSECT)
                                write_section_header = False
                            fp.write(
                                "%s = %s\n" % (
                                    key, str(elem).replace(
                                        '\n', '\n\t'
                                    )
                                )
                            )
                        elif write_empty:
                            if write_section_header:
                                fp.write("[%s]\n" % DEFAULTSECT)
                                write_section_header = False
                            fp.write(
                                "%s = %s\n" % (
                                    key, str(elem).replace(
                                        '\n', '\n\t'
                                    )
                                )
                            )
                else:

                    value2 = value.split(';', 1)[0].strip()
                    if str(value2) != "" and str(value2) != "None":
                        if write_section_header:
                            fp.write("[%s]\n" % DEFAULTSECT)
                            write_section_header = False
                        fp.write(
                            "%s = %s\n" % (
                                key, str(value).replace(
                                    '\n', '\n\t'
                                )
                            )
                        )
                    elif write_empty:
                        if write_section_header:
                            fp.write("[%s]\n" % DEFAULTSECT)
                            write_section_header = False
                        fp.write(
                            "%s = %s\n" % (
                                key, str(value).replace(
                                    '\n', '\n\t'
                                )
                            )
                        )
            if not write_section_header:
                fp.write("\n")
        for section in self._sections:
            write_section_header = True
            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    if isinstance(value, list):
                        for elem in value:

                            elem2 = elem.split(';', 1)[0].strip()
                            if str(elem2) != "" and str(elem2) != "None":
                                if write_section_header:
                                    fp.write("[%s]\n" % section)
                                    write_section_header = False
                                fp.write(
                                    "%s = %s\n" % (
                                        key, str(elem).replace(
                                            '\n', '\n\t'
                                        )
                                    )
                                )
                            elif write_empty:
                                if write_section_header:
                                    fp.write("[%s]\n" % section)
                                    write_section_header = False
                                fp.write(
                                    "%s = %s\n" % (
                                        key, str(elem).replace(
                                            '\n', '\n\t'
                                        )
                                    )
                                )
                    else:

                        value2 = value.split(';', 1)[0].strip()
                        if str(value2) != "" and str(value2) != "None":
                            if write_section_header:
                                fp.write("[%s]\n" % section)
                                write_section_header = False
                            fp.write(
                                "%s = %s\n" % (
                                    key, str(value).replace(
                                        '\n', '\n\t'
                                    )
                                )
                            )
                        elif write_empty:
                            if write_section_header:
                                fp.write("[%s]\n" % section)
                                write_section_header = False
                            fp.write(
                                "%s = %s\n" % (
                                    key, str(value).replace(
                                        '\n', '\n\t'
                                    )
                                )
                            )

            if not write_section_header:
                fp.write("\n")

    # pylint: enable=arguments-differ

    def _read_duplicate(self, file_fp, fpname, dummy_overwrite_first=False):
        """Parse a sectioned setup file.

        The sections in setup file contains a title line at the top,
        indicated by a name in square brackets (`[]'), plus key/value
        options lines, indicated by `name: value' format lines.
        Continuations are represented by an embedded newline then
        leading whitespace.  Blank lines, lines beginning with a '#',
        and just about everything else are ignored.
        """
        cursect = None  # None, or a dictionary
        optname = None
        lineno = 0
        # None, or an exception
        exception = None

        seen = []

        while True:
            line = file_fp.readline()
            if not line:
                break
            lineno = lineno + 1
            # comment or blank line?
            if line.strip() == '' or line[0] in '#;':
                continue
            if line.split(None, 1)[0].lower() == 'rem' and line[0] in "rR":
                # no leading whitespace
                continue
            # continuation line?
            if line[0].isspace() and cursect is not None and optname:
                value = line.strip()
                if value:
                    # pylint: disable=unsupported-assignment-operation
                    # pylint: disable=unsubscriptable-object
                    cursect[optname] = "%s\n%s" % (cursect[optname], value)
            # a section header or option header?
            else:
                # is it a section header?
                mo_header = self.SECTCRE.match(line)
                if mo_header:
                    sectname = mo_header.group('header')
                    if sectname in self._sections:
                        cursect = self._sections[sectname]
                    elif sectname == DEFAULTSECT:
                        cursect = self._defaults
                    else:
                        cursect = self._dict()
                        cursect['__name__'] = sectname
                        self._sections[sectname] = cursect
                    # So sections can't start with a continuation line
                    optname = None
                # no section header in the file?
                elif cursect is None:
                    raise configparser.MissingSectionHeaderError(
                        fpname, lineno, line
                    )
                # an option line?
                else:
                    mo_option = self.OPTCRE.match(line)
                    if mo_option:
                        optname, vi_sep, optval = mo_option.group(
                            'option', 'vi', 'value'
                        )
                        if vi_sep in ('=', ':') and ';' in optval:
                            # ';' is a comment delimiter only if it follows
                            # a spacing character
                            pos = optval.find(';')
                            if (
                                pos != -1 and (
                                    optval[pos - 1].isspace() or pos == 0
                                )
                            ):
                                optval = optval[:pos]

                        optval = optval.strip()
                        # allow empty values
                        if optval == '""':
                            optval = ''
                        optname = self.optionxform(optname.rstrip())

                        # if option already exists, append to a list
                        # pylint: disable=unsubscriptable-object
                        # pylint: disable=unsupported-membership-test
                        # pylint: disable=unsupported-assignment-operation
                        if optname in cursect and optname in seen:
                            if isinstance(cursect[optname], list):
                                cursect[optname].append(optval)
                            else:
                                cursect[optname] = [cursect[optname], optval]
                        else:
                            cursect[optname] = optval
                            seen.append(optname)
                    else:
                        # a non-fatal parsing error occurred.  set up the
                        # exception but keep going. the exception will be
                        # raised at the end of the file and will contain a
                        # list of all bogus lines
                        if not exception:
                            exception = configparser.ParsingError(fpname)
                        exception.append(lineno, repr(line))

        # if any parsing errors occurred, raise an exception
        if exception is not None:
            raise exception  # pylint: disable=raising-bad-type

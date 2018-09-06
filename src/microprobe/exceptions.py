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
""":mod:`microprobe.exceptions` module

This module define the excpeption hierarchy used in Microprobe framework.
"""


# Constants

# Functions


# Classes
class MicroprobeException(Exception):
    """Base class for all Microprobe-defined Exceptions"""
    pass


class MicroprobeWarning(MicroprobeException, Warning):
    """Base class for all Microprobe-defined Warning Exceptions"""
    pass


class MicroprobeError(MicroprobeException, Exception):
    """Base class for all Microprobe-defined Error Exceptions"""
    pass


class MicroprobeValueError(MicroprobeError, ValueError):
    """MicroproveValueError Exception"""
    pass


# pylint: disable=too-many-ancestors
class MicroprobeDuplicatedValueError(MicroprobeValueError):
    """MicroprobeDuplicatedValueError Exception"""
    pass
# pylint: enable=too-many-ancestors


class MicroprobeCalledProcessError(Exception):
    """MicroprobeCalledProcessError Exception"""

    def __init__(self, returncode, cmd, output):

        super(MicroprobeCalledProcessError, self).__init__()

        self.returncode = returncode
        self.cmd = cmd
        self.output = output

    def __str__(self):
        return "Command '%s' returned non-zero exit status %d.\nOutput:%s" % (
            self.cmd, self.returncode, self.output
        )


class MicroprobeAsmError(MicroprobeError):
    """MicroprobeAsmError Exception"""
    pass


class MicroprobeObjdumpError(MicroprobeError):
    """MicroprobeObjdumpError Exception"""
    pass


class MicroprobeRunCmdError(MicroprobeError):
    """MicroprobeRunCmdError Exception"""
    pass


class MicroprobeAddressTranslationError(MicroprobeError):
    """MicroprobeAddressTranslationError Exception"""
    pass


class MicroprobeBinaryError(MicroprobeError):
    """MicroprobeBinaryError Exception"""
    pass


class MicroprobePolicyError(MicroprobeError):
    """MicroprobePolicyError Exception"""
    pass


class MicroprobeUncheckableEnvironmentWarning(MicroprobeWarning):
    """MicroprobeUncheckableEnvironmentWarning Warning"""
    pass


class MicroprobeTypeError(MicroprobeError, TypeError):
    """MicroprobeTypeError Exception"""
    pass


class MicroprobeLookupError(MicroprobeError, LookupError):
    """MicroprobeLookupError Exception"""
    pass


class MicroprobeArchitectureDefinitionError(MicroprobeError):
    """MicroprobeArchitectureDefinitionError Exception"""
    pass


class MicroprobeArchitectureFormatError(MicroprobeArchitectureDefinitionError):
    """MicroprobeArchitectureFormatError Exception"""
    pass


class MicroprobeYamlFormatError(MicroprobeError):
    """MicroprobeYamlFormatError Exception"""
    pass


class MicroprobeCacheError(MicroprobeError):
    """MicroprobeCacheError Exception"""
    pass


class MicroprobeDMAFormatError(MicroprobeError):
    """MicroprobeDMAFormatError Exception"""
    pass


class MicroprobeMPTFormatError(MicroprobeError):
    """MicroprobeMPTFormatError Exception"""
    pass


class MicroprobeCodeGenerationError(MicroprobeError):
    """MicroprobeCodeGenerationError Exception"""
    pass


class MicroprobeTargetDefinitionError(MicroprobeError):
    """MicroprobeTargetDefinitionError Exception"""
    pass


class MicroprobeModelError(MicroprobeError):
    """MicroprobeModelError Exception"""
    pass


class MicroprobeImportDefinitionError(MicroprobeError):
    """MicroprobeImportDefinitionError Exception"""
    pass


class MicroprobeImportError(MicroprobeError):
    """MicroprobeImportError Exception"""
    pass


class MicroprobeNoComparatorError(MicroprobeCodeGenerationError):
    """Exception raised when there is no comparator suitable to perform a
    given action.

    :param val1: First value to compare.
    :type val1: :class:`~.int` or :class:`~.Register`
    :param val2: Second value to compare.
    :type val2: :class:`~.int` or :class:`~.Register`

    """

    def __init__(self, val1, val2):
        """

        :param val1:
        :param val2:

        """
        super(MicroprobeNoComparatorError, self).__init__()
        self._val1 = val1
        self._val2 = val2

    def __str__(self):
        """ """
        return "No comparator found to compare: '%s' and '%s'." % (
            self._val1, self._val2
        )


class MicroprobeBranchConditionError(MicroprobeCodeGenerationError):
    """Exception raised when the branch condition is not supported.

    :param string: cond: Condition

    """

    def __init__(self, cond):
        """

        :param cond:

        """
        super(MicroprobeBranchConditionError, self).__init__()
        self._cond = cond

    def __str__(self):
        """ """
        return "Condition '%s' not supported." % (self._cond)


class MicroprobeConstantRegisterError(MicroprobeCodeGenerationError):
    """MicroprobeConstantRegisterError Exception"""
    pass


class MicroprobeNoGenerationPathError(MicroprobeCodeGenerationError):
    """Exception raised when there is not a path suitable to generate a given
    value using the available :class:`~.Generator`
    instances.

    :param target: Value to generate.
    :type target: :class:`~.int`
    :param origin: Starting value.
    :type origin: :class:`~.int`
    :param address: If value to generate is an address.
    :type address: :class:`~.bool`

    """

    def __init__(self, target, origin, address):
        """

        :param target:
        :param origin:
        :param address:

        """
        super(MicroprobeNoGenerationPathError, self).__init__()
        self._target = target
        self._origin = origin
        self._address = address

    def __str__(self):
        """ """
        if self._address:
            return "It was not possible to generate the address '%d' " \
                   "from '%d' with the available Generators."
        else:
            return "It was not possible to generate the value '%d' from " \
                   "'%d' with the available Generators."

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
docstring
"""
# Futures
from __future__ import absolute_import

# Built-in modules
import collections
import inspect
import os

# Own modules
from microprobe import MICROPROBE_RC
from microprobe.exceptions import MicroprobePolicyError
from microprobe.utils.imp import load_source
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import findfiles


# Constants
LOG = get_logger(__name__)
__all__ = ["find_policy"]
_POLICY_ATTRIBUTES = ['NAME', 'DESCRIPTION', 'SUPPORTED_TARGETS', 'policy']


# Functions
def find_policy(target_name, policy_name):

    policy = None

    paths = MICROPROBE_RC["architecture_paths"] \
        + MICROPROBE_RC["default_paths"]

    policyfiles = findfiles(paths, "policies/.*.py$", full=True)

    for policyfile in policyfiles:

        name = (os.path.basename(policyfile).replace(".py", ""))
        module = load_source("%s_test" % name, policyfile)
        pdef = dict(inspect.getmembers(module))

        if len(
            [elem for elem in pdef if elem in _POLICY_ATTRIBUTES]
        ) != len(_POLICY_ATTRIBUTES):
            continue

        if (target_name not in pdef['SUPPORTED_TARGETS'] and
                "all" not in pdef['SUPPORTED_TARGETS']):
            continue

        if pdef['NAME'] != policy_name:
            continue

        if policy is not None:
            raise MicroprobePolicyError(
                "Multiple policies found for '%s' in target '%s'" %
                (policy_name, target_name)
            )

        # Reload source for good policy with correct module
        # name
        module = load_source("%s" % name, policyfile)
        pdef = dict(inspect.getmembers(module))
        policy = Policy(
            pdef['NAME'], pdef['DESCRIPTION'], pdef['policy'],
            pdef['SUPPORTED_TARGETS'], pdef
        )

    if policy is None:
        raise MicroprobePolicyError(
            "No policies found for '%s' in target '%s'" %
            (policy_name, target_name)
        )

    return policy


# Classes
Policy = collections.namedtuple(
    'Policy', [
        'name', 'description', 'apply', 'targets', 'extra'
    ]
)

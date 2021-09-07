#!/usr/bin/env sh
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
#
# Microprobe CI support scripts
#

set -e # Finish right after a non-zero return command

if [ "$WORKSPACE" = "" ]; then
	WORKSPACE=$(pwd)
    export WORKSPACE
fi

# shellcheck source=dev_tools/ci/environment.sh
. "$WORKSPACE/dev_tools/ci/environment.sh"
start_script "$0"

command -v nosetests
python "$(command -v nosetests)" --version

set +e
if [ "$2" = "" ]; then
    # shellcheck disable=SC2086,SC2046
    $NICE python "$(command -v nosetests)" $(find "$WORKSPACE/targets/" -type d -name "tools" | grep "tests/tools")  --xunitmp-file="tests_tools${PYTHON_VERSION}$1.xml" $NOSEOPTS --cover-xml-file="cover_tools${PYTHON_VERSION}$1.xml"
    error=$?
else
    # shellcheck disable=SC2086,SC2046
    $NICE python "$(command -v nosetests)" $(find "$WORKSPACE/targets/" -type d -name "tools" | grep "tests/tools" | grep "$2")  --xunitmp-file="tests_tools${PYTHON_VERSION}$1.xml" $NOSEOPTS --cover-xml-file="cover_tools${PYTHON_VERSION}$1.xml"
    error=$?
fi
set -e

if [ "$error" -ne 0 ]; then
	exit_error "$0"
fi
exit_success "$0"

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

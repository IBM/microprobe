#!/usr/bin/env sh
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
#
# Microprobe CI support scripts
#

set -e # Finish right after a non-zero return command

if [ "x$WORKSPACE" = "x" ]; then
	WORKSPACE=$(pwd)
    export WORKSPACE
fi

# shellcheck source=dev_tools/ci/environment.sh
. "$WORKSPACE/dev_tools/ci/environment.sh"
start_script "$0"

echo Running pycodestyle version:
python "$(command -v pycodestyle)" --version

set +e
# shellcheck disable=SC2046
$NICE python "$(command -v pycodestyle)" --count --statistics $(find "$WORKSPACE/src/" "$WORKSPACE/targets/" -name "*.py") > pycodestyle$PYTHON_VERSION.out 2> pycodestyle.err
error=$?
set -e

echo "Return code: $error"

nerror=$(cat pycodestyle.err)
rm -fr pycodestyle.err

echo "Num errors: $nerror"

if [ "$error" -ne 0 ]; then
    echo "Errors found, check pycodestyle$PYTHON_VERSION.out file and fix them"
	exit_error "$0"
fi

echo "No errors found!"
exit_success "$0"

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

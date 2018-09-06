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

if [ "x" = "x$1" ]; then
    echo "Need to provide a python module"
    exit_error "$0"
fi

if [ ! -f "$1" ]; then
    echo "File $1 does not exist"
    exit_error "$0"
fi

which nosetests
nosetests --version

NOSEOPTS="-d -v -e load_tests --exe -x --detailed-errors --process-timeout=$TIMEOUT"

set +e
echo "$NICE nosetests $NOSEOPTS $*"
# shellcheck disable=SC2068,SC2086
$NICE nosetests $NOSEOPTS $@
error=$?
set -e

if [ "$error" -ne 0 ]; then
	exit_error "$0"
fi
exit_success "$0"

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

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
	WORKSPACEORIG="$(pwd)"
else
    WORKSPACEORIG="$WORKSPACE"
fi
export WORKSPACEORIG

WORKSPACE="$(mktemp -u)"
ln -s "$(pwd)" "$WORKSPACE"
cd "$WORKSPACE"
export WORKSPACE

# shellcheck source=dev_tools/ci/environment.sh
. "$WORKSPACE/dev_tools/ci/environment.sh"

unset PYTHONPATH
unset MICROPROBEDATA
unset MICROPROBETEMPLATES
unset MICROPROBEWRAPPERS

start_script "$0"

if [ "x$1" = "x" ]; then
    echo "I need the python version: 2.6 or 2.7"
	exit_error "$0"
fi

VERSION=$1
set +e
which "python$VERSION"
error=$?
set -e

if [ "$error" -ne 0 ]; then
    echo "python$VERSION not found"
	exit_error "$0"
fi

tmpdir=$(mktemp -d)
rm -fr "$tmpdir"
python "$(which virtualenv)" --no-site-packages --python="python$VERSION" "$tmpdir"

# shellcheck source=/dev/null
. "$tmpdir/bin/activate"

cd "$VIRTUAL_ENV"

# No user packages within the virtual env
export PYTHONNOUSERSITE=True

cat "$WORKSPACE/dev_tools/ci/pip.conf" "$WORKSPACE"/targets/*/dev_tools/ci/pip.conf | sed "s#VIRTUAL_ENV#$WORKSPACE/distribution#g" > "$VIRTUAL_ENV/pip.conf"

set +e
pip install --no-cache-dir --pre -U microprobe_all
error=$?
set -e
if [ "$error" -ne 0 ]; then
    cd "$WORKSPACEORIG"
    rm -f "$WORKSPACE"
	exit_error "$0"
fi

error=0
set +e

# Clean state
unset PYTHONPATH
unset PYTHONNOUSERSITE
deactivate

# shellcheck source=/dev/null
. "$tmpdir/bin/activate"

($NICE mp_target -T riscv_v22-riscv_generic-riscv64_linux_gcc > /dev/null) || error=1

# Test target definitions
for file in $WORKSPACE/targets/*/dev_tools/ci/test_deploy_001_install.sh; do
    if [ -r "$file" ]; then
        echo "Sourcing $file"
        # shellcheck disable=SC1090
        . "$file"
    fi
done;

wait
set -e

# Test all tools entry
for elem in $WORKSPACEORIG/targets/*/tools/*.py; do
    echo "$elem"
    elem="$(basename "$elem")"
    elem="$(echo "$elem" | sed "s#.py\$##")"
    echo "Testing $elem"
    $elem -h
done

cd "$WORKSPACEORIG"

set +e
rm -f "$WORKSPACE"
set -e

if [ "$error" -ne 0 ]; then
	exit_error "$0"
fi

exit_success "$0"

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

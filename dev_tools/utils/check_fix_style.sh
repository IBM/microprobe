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
set -e
if [ "$WORKSPACE" = "" ]; then
    WORKSPACE=$(pwd)
	export WORKSPACE
fi

input=$*

# shellcheck source=dev_tools/ci/environment.sh
. "$WORKSPACE/dev_tools/ci/environment.sh"

check_style () {
    file=$1
    echo Check template "$file"
    error=0

    sed -i "s/^# functions$/# Functions/g" "$file"
    sed -i "s/^# classes$/# Classes/g" "$file"
    sed -i "s/^# constants$/# Constants/g" "$file"

    isort -ac -rc "$file"

    # check_str "$file" "^# Futures$"
    # check_str "$file" "^# Built-in modules$"
    # check_str "$file" "^# Third party modules$"
    # check_str "$file" "^# Own modules$"
    check_str "$file" "^__author__ ="
    check_str "$file" "^__copyright__ ="
    check_str "$file" "^__credits__ ="
    check_str "$file" "^__license__ ="
    check_str "$file" "^__version__ ="
    check_str "$file" "^__maintainer__ ="
    check_str "$file" "^__email__ ="
    check_str "$file" "^__status__ ="
    check_str "$file" "^__all__ ="
    check_str "$file" "^# Constants"
    check_str "$file" "^# Functions"
    check_str "$file" "^# Classes"

    # if [ $error -ne 0 ]; then
    #    exit 1
    # fi
    
    python "$(command -v flynt)" -ll 79 -tc -tj "$file"
    sed -i "s/ : /: /g" "$file"

    python "$(command -v black)" -l 79 --target-version py39 "$file"
    sed -i "s/ : /: /g" "$file"

    echo Check pycodestyle "$file"
    set +e
    python "$(command -v pycodestyle)" --count --statistics "$file"
    set -e

    echo Check pylint "$file"
    set +e
    python "$(command -v pylint)" "$file" -r n -f parseable -d I0011,R0902,R0913,W0511,R0912,C0111,R0101,R0915,C0302,R0914,R0904,C0112,W0703,W0125,C0209
    error=$?
    set -e

    if [ $error -ne 0 ]; then
        echo Check "$file"
    fi

}

check_str () {
    if [ "$(grep -c "$2" < "$1")" -ne 1 ]; then
        echo "$1 fails $2 $(grep -c "$2" < "$1")"
        error=1
    fi
}

for i in $input; do
    if [ -f "$i" ]; then
        check_style "$i"
    fi
done;
exit 0

for file in $(find "$WORKSPACE/src/" "$WORKSPACE/targets/" -type f -name "*.py" | grep -v ./venv | grep -v ./deploy | sort); do
     check_style "$file"
done;

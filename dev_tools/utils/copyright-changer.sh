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
set -e

usage () {
    echo ""
    echo "Usage:"
    echo ""
    echo "copyright-changer.sh old_year new_year"
    echo ""
}

replace () {
    # $1 dir
    # $2 extension
    # $3 old_str
    # $4 new_str

    if [ ! -d "$1" ]; then
        echo "$1 directory does not exist"
        exit 255
    fi

    tmpfile=$(mktemp)

    # shellcheck disable=SC2044
    for file in $(find "$1" -name "*$2" -type f); do
        echo "$file"
        sed "s/$3/$4/g" < "$file" > "$tmpfile" 
        cp "$tmpfile" "$file"
    done
    rm -fr "$tmpfile"
}

if [ "x$1" = "x" ]; then
    echo "Provide previous version string"
    usage
    exit 255
fi

if [ "x$2" = "x" ]; then
    echo "Provide new version string"
    usage
    exit 255
fi

for directory in ./src/ ./targets/ ./doc/ ./dev_tools/; do 
    replace $directory .py "__copyright__ = \"Copyright $1 IBM Corporation\"" "__copyright__ = \"Copyright $2 IBM Corporation\""
    replace $directory .yaml "# Copyright $1 IBM Corporation" "# Copyright $2 IBM Corporation"
    replace $directory .avp "* Copyright: Copyright $1 IBM Corporation" "* Copyright: Copyright $2 IBM Corporation"
    replace $directory .rst "   Copyright $1 IBM Corporation." "   Copyright $2 IBM Corporation."
    replace $directory .py "__license__ = \"IBM (c) $1 All rights reserved\"" "__license__ = \"IBM (c) $2 All rights reserved\""
    replace $directory .sh "# Copyright $1 IBM Corporation" "# Copyright $2 IBM Corporation"
    replace $directory .py "# Copyright $1 IBM Corporation" "# Copyright $2 IBM Corporation"
    replace $directory .sh "# IBM (c) $1 All rights reserved" "# IBM (c) $2 All rights reserved"
done

echo "DONE!"

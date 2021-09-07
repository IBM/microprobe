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

# cmd="yapf -i --verify --style='{based_on_style: pep8, blank_line_before_nested_class_or_def: True, dedent_closing_brackets: True, indent_dictionary_value: True}' "
cmd="yapf -i --verify --style pep8 "
cmd2="autopep8 -a -a -a -i "

if [ "$1" = "" ]; then
    echo "Please provide a file name"
    exit 255
fi

format () {

    echo "$cmd $1"
    set +e
    eval "$cmd $1"
    result=$?
    set -e
    
    if [ "$result" -eq 2 ]; then
        format "$1"
    elif [ "$result" -ne 0 ]; then
        echo "Error processing $1"
        exit 255
    fi
}

format2 () {

    echo "$cmd2 $1"
    set +e
    eval "$cmd2 $1"
    result=$?
    set -e
    
    if [ "$result" -ne 0 ]; then
        echo "Error processing $1"
        exit 255
    fi

    echo "$cmd2 $1"
    set +e
    eval "$cmd2 $1"
    result=$?
    set -e
    
    if [ "$result" -ne 0 ]; then
        echo "Error processing $1"
        exit 255
    fi
}


cfile=$1
while [ "$cfile" != "" ]; do

    if [ -e "$cfile" ]; then
        if [ -f "$cfile" ]; then
            isort -rc --atomic "$cfile"
            format "$cfile"
            format2 "$cfile"
        elif [ -d "$cfile" ]; then
            echo "Recursive directory"
            # shellcheck disable=2044
            for file in $(find "$cfile" -name "*.py"); do
                isort -rc --atomic "$cfile"
                format "$file"
                format2 "$file"
            done;
        else
            echo "$cfile not a file, not a directory"
        fi
    else
        echo "$cfile does not exits"
    fi

    shift
    cfile="$1"

done;

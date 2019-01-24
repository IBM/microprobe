#!/usr/bin/env bash
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
# shellcheck disable=SC2039,SC2086,SC2089,SC2090,SC2181
#
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

usage () {
    echo -e "Usage: $0 [OPTION]... [FILE]...\\n\
\\n\
Options:\\n\
  -h                         print this help text\
"
}

# Determine the comment syntax of a file
#   $1: a file
comment_syntax () {
    extension=${1##*.}
    case $extension in
        py|yaml|sh)
            comment="#"
            ;;
        avp)
            comment="*"
            ;;
        scala)
            comment="//"
            ;;
        *)
            echo "Unable to determine comment syntax for file \"$1\"" >&2
            exit 1
            ;;
    esac
    echo $comment
}

# Get the current year
file_year () {
    date=$(date)
    year=${date##* }
    echo "$year"
}

# Determine the appropriate year for a file
#   $1: a file
last_modified_year () {
    # Determine the copyright year using the current year if this file is
    # not under verson control.
    date=$(git ls-files --error-unmatch "$1" 2>/dev/null && \
        git log -1 --format="%ad" "$1" 2>/dev/null)
    if [ $? -ne 0 ]; then
        date=$(date)
    else
        date=${date% *}
    fi
    year=${date##* }
    if ! [[ $year =~ ^[0-9]{4}$ ]]; then
        echo "Year parsing is not a year, got \"$year\"" >&2
        exit 1
    fi
    echo "$year"
}

# Emit an Apache v2 Copyright
#  $1: a comment syntax
#  $2: a year
copyright_factory () {
    comment=$1
    year=$2
    # Build Apache v2 copyright text based on the determined year and
    # comment syntax
    copyright="$comment Copyright $year IBM Corporation\\n\
$comment\\n\
$comment Licensed under the Apache License, Version 2.0 (the \"License\");\\n\
$comment you may not use this file except in compliance with the License.\\n\
$comment You may obtain a copy of the License at\\n\
$comment\\n\
$comment http://www.apache.org/licenses/LICENSE-2.0\\n\
$comment\\n\
$comment Unless required by applicable law or agreed to in writing, software\\n\
$comment distributed under the License is distributed on an \"AS IS\" BASIS,\\n\
$comment WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\\n\
$comment See the License for the specific language governing permissions and\\n\
$comment limitations under the License."

    echo $copyright
}

while getopts "h" C; do
    case $C in
        h)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

comment=$(comment_syntax "$1")
exit_code=$?
if [ $exit_code -ne 0 ]; then
    exit $exit_code
fi

year=$(file_year)
if [ $exit_code -ne 0 ]; then
    exit $exit_code
fi

copyright=$(copyright_factory $comment $year)
exit_code=$?
if [ $exit_code -ne 0 ]; then
    exit $exit_code
fi

first_line=$(head -n1 "$1" 2>/dev/null)
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "Unable to find file \"$1\"" >&2
    exit $exit_code
fi

# Determine if we need to skip over a shebang
start=1
if [[ $first_line =~ ^#! ]]; then
    start=2
fi

# The copyright
maybe_copyright_line=$(sed "$start q;d" "$1")
copyright_re="(^.+(Copyright|copyright).+)[0-9]{4}(.+IBM.+$)"
if [[ $maybe_copyright_line =~ $copyright_re ]]; then
    echo "Updating copyright for file: $1"
    sed -i "$start s/[0-9]\\{4\\}/$year/" "$1"
else
    echo "Adding copyright for file: $1"
    sed -i "$start i $copyright" "$1"
fi

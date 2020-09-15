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

file=$1
echo "file: $file"

count=0
mod=$((count % 2))
error=0

IFSOLD=$IFS
IFS="$(printf '%b_' '\n')"
IFS="${IFS%_}" # protect trailing \n

mypipe=$(mktemp -u)

mkfifo "$mypipe"

cut -d':' -f 2 < "$file" | cut -f 2 > "$mypipe" &
while IFS= read -r line
do
    echo "Line: $line"

    if [ $count -lt 3 ]; then

        line1=""
        line2=""

    elif [ $mod -eq 0 ]; then

        line1=$line

    elif [ $mod -eq 1 ]; then

        line2=$line

        if [ "$line1" != "$line2" ] ; then
            echo "'$line1' == '$line2'" | tee "$file.asmfail"
            error=1 
            break
        else
            echo "\"$line1\" equal to \"$line2\""
        fi
    fi

    mod=$((count % 2))
    count=$((count + 1))

done < "$mypipe"
rm "$mypipe"

IFS=$IFSOLD

if [ $error -eq 0 ]; then
    touch "$file.asmok"
    exit 0
fi

exit 255

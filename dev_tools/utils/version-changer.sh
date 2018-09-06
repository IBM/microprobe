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
  echo "version-changer.sh old_version new_version"
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
      
for directory in ./src/ ./targets/ ./doc/ ./policies/ ./tests/ ./dev_tools/; do 
  replace "$directory" .py "__version__ = \"$1\"" "__version__ = \"$2\""
  replace "$directory" .yaml "# Version: $1" "# Version: $2"
  replace "$directory" .py "# Version: $1" "# Version: $2"
done

echo "DONE!"

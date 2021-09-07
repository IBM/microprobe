#!/usr/bin/env bash
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

if [ $# -ne 1 ]; then
  echo "Create ISA skeleton utility. It generates the required files to start a new ISA backend."
  echo
  echo "Usage: $0 target_dir"
  echo
  exit 255
fi

if [ -e "$1" ]; then
  echo "Target '$1' already exists"
  exit 255
fi

DIR="$( cd -P -- "$(dirname -- "$(command -v -- "$0")")" && pwd -P )"
TEMPLATE_DIR=$DIR/templates

mkdir "$1"

for elem in comparator.py  generator.py  instruction.py  operand.py  register.py; do
cp "$TEMPLATE_DIR/header.python" "$1/$elem"
done

for elem in isa instruction register_type register instruction_field instruction_format operand; do
mkdir "$1/$elem.props";
cp "$TEMPLATE_DIR/header.yaml" "$1/$elem.yaml"
done;

echo "ISA skeleton created in '$1'!"
exit 0

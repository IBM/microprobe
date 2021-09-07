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
# ARGS: $1 is the target IPC
#       $2 is the name of the generate benchmark
target_ipc=$1
# source_bench=$2

# Compile the benchmark (you can uncomment the example line below)
# gcc -O0 -mcpu=power7 -mtune=power7 -std=c99 $source_bench.c -o $source_bench

# Evaluate the ipc. Something like:
# ipc=< your preferred commands to evaluate the IPC >
# Lines below just return a random IPC
range=$(echo "$1" | cut -d'.' -f 1)-4
ipc=$(shuf -i "$range" -n 1)
ipc=${ipc}.$(shuf -i 0-999999 -n 1)

# Compute the score (the closer $ipc to the target IPC the higher the score)
score=$(echo \(1/\("$ipc"-"$target_ipc"\)\)^2 | bc -l)

echo "$score"

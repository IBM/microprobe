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
set -u # Finish right after a undefined expression is used
set -a # All following variables are exported

basedir=$(pwd)

if [ ! -d "$basedir/toolchain_riscv/install/bin" ]; then
    if [ ! -d "$basedir/toolchain_riscv" ]; then
        mkdir -p "$basedir/toolchain_riscv"
    fi

    cd "$basedir/toolchain_riscv"
    if [ ! -d "$basedir/toolchain_riscv/riscv-gnu-toolchain" ]; then
        git clone --recursive https://github.com/riscv/riscv-gnu-toolchain
    fi

    cd "$basedir/toolchain_riscv/riscv-gnu-toolchain"
    if [ ! -d "$basedir/toolchain_riscv/install/bin" ]; then
        ./configure --prefix="$basedir/toolchain_riscv/install/"
        make -j 4 > /dev/null 2> /dev/null &
        pid=$!

        while [ "$(ps -p $pid | wc -l)" -eq 2 ]; do
            sleep 60
            echo "Waiting compilation to finish ..."
        done;

        make install -j 4 > /dev/null 2> /dev/null &
        pid=$!

        while [ "$(ps -p $pid | wc -l)" -eq 2 ]; do
            sleep 60
            echo "Waiting installation to finish ..."
        done;
    fi
    rm -fr "$basedir/toolchain_riscv/riscv-gnu-toolchain"
fi

PATH=$PATH:$basedir/toolchain_riscv/install/bin
export PATH
command -v riscv64-unknown-elf-gcc

rm -fr

cd - || exit 255

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

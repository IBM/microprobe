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
#
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
#
# ----------------------------------------------------------------------------
#
# Microprobe CI support scripts
#
# Author: Ramon Bertran Monfort <rbertra@us.ibm.com>
#

set -e # Finish right after a non-zero return command
set -u # Finish right after a undefined expression is used
set -a # All following variables are exported

ATVERSION=14.0
DISTRO=bionic
UPDATE=3

if [ -f /opt/at$ATVERSION/bin/powerpc64le-linux-gnu-gcc ]; then
    echo "Toolchain already there"
    rm -fr "./toolchain_powerpc"
    exit 0
fi

if [ ! -d ./toolchain_powerpc ]; then
    mkdir ./toolchain_powerpc
fi

cd ./toolchain_powerpc

baseurl="https://public.dhe.ibm.com/software/server/POWER/Linux/toolchain/at/ubuntu/dists/$DISTRO/at$ATVERSION/binary-amd64/"

packages="advance-toolchain-at$ATVERSION-cross-common_$ATVERSION-${UPDATE}_amd64.deb 
advance-toolchain-at$ATVERSION-cross-ppc64le-libnxz_$ATVERSION-${UPDATE}_amd64.deb  
advance-toolchain-at$ATVERSION-cross-ppc64le-mcore-libs_$ATVERSION-${UPDATE}_amd64.deb  
advance-toolchain-at$ATVERSION-cross-ppc64le-runtime-extras_$ATVERSION-${UPDATE}_amd64.deb
advance-toolchain-at$ATVERSION-cross-ppc64le_$ATVERSION-${UPDATE}_amd64.deb  
advance-toolchain-cross-common_$ATVERSION-${UPDATE}_amd64.deb   
advance-toolchain-cross-ppc64le-libnxz_$ATVERSION-${UPDATE}_amd64.deb 
advance-toolchain-cross-ppc64le-mcore-libs_$ATVERSION-${UPDATE}_amd64.deb 
advance-toolchain-cross-ppc64le-runtime-extras_$ATVERSION-${UPDATE}_amd64.deb   
advance-toolchain-cross-ppc64le_$ATVERSION-${UPDATE}_amd64.deb"

for package in $packages; do
    if [ ! -f "./$package" ]; then 
        echo "Downloading $package ..."
        axel -n 8 -q "$baseurl/$package"
    else
        echo "$package already in cache"
    fi
done;

echo "Installing packages ..."
set +e
# shellcheck disable=SC2086
sudo dpkg -i $packages
#dpkg --configure *deb
sudo apt-get install -f -y
# shellcheck disable=SC2086
sudo dpkg -i $packages
#dpkg --configure *deb
sudo apt-get install -f -y
# shellcheck disable=SC2086
sudo dpkg -i $packages
#dpkg --configure *deb
sudo apt-get install -f -y
set -e

PATH="$PATH:/opt/at$ATVERSION/bin"
export PATH
command -v powerpc64le-linux-gnu-gcc

cd - || exit 1

rm -fr "./toolchain_powerpc"

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

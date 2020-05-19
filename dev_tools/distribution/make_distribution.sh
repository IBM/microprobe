#!/bin/bash
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

# Check if the script has been executed from the base development directory
cdir="$(pwd)/dev_tools/distribution"

usage () {
    echo "Usage:"
    echo "$0 [stable|devel] [directory|ONLINE]"
    echo ""
}

if [ ! -d "$cdir" ]; then
    usage
    echo "Distribution script executed from the wrong directory."
    echo "It has to be executed from root directory"
    exit 1
fi

# Check number of parameters
if [ $# -lt 1 ]; then
    usage
    exit 1
fi

# Create temp directories
tmp=$(mktemp -d)
tmp2=$(mktemp -d)

###############################################################################
################################ CONFIGURATION ################################
###############################################################################

# Target package directory

if [ "x$2" = "x" ]; then
    echo "No target specified"
    exit 255
else
    packagedir="$2"
fi

if [ "$packagedir" = "ONLINE" ]; then
    echo "PyPI support not yet implemented"
    echo "Use: twine upload --repository-url https://upload.pypi.org/legacy/ distribution/common/dev/*.whl"
    echo "Use: twine upload --repository-url https://upload.pypi.org/legacy/ distribution/common/stable/*.whl"
    exit 0
else
    mkdir -p "$packagedir"
fi

# Number of copies to keep in the package directory
keep=30

###############################################################################
############################# END CONFIGURATION ###############################
###############################################################################

###############################################################################
################################ BUILD FLAGS ##################################
###############################################################################

# Extra flags to all commands
extra="--no-user-cfg"
# extra="$extra --verbose"
extra="$extra --quiet"

# Flags for binary_wheel distribution
bwheel="build --build-purelib $tmp --build-temp $tmp"
bwheel="$bwheel bdist_wheel --universal --bdist-dir $tmp"
bwheel="$bwheel --python-tag py2"
bwheel="$bwheel --dist-dir"
rotatewhl="rotate --keep $keep --match .whl"
rotatewhl="$rotatewhl --dist-dir"

# Flags for source distrubution
#
# sdist="sdist --formats bztar --dist-dir"
# rotatesource="rotate --keep $keep --match .tar.bz2 --dist-dir"

mdate=$(date +%Y%m%d%H%M%S)

# rc release candidate
inforc="egg_info --tag-build .rc$mdate --egg-base $tmp2"

# Official release
infooff="egg_info --tag-build .$mdate --egg-base $tmp2"

# daily r release
infodaily="egg_info --tag-build .$mdate --egg-base $tmp2"

###############################################################################
############################## END BUILD FLAGS ################################
###############################################################################

if [ "x$1" = "xcandidate" ]; then
     info=$inforc
     finaldir="stable"
elif [ "x$1" = "xstable" ]; then
     info=$infooff
     finaldir="stable"
elif [ "x$1" = "xdevel" ]; then
     info=$infodaily
     finaldir="dev"
else
    usage
    echo "Unkown '$1' parameter"
    exit 1
fi

create_wheel () {
    # $1 setup file
    # $2 target dir
    echo "Start wheel generation using setup file: $1"
    installdir=$packagedir/$2/$finaldir
    cp "$cdir/$1" ./setup.py
    echo "Launching setup script"
    # shellcheck disable=SC2086
    python ./setup.py $extra $info check --strict $bwheel $installdir $rotatewhl $installdir
    echo "Cleaning temporary files"
    rm -fr ./setup.py
    rm -fr "${tmp:?}/*"
    rm -fr "${tmp2:?}/*"
    echo "Wheel installed in $installdir"
    echo "Finish wheel generation using setup file: $1"

}

create_tmp_package () {
    # $1: new dir
    # $2: orig dir
    # $3: create __init__.py
    # $4: touch base __init__.py id does not exist 

    echo "Start creating temporary package in '$1' from '$2'"
    echo "Create init: $3"
    echo "Touch base init: $4"

    echo "Copying files"
    mkdir -p "$1"
    cp -r "$2"/* "$1"/

    set +e
    find "$1/" -type d -name dev_tools -exec rm -fr {} \;
    find "$1/" -type d -name tests -exec rm -fr {} \;
    set -e

    if [ "$4" -eq 1 ]; then
        if [ ! -f "$(dirname "$1")/__init__.py" ]; then
            echo "Creating __init__.py fake base package"
            touch "$(dirname "$1")/__init__.py"
        fi
    fi

    if [ "$3" -eq 1 ]; then
        # shellcheck disable=SC2044
        for dir in $(find "$1" -type d | grep -v autom4te.cache$); do
            if [ ! -f "$dir/__init__.py" ]; then
                echo "Creating __init__.py fake package"
                touch "$dir/__init__.py"
            fi

            if [ "$(basename "$dir" | grep -c "\\.")" -gt 0 ]; then
                echo "Invalid directory name $dir"
                basename "$dir"
                echo "Avoid use of dots '.' in directory names"
                exit 255
            fi
        done
    fi

    echo "End creating temporary package in '$1' from '$2'"

}

remove_tmp_package () {
    echo "Remove temporary package in '$1'"
    rm -fr "$1"
}

origmask=$(umask)
umask 022

#
####
#
# CREATE MICROPROBE PACKAGES
#
####
#

remove_tmp_package ./src/microprobe/definitions/
remove_tmp_package ./src/microprobe/doc

create_wheel microprobe_all.py common

create_tmp_package ./src/microprobe/definitions/generic/ ./targets/generic/ 1 1

cp -f ./src/microprobe/microprobe.cfg ./microprobe.orig
echo "revision_core = $(git rev-parse --abbrev-ref HEAD) $(git rev-parse --short HEAD) built on $mdate" >> ./src/microprobe/microprobe.cfg
create_wheel microprobe_core.py common
rm -f ./src/microprobe/microprobe.cfg
mv -f ./microprobe.orig ./src/microprobe/microprobe.cfg 

create_tmp_package ./src/microprobe/definitions/riscv/ ./targets/riscv/ 1 1
create_wheel microprobe_target_riscv.py common

remove_tmp_package ./src/microprobe/definitions/

if [ ! -d ./doc/build/html ]; then
    ./dev_tools/ci/code_conventions_003_documentation.sh
fi

create_tmp_package ./src/microprobe/doc ./doc/build/html/ 1 0
create_wheel microprobe_doc.py common
remove_tmp_package ./src/microprobe/doc

umask "$origmask"

echo "Cleaning up temporary directories"
rm -fr "$tmp" "$tmp2"

exit 0

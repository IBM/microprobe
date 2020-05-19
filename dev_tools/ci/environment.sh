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

if [ -f "$0.error" ] && [ "x$1" = "x-c" ]; then
    echo "Error in $0"
    cat "$0.error"
    echo "Error in $0"
    exit 1
elif [ "x$1" = "x-c" ]; then
    echo "Not error in $0"
    exit 0
else
    rm -f "$0.error"
fi

# Generic options
if [ -z "$MAXJOBS" ] ; then
    MAXJOBS=$(grep -c processor < /proc/cpuinfo)
    if [ "$MAXJOBS" -gt 48 ]; then
        MAXJOBS=48
    fi
fi

export MAXJOBS
TIMEOUT=7200
export TIMEOUT

# Check if we are in travis
if [ "$TRAVIS" = "true" ] && [ "$CI" = "true" ]; then
    export NICE=""
    export WORKSPACE=$TRAVIS_BUILD_DIR
    if [ "$TRAVIS_BRANCH" = "master" ]; then
        export BUILD_TYPE="stable"
    fi
    MAXJOBS=1
    export NOSEOPTS=" -d -v -e load_tests --exe --processes=$MAXJOBS --detailed-errors --process-timeout=$TIMEOUT "

    MP_TESTING_COMPILER_RISCV_V22=$(command -v riscv64-unknown-elf-gcc)
    export MP_TESTING_COMPILER_RISCV_V22
else
    export NICE="nice -n 1"
    if [ "x$WORKSPACE" = "x" ]; then
        WORKSPACE=$(pwd)
        export WORKSPACE
    fi
    # export NOSEOPTS=" -d -v --with-coverage --cover-branches --cover-inclusive --cover-tests --with-xunitmp -e load_tests --exe --processes=$MAXJOBS --detailed-errors --process-timeout=$TIMEOUT --cover-xml --cover-erase "
    export NOSEOPTS=" -d -v --with-xunitmp -e load_tests --exe --processes=$MAXJOBS --detailed-errors --process-timeout=$TIMEOUT "
    # export NOSEOPTS="-d -v -e load_tests --exe --processes=$MAXJOBS -x --detailed-errors --process-timeout=$TIMEOUT"

    set +e
    MP_TESTING_COMPILER_RISCV_V22=$(command -v riscv64-unknown-elf-gcc)
    export MP_TESTING_COMPILER_RISCV_V22
    set -e

fi

# Python option. Make sure we are in a controlled environment
if [ "x$PYTHON_VERSION" = "x" ]; then
    export PYTHON_VERSION=2.7
fi

if [ "x$BUILD_TYPE" != "xstable" ]; then
    export BUILD_TYPE='devel'
else
    export BUILD_TYPE='stable'
fi

export MP_TESTING_CFLAGS_RISCV_V22="-march=rv64g"
export MP_TESTING_DFLAGS_RISCV_V22="-M numeric,no-aliases"
export MP_TESTING_AFLAGS_RISCV_V22="-march=rv64g"

export PYTHONNOUSERSITE=True
export PYTHONPATH=""

# Import submodule environments if they exist
for file in "$WORKSPACE"/targets/*/dev_tools/ci/init_environment.sh; do
    if [ -r "$file" ]; then
        echo "Sourcing $file ..."
        # shellcheck disable=SC1090
        . "$file"
    fi
done;

for file in "$WORKSPACE"/targets/*/dev_tools/ci/environment.sh; do
    if [ -r "$file" ]; then
        echo "Sourcing $file ..."
        # shellcheck disable=SC1090
        . "$file"
    fi
done;


start_script() {
    rm -f "$0.error"
}

exit_success() {
    exit 0
}

exit_error() {
    if [ "$TRAVIS" = "true" ] && [ "$CI" = "true" ]; then
        echo "Error in $1"
        if [ -f "$2" ]; then
            cat "$2"
        fi
        exit 1
    else
        touch "$1.error"
        if [ -f "$2" ]; then
            tee "$1.error" < "$2"
        fi
        exit 0
    fi
}

# Check if we are in travis
if [ "$TRAVIS" = "true" ] && [ "$CI" = "true" ]; then
    if [ "$NEEDINSTALL" != "False" ]; then
        pip install -U -r requirements_devel.txt --no-cache-dir
        NEEDINSTALL=False
        export NEEDINSTALL
    fi
else
    # Create a virtual environment and activate it and install dependencies
    # only if we are not already in a virtual env
    if [ "x$VIRTUAL_ENV" = "x" ]; then

        # No user packages within the virtual env
        export PYTHONPATH=""
        export PYTHONNOUSERSITE=True

        NEEDINSTALL="False"
        if [ ! -d "./venv-python$PYTHON_VERSION" ]; then
            NEEDINSTALL="True"
            rm -fr ./get_pip
            mkdir -p ./get_pip
            (cd ./get_pip
            wget https://bootstrap.pypa.io/get-pip.py --no-check-certificate
            python$PYTHON_VERSION get-pip.py --cache-dir "../.cache-python$PYTHON_VERSION" --prefix . -I -U --disable-pip-version-check --no-cache-dir --no-warn-script-location
            PYTHONPATH=$(find ./lib/ -name site-packages -type d) ./bin/pip install --cache-dir "../.cache-python$PYTHON_VERSION" --prefix . -I -U virtualenv --no-cache-dir --no-warn-script-location
            PYTHONPATH=$(find ./lib/ -name site-packages -type d) ./bin/virtualenv --clear --python=python$PYTHON_VERSION "../venv-python$PYTHON_VERSION" --app-data "../.app-data-python$PYTHON_VERSION"
            )
            rm -fr ./get_pip
        fi
        # shellcheck source=/dev/null
        .  "$WORKSPACE/venv-python$PYTHON_VERSION/bin/activate"

        if [ "x$NEEDINSTALL" = "xTrue" ] || [ "$BUILD_TYPE" = "stable" ]; then

            pip=$(command -v pip)
            vpython=$(head -n 1 "$pip" | sed "s/#\\!//g")

            "$vpython" "$pip" install -U -I pip --no-cache-dir
            "$vpython" "$pip" install -U -I setuptools --no-cache-dir
            set +e
            "$vpython" "$pip" install -U -I -r requirements_devel.txt --no-cache-dir
            # shellcheck disable=SC2181
            if [ $? -ne 0 ]; then
                "$vpython" "$pip" install -U -I -r requirements_devel.txt --no-cache-dir
                if [ $? -ne 0 ]; then
                    "$vpython" "$pip" install -U -I -r requirements_devel.txt --no-cache-dir
                    if [ $? -ne 0 ]; then
                        echo "Error setting environment"
                        exit 255
                    fi
                fi
            fi
            set -e

        fi

    else
        echo "We are already in a virtualenv environment. Assuming Microprobe-ready environment"
    fi
fi

# Add PATHs
export PYTHONPATH=$WORKSPACE/src/:$PYTHONPATH
export MICROPROBEDATA=$WORKSPACE/targets/
MICROPROBETEMPLATES="$(find "$(pwd)"/targets -type d -name templates -exec echo -n {}: \;)"
export MICROPROBETEMPLATES
MICROPROBEWRAPPERS="$(find "$(pwd)"/targets -type d -name wrappers -exec echo -n {}: \;)"
export MICROPROBEWRAPPERS
PATH=$PATH:$(find "$(pwd)/targets" -type d -name tools -exec echo -n {}: \;)
export PATH

find "$WORKSPACE/targets/" -name \*yaml.cache -delete
# export MICROPROBENOCACHE=True

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

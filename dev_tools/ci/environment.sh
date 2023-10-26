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
# Microprobe CI support scripts
#

set -e # Finish right after a non-zero return command

if [ -f "$0.error" ] && [ "$1" = "-c" ]; then
    echo "Error in $0"
    cat "$0.error"
    echo "Error in $0"
    exit 1
elif [ "$1" = "-c" ]; then
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
    echo "MAXJOBS $MAXJOBS"
fi

export MAXJOBS
TIMEOUT=7200
export TIMEOUT

# Check if we are in travis
if [ "$TRAVIS" = "true" ] && [ "$CI" = "true" ]; then
    export NICE=""
    export WORKSPACE="$TRAVIS_BUILD_DIR"
    if [ "$TRAVIS_BRANCH" = "master" ]; then
        export BUILD_TYPE="stable"
    fi
    MAXJOBS=1
    export NOSEOPTS=" -d -v -e load_tests --exe --processes=$MAXJOBS --detailed-errors --process-timeout=$TIMEOUT "

    MP_TESTING_COMPILER_RISCV_V22=$(command -v riscv64-linux-gnu-gcc-8)
    export MP_TESTING_COMPILER_RISCV_V22
else
    export NICE="nice -n 1"
    if [ "$WORKSPACE" = "" ]; then
        WORKSPACE=$(pwd)
        export WORKSPACE
    fi
    # export NOSEOPTS=" -d -v --with-coverage --cover-branches --cover-inclusive --cover-tests --with-xunitmp -e load_tests --exe --processes=$MAXJOBS --detailed-errors --process-timeout=$TIMEOUT --cover-xml --cover-erase "
    export NOSEOPTS=" -d -v --with-xunitmp -e load_tests --exe --processes=$MAXJOBS --detailed-errors --process-timeout=$TIMEOUT -x"
    # export NOSEOPTS="-d -v -e load_tests --exe --processes=$MAXJOBS -x --detailed-errors --process-timeout=$TIMEOUT"

    set +e
    MP_TESTING_COMPILER_RISCV_V22=$(command -v riscv64-linux-gnu-gcc-8)
    export MP_TESTING_COMPILER_RISCV_V22
    set -e

fi

# Python option. Make sure we are in a controlled environment
if [ "$PYTHON_VERSION" = "" ]; then
    PYTHON_VERSION="$(python3 -V 2>&1 | cut -d ' ' -f 2 | cut -d '.' -f 1,2)"
    echo "PYTHON_VERSION=$PYTHON_VERSION"
    export PYTHON_VERSION
fi

if [ "$BUILD_TYPE" != "stable" ]; then
    export BUILD_TYPE='devel'
else
    export BUILD_TYPE='stable'
fi

export MP_TESTING_CFLAGS_RISCV_V22="-march=rv64gc"
export MP_TESTING_DFLAGS_RISCV_V22="-M numeric,no-aliases"
export MP_TESTING_AFLAGS_RISCV_V22="-march=rv64gc"

# Check if we are in travis
if [ "$TRAVIS" = "true" ] && [ "$CI" = "true" ]; then
    MP_TESTING_COMPILER_POWER=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER
    MP_TESTING_COMPILER_POWER_V206=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V206
    MP_TESTING_COMPILER_POWER_V207=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V207
    MP_TESTING_COMPILER_POWER_V300=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V300
    MP_TESTING_COMPILER_POWER_V310=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V310
elif [ "$(uname -m)" = "ppc64le" ]; then
    set +e
    MP_TESTING_COMPILER_POWER=$(command -v gcc)
    export MP_TESTING_COMPILER_POWER
    MP_TESTING_COMPILER_POWER_V206=$(command -v gcc)
    export MP_TESTING_COMPILER_POWER_V206
    MP_TESTING_COMPILER_POWER_V207=$(command -v gcc)
    export MP_TESTING_COMPILER_POWER_V207
    MP_TESTING_COMPILER_POWER_V300=$(command -v gcc)
    export MP_TESTING_COMPILER_POWER_V300
    MP_TESTING_COMPILER_POWER_V310=$(command -v gcc)
    export MP_TESTING_COMPILER_POWER_V310
    set -e
else
    set +e
    MP_TESTING_COMPILER_POWER=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER
    MP_TESTING_COMPILER_POWER_V206=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V206
    MP_TESTING_COMPILER_POWER_V207=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V207
    MP_TESTING_COMPILER_POWER_V300=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V300
    MP_TESTING_COMPILER_POWER_V310=$(command -v powerpc64le-linux-gnu-gcc)
    export MP_TESTING_COMPILER_POWER_V310
    set -e
fi

export MP_TESTING_CFLAGS_POWER_V206="-mcpu=power7 -mtune=power7"
export MP_TESTING_DFLAGS_POWER_V206="-M power7"
export MP_TESTING_AFLAGS_POWER_V206="-mpower7"

export MP_TESTING_CFLAGS_POWER_V207="-mcpu=power8 -mtune=power8"
export MP_TESTING_DFLAGS_POWER_V207="-M power8"
export MP_TESTING_AFLAGS_POWER_V207="-mpower8"

export MP_TESTING_CFLAGS_POWER_V300="-mcpu=power9 -mtune=power9"
export MP_TESTING_DFLAGS_POWER_V300="-M power9"
export MP_TESTING_AFLAGS_POWER_V300="-mpower9"

export MP_TESTING_CFLAGS_POWER_V310="-mcpu=power10 -mtune=power10"
export MP_TESTING_DFLAGS_POWER_V310="-M power10"
export MP_TESTING_AFLAGS_POWER_V310="-mpower10"



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
        if [ "$2" != "" ]; then
            if [ -f "$2" ]; then
                set +e
                timeout 5 cat "$2"
                set -e
            fi
        fi
        exit 1
    else
        touch "$1.error"
        if [ "$2" != "" ]; then
            if [ -f "$2" ]; then
                set +e
                timeout 5 tee "$1.error" < "$2"
                set -e
            fi
        fi
        exit 0
    fi
}

# Check if we are in travis
if [ "$TRAVIS" = "true" ] && [ "$CI" = "true" ]; then
    if [ "$NEEDINSTALL" != "False" ]; then
        pip3 install -U pip
        pip3 install -U -r requirements_devel.txt
        pip3 install -U -r requirements.txt
        # shellcheck disable=SC2046
        pip3 install -U $(pip3 list | grep "\." | cut -d " " -f 1)
        # shellcheck disable=SC2046
        pip3 install -U $(pip3 list | grep "\." | cut -d " " -f 1)
        # shellcheck disable=SC2046
        pip3 install -U $(pip3 list | grep "\." | cut -d " " -f 1)
        NEEDINSTALL=False
        export NEEDINSTALL
    fi
else
    # Create a virtual environment and activate it and install dependencies
    # only if we are not already in a virtual env
    if [ "$VIRTUAL_ENV" = "" ]; then

        # No user packages within the virtual env
        export PYTHONPATH=""
        export PYTHONNOUSERSITE=True

        NEEDINSTALL="True"
        if [ ! -d "./venv-python$PYTHON_VERSION" ]; then
            NEEDINSTALL="True"
            rm -fr ./get_pip
            mkdir -p ./get_pip
            (cd ./get_pip
            wget https://bootstrap.pypa.io/get-pip.py --no-check-certificate
            "python$PYTHON_VERSION" get-pip.py --prefix . -I -U --disable-pip-version-check --no-warn-script-location
            PYTHONPATH=$(find ./lib/ -name site-packages -type d) ./bin/pip3 install --prefix . -I -U virtualenv --no-warn-script-location
            PYTHONPATH=$(find ./lib/ -name site-packages -type d) ./bin/virtualenv --clear --python="python$PYTHON_VERSION" "../venv-python$PYTHON_VERSION" --app-data "../.app-data-python$PYTHON_VERSION"
            )
            rm -fr ./get_pip
        fi
        # shellcheck source=/dev/null
        .  "$WORKSPACE/venv-python$PYTHON_VERSION/bin/activate"

        if [ "$NEEDINSTALL" = "True" ] || [ "$BUILD_TYPE" = "stable" ]; then

            pip=$(command -v pip3)
            vpython=$(head -n 1 "$pip" | sed "s/#\\!//g")

            "$vpython" "$pip" install -U pip
            "$vpython" "$pip" install -U setuptools
            set +e
            "$vpython" "$pip" install -U -r requirements_devel.txt
            # shellcheck disable=SC2181
            if [ $? -ne 0 ]; then
                "$vpython" "$pip" install -U -r requirements_devel.txt
                if [ $? -ne 0 ]; then
                    "$vpython" "$pip" install -U -r requirements_devel.txt
                    if [ $? -ne 0 ]; then
                        echo "Error setting environment"
                        exit 255
                    fi
                fi
            fi

            # shellcheck disable=SC2046
            "$pip" install -U $("$pip" list | grep "\." | cut -d " " -f 1)
            # shellcheck disable=SC2046
            "$pip" install -U $("$pip" list | grep "\." | cut -d " " -f 1)
            # shellcheck disable=SC2046
            "$pip" install -U $("$pip" list | grep "\." | cut -d " " -f 1)

            set -e

        fi

    else
        echo "We are already in a virtualenv environment. Assuming Microprobe-ready environment"
    fi
fi

# Add PATHs
export PYTHONPATH="$WORKSPACE/src/:$PYTHONPATH"
export MICROPROBEDATA="$WORKSPACE/targets/"
MICROPROBETEMPLATES="$(find "$(pwd)"/targets -type d -name templates -exec echo -n {}: \;)"
export MICROPROBETEMPLATES
MICROPROBEWRAPPERS="$(find "$(pwd)"/targets -type d -name wrappers -exec echo -n {}: \;)"
export MICROPROBEWRAPPERS
PATH=$PATH:$(find "$(pwd)/targets" -type d -name tools -exec echo -n {}: \;)
export PATH

find "$WORKSPACE/targets/" -name \*yaml.cache -delete
# export MICROPROBENOCACHE=True

# vim: set tabstop=4 softtabstop=4 shiftwidth=4 expandtab

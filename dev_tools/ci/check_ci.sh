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

shellcheck -x -s sh ./*.sh dev_tools/*/*.sh ./targets/*/dev_tools/*/*.sh
# Code Conventions (always run)
./dev_tools/ci/code_conventions_001_pycodestyle.sh
./dev_tools/ci/code_conventions_002_pylint.sh
./dev_tools/ci/code_conventions_003_documentation.sh
# Fast Functional Tests (run for branches and PR)
./dev_tools/ci/test_001_end2end_tools.sh
./dev_tools/ci/test_002_end2end_examples.sh
./dev_tools/ci/test_003_end2end_targets.sh
./dev_tools/ci/test_004_unittest.sh
# Build Release (always run)
./dev_tools/ci/build_001_distribution.sh
# Test Release Deploy (always run)
./dev_tools/ci/test_deploy_001_install.sh 2.7

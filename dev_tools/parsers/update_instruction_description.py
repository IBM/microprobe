#!/usr/bin/env python
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
"""
Helper script to fix instruction yaml descriptions from binutils source code
descriptions
"""

# imports
from __future__ import absolute_import
from __future__ import print_function
import sys
import os


def main():
    """ main function """
    usage = "Usage: %s [-h | " \
        "yaml_definition_file description_file ]" % sys.argv[0]

    if len(sys.argv) != 3:
        sys.exit(usage)
    elif sys.argv[1] == '-h':
        print(usage)
        print("")
        print("This utility translates read a yaml instruction definition ")
        print("file and fixes the instruction descriptions from a description")
        print(" file provided.")
        print("")
        sys.exit(1)

    inputfile = sys.argv[1]
    descfile = sys.argv[2]

    if not os.path.exists(inputfile):
        sys.exit('ERROR: Input file %s was not found!' % inputfile)

    if not os.path.exists(descfile):
        sys.exit('ERROR: Input file %s was not found!' % descfile)

    descriptions = {}
    descriptions_cnt = {}

    with open(descfile, 'r') as input_fd:

        for line in input_fd:

            if line.startswith("#") or line.strip() == "":
                continue

            mnemonic = str.upper(line.split(" ")[1])
            descr = line.split("\"")[1]

            descr = "%s%s" % (str.upper(descr[0]), str.lower(descr[1:]))

            if mnemonic not in descriptions:
                descriptions[mnemonic] = descr

    with open(inputfile, 'r') as input_fd:

        current_mnemonic = None

        for line in input_fd:
            line = line[:-1]

            if line.startswith("  Mnemonic: "):
                current_mnemonic = line.split('"')[1].upper()
                descriptions_cnt[current_mnemonic] = 1

            if (current_mnemonic is None or
                    not line.startswith("  Description: ") or
                    current_mnemonic not in descriptions):
                print(line)
                continue

            cdescription = "(".join(line.split('"')[1].split("(")[:-1]).strip()
            cmask = "(" + line.split('"')[1].split("(")[-1].strip()

            if cdescription == descriptions[current_mnemonic]:
                print(line)
                continue

            nfull = "  Description: \"%s %s\"" % (
                descriptions[current_mnemonic], cmask)

            print(nfull)


if __name__ == "__main__":
    main()

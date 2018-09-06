#!/usr/bin/env python
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

"""
docstring
"""

# imports
from __future__ import absolute_import
from __future__ import print_function
import sys
import os


# constants
usage = "Usage: %s [-h | input_table_file -f/-F]" % sys.argv[0]
formats = {}
fields = {}
dscr = "No description provided"


# functions
def print_header():
    print("# Copyright 2011-2018 IBM Corporation")
    print("# All rights reserved")
    print("#")
    print("# Author: Ramon Bertran")
    print("# Email: rbertra@us.ibm.com")
    print("#")
    print("# Version: 0.5")
    print("#")


def print_ifield(name, descr, size, show, IO, operand):
    print("- Name: \"%s\"" % name)
    print("  Description: %s" % descr)
    print("  Size: %s" % size)
    print("  Show: %s" % show)
    print("  IO: %s" % IO)
    print("  Operand: %s" % operand)


def print_iformat(name, dummy_descr, fields):
    print("- Name: \"%s\"" % name)
    print("  Description: %s Format" % name)
    print("  Fields:")
    for field in fields:
        print("  - %s" % field)
    print("  Assembly: OPC " + ",".join([field for field in fields
                                         if isinstance(field, str) and
                                         not field.startswith("opc")]))


# MAIN PROGRAM
# Parameter checking
if len(sys.argv) < 2:
    sys.exit(usage)
elif sys.argv[1] == '-h':
    print(usage)
    print("")
    print("This utility translates old Microprobe instruction format files")
    print("to YAML files used on the following version")
    print("")
    print("-h \t prints this help")
    print("-f \t Dumps the instruction fields ")
    print("-F \t Dumps the instruction formats ")
    sys.exit(1)
elif len(sys.argv) < 3 or sys.argv[2] not in ["-f", "-F"]:
    sys.exit(usage)

# Process input
inputfile = sys.argv[1]

if not os.path.exists(inputfile):
    sys.exit('ERROR: Input file %s was not found!' % inputfile)

dump_fields = sys.argv[2] == "-f"
dump_formats = sys.argv[2] == "-F"

with open(inputfile, 'r') as input_fd:

    for line in input_fd:
        line = line.strip()

        if line.startswith("#") or line == "":
            continue

        elif line.startswith("Field:"):
            field = line.split(":")[1].strip()
            size = int(line.split(":")[2].strip())
            assert field not in list(
                fields.keys()), "Field %s duplicated" % field
            fields[field] = size

        elif line.startswith("Format:"):
            line = line.replace("\t", " ")
            line = line.replace("Format:", "")
            linesplit = [elem.strip() for elem in line.split("|")][:-1]
            formatname = linesplit[0].replace(":", "")

            assert formatname not in list(formats.keys()), \
                "Format %s duplicated" % formatname
            ins_fmt = []
            formats[formatname] = ins_fmt
            for idx in range(1, len(linesplit)):
                subfield = linesplit[idx]
                if subfield.isdigit():
                    ins_fmt.append(size)
                else:
                    ins_fmt.append(subfield)
        else:
            raise Exception("Unknown format")


if dump_fields:
    print_header()
    for name in sorted(fields.keys()):
        size = fields[name]
        show = True
        IO = "N/A"
        operand = "XX"
        print_ifield(name, dscr, size, show, IO, operand)

elif dump_formats:
    print_header()
    for name in sorted(formats.keys()):
        fields = formats[name]
        print_iformat(name, dscr, fields)

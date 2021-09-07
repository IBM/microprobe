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
docstring
"""
# from microprobe.code.ins import Instruction
from __future__ import absolute_import
from __future__ import print_function
import sys
import six


usage = "Usage: %s [-h | options] < infile > outfile" % sys.argv[0]

# functions


def print_header():
    print("# Copyright 2011-2021 IBM Corporation")
    print("# All rights reserved")
    print("#")
    print("# Author: Ramon Bertran")
    print("# Email: rbertra@us.ibm.com")
    print("#")
    print("# Version: 0.5")
    print("#")


def print_int_property(name, descr, default, props):
    print_header()
    print("---")
    print("- Name: %s" % name)
    print("  Description: %s" % descr)
    print("  Default: %s" % str(default))
    print("  Values:")
    for prop, value in sorted(six.iteritems(props), key=lambda ins: ins[0]):
        if (value != default):
            print("    %s: %s" % (prop, str(value)))


if len(sys.argv) < 2:
    sys.exit(usage)
elif sys.argv[1] == '-h':
    print(usage)
    print("")
    print("This utility extracts fields from csv (stdin) to properties")
    print("")
    print("-h \t prints this help")
    print("-n [name] \tcolumn name to be the property")
    print("-f columnname=value \tfilter")
    print("-p name \t property name")
    print("-d default \t property default value")
    print("-D description \t property description")
    print("-k key \t property key")
    print("-s separator \t property separator (if multiple keys)")


skip = True

cname = None
pfilter = []
pname = None
pdesc = None
pdefault = None
pkey = []
pkeysep = None

for idx, value in enumerate(sys.argv):
    # print idx, value
    if skip:
        skip = False
        continue

    if value == "-n":
        assert cname is None, "Column name specified twice"
        cname = sys.argv[idx + 1]
        skip = True
    elif value == "-f":
        pfilter.append(sys.argv[idx + 1].split('='))
        skip = True
    elif value == "-p":
        assert pname is None, "Property name specified twice"
        pname = sys.argv[idx + 1]
        skip = True
    elif value == "-d":
        assert pdefault is None, "Property default specified twice"
        pdefault = sys.argv[idx + 1]
        skip = True
    elif value == "-k":
        pkey.append(sys.argv[idx + 1])
        skip = True
    elif value == "-s":
        assert pkeysep is None, "Key separator specified twice"
        pkeysep = sys.argv[idx + 1]
        skip = True
    elif value == "-D":
        assert pdesc is None, "Property descriptor specified twice"
        pdesc = sys.argv[idx + 1]
        skip = True

if pdesc is None:
    pdesc = "Not provided"

if pkeysep is None:
    pkeysep = "_"

assert cname is not None, "Column name not provided"
assert pname is not None, "Property name not provided"
assert pdefault is not None, "Default value not provided"
assert len(pkey) > 0, "Key not specified"

header = None


def get_value(line, key):
    val = [cidx for (cidx, cval) in enumerate(header.split(","))
           if cval == key][0]
    return line.split(",")[val]


def get_key(line):
    key = []
    for elem in pkey:
        key.append(get_value(line, elem))
    return pkeysep.join(key)


def filters_ok(line):
    for ufilter in pfilter:
        if get_value(line, ufilter[0]) != ufilter[1]:
            return False
    return True


props = {}
for line in sys.stdin.readlines():
    if header is None:
        header = line
        continue

    if filters_ok(line):
        props[get_key(line)] = get_value(line, cname)


print_int_property(pname, pdesc, pdefault, props)

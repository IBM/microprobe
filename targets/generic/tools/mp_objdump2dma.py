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
File: mp_dma2objdump

This script processes a dma file and dumps the corresponding objdump.
"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import sys

# Third party modules
from six.moves import range

# Own modules
from microprobe.exceptions import MicroprobeObjdumpError
from microprobe.utils.cmdline import CLI, existing_file, new_file
from microprobe.utils.misc import Progress, RejectingDict


# Constants
_DATAWIDTH = 8


# Functions
def dump_dma(arguments):
    """

    :param target:
    :type target:
    :param arguments:
    :type arguments:
    """

    ifile = open(arguments['input_objdump_file'], 'r')
    inputlines = ifile.readlines()
    ifile.close()

    progress = Progress(len(inputlines), msg="Lines parsed:")
    lines_dict = {}
    caddress = None
    displace = 0
    for idx, line in enumerate(inputlines):

        idx = idx + 1
        progress()

        line = line.strip()

        if line == "" or "file format" in line or line.startswith("Disass"):
            continue

        tsplit = line.split("\t")

        if len(tsplit) not in [1, 3, 4]:
            raise MicroprobeObjdumpError(
                "Unable to parse '%s' at line '%s'" % (line, idx)

            )
        if len(tsplit) == 1:

            space_split = tsplit[0].split(" ")

            if len(space_split) != 2:
                raise MicroprobeObjdumpError(
                    "Unable to parse '%s' at line '%s'" % (line, idx)
                )

            address, label = space_split

            if not label.endswith('>:') or label[0] != '<':
                raise MicroprobeObjdumpError(
                    "Unable to parse '%s' at line '%s'" % (line, idx)
                )

            try:
                new_address = int(address, 16)
            except ValueError:
                raise MicroprobeObjdumpError(
                    "Unable to parse '%s' at line '%s'" % (line, idx)
                )

            if caddress is None:
                caddress = new_address
            elif new_address != (caddress + displace):
                caddress = new_address
                displace = 0

            continue

        if len(tsplit) in [3, 4] and caddress is None:
            raise MicroprobeObjdumpError(
                "Unable to know the address of '%s' at line '%s'" % (line, idx)
            )

        if not tsplit[0].endswith(":"):
            raise MicroprobeObjdumpError(
                "Unable to parse '%s' at line '%s'" % (line, idx)
            )

        if (caddress + displace) < int(tsplit[0][:-1], 16):

            caddress = int(tsplit[0][:-1], 16)
            displace = 0

        elif (caddress + displace) > int(tsplit[0][:-1], 16):

            raise MicroprobeObjdumpError(
                "Conflicting addresses in '%s' at line '%s'" % (line, idx)
            )

        value = "".join(tsplit[1].split(' ')).lower()
        if caddress in lines_dict:
            lines_dict[caddress] += value
            displace += len(value) // 2
        else:
            lines_dict[caddress] = value
            displace = len(value) // 2

    used_addresses = RejectingDict()
    progress = Progress(len(list(lines_dict.keys())), msg="Writing output")

    with open(arguments['output_dma_file'], 'w') as fdout:

        for caddress in sorted(lines_dict):

            value = lines_dict[caddress]

            progress()

            if caddress % 8 != 0:

                contents = value[0:((caddress % 8) * 2)]
                value = value[((caddress % 8) * 2):]
                contents = "0" * (16 - len(contents)) + contents
                caddress = (caddress // 8) * 8

                line = "D %016x %s\n" % (caddress, contents)
                used_addresses[caddress] = line
                fdout.write(line)
                caddress += 8

            for idx in range(0, len(value), 16):

                contents = value[idx:idx + 16]
                contents += "0" * (16 - len(contents))

                line = "D %016x %s\n" % (caddress, contents)
                used_addresses[caddress] = line
                fdout.write(line)
                caddress += 8


# Main
def main():
    """
    Program main
    """
    args = sys.argv[1:]
    cmdline = CLI(
        "Microprobe Objdump to DMA tool",
        default_config_file="mp_objdump2dma.cfg"
    )

    groupname = "Objdump to DMA arguments"

    cmdline.add_group(
        groupname, "Command arguments related to Objdump to DMA tool"
    )

    cmdline.add_option(
        "input-objdump-file",
        "i",
        None,
        "Objdump file to process",
        group=groupname,
        opt_type=existing_file,
        required=True
    )

    cmdline.add_option(
        "output-dma-file",
        "O",
        None,
        "Output DMA file",
        group=groupname,
        opt_type=new_file,
        required=True
    )

    cmdline.main(args, _main)


def _main(arguments):
    """
    Program main, after processing the command line arguments

    :param arguments: Dictionary with command line arguments and values
    :type arguments: :class:`dict`
    """

    dump_dma(arguments)


if __name__ == '__main__':  # run main if executed from the command line
    # and the main method exists

    if callable(locals().get('main')):
        main()
        exit(0)

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
from __future__ import absolute_import
from __future__ import print_function
import sys

myfile = sys.argv[1]
old = sys.argv[2]
new = sys.argv[3]

print(("Replace '%s' by '%s' in '%s'" % (old, new, myfile)))

fd = open(myfile, 'r')
contents = ''.join(fd.readlines())
fd.close()

contents = contents.replace(old, new)

# print(contents)

fd = open(myfile, 'w')
fd.write(contents)
fd.close()

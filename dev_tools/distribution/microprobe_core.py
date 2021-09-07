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
Setup script for microprobe_core package
"""

from __future__ import absolute_import
import os
from setuptools import setup, find_packages
from microprobe.utils.info import AUTHOR, VERSION, EMAIL, MAINTAINER, LICENSE,\
    CLASSIFIERS, WEBSITE, PACKAGEURL, KEYWORDS


def read(fname):
    """ Read a file """
    return open(fname).read()


setup(
    version=VERSION,
    author=AUTHOR,
    author_email=EMAIL,
    maintainer=MAINTAINER,
    maintainer_email=EMAIL,
    license=LICENSE,
    name="microprobe_core",
    description=(
        "Microprobe: Microbenchmark generation framework: "
        "Main package"),
    keywords=KEYWORDS,
    url=WEBSITE,
    # download_url=PACKAGEURL,
    package_dir={
        '': os.path.join(
            ".",
            'src')},
    packages=find_packages(
        os.path.join(
            ".",
            'src')),
    package_data={
        '': [
            '*.yaml',
            'default/*yaml'],
        'microprobe': ['*.cfg'],
        'microprobe.definitions.generic.templates': ["*"]
    },
    entry_points={
        'console_scripts': [
            'mp_bin2asm = '
            'microprobe.definitions.generic.tools.mp_bin2asm:main',
            'mp_bin2objdump = '
            'microprobe.definitions.generic.tools.mp_bin2objdump:main',
            'mp_c2mpt = microprobe.definitions.generic.tools.mp_c2mpt:main',
            'mp_epi = microprobe.definitions.generic.tools.mp_epi:main',
            'mp_mpt2bin = microprobe.definitions.generic.tools.mp_mpt2bin:main',
            'mp_mpt2elf = microprobe.definitions.generic.tools.mp_mpt2elf:main',
            'mp_mpt2test = '
            'microprobe.definitions.generic.tools.mp_mpt2test:main',
            'mp_objdump2mpt = '
            'microprobe.definitions.generic.tools.mp_objdump2mpt:main',
            'mp_seq = microprobe.definitions.generic.tools.mp_seq:main',
            'mp_seqtune = '
            'microprobe.definitions.generic.tools.mp_seqtune:main',
            'mp_target = microprobe.definitions.generic.tools.mp_target:main',
        ]},
    install_requires=[
        'ordereddict',
        'PyYAML',
        'rxjson',
        'argparse',
        'fasteners',
        'cachetools',
        'six'],
    long_description=read(
        os.path.join(
            ".",
            "ABOUT.rst")),
    classifiers=CLASSIFIERS,
    zip_safe=False,
    platforms=['none-any'])

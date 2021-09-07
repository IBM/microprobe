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
Setup script for microprobe_target_power package
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os

# Third party modules
from setuptools import find_packages, setup

# Own modules
from microprobe.utils.info import AUTHOR, CLASSIFIERS, EMAIL, \
    KEYWORDS, LICENSE, MAINTAINER, PACKAGEURL, VERSION, WEBSITE

packages = [
    elem for elem in find_packages(
        os.path.join(
            ".",
            'src')) if '.power' in elem]


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
    name="microprobe_target_power",
    description=(
        "Microprobe: Microbenchmark generation framework: "
        "Target definitions for POWER"),
    keywords=KEYWORDS,
    url=WEBSITE,
    # download_url=PACKAGEURL,
    install_requires=['microprobe_core>=%s' % VERSION],
    package_dir={'': os.path.join(".", 'src')},
    packages=packages,
    package_data={
        '': ["*"]
    },
    entry_points={
        'console_scripts': [
            'mp_mpt2trace = '
            'microprobe.definitions.power.tools.mp_mpt2trace:main',
        ]},
    long_description=read(os.path.join(".", "ABOUT.rst")),
    classifiers=CLASSIFIERS,
    zip_safe=False,
    platforms=['none-any']
)

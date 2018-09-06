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
Setup script for microprobe_all package
"""

from __future__ import absolute_import
import os
from setuptools import setup
from setuptools.dist import Distribution
from microprobe.utils.info import AUTHOR, VERSION, EMAIL, MAINTAINER, LICENSE,\
    CLASSIFIERS, WEBSITE, PACKAGEURL, KEYWORDS


class GenericDistribution(Distribution):

    """ Force distribution to be pure """

    def is_pure(self):
        return True


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
    name="microprobe_all",
    description=(
        "Microprobe: Microbenchmark generation framework: "
        "A modular and extensible framework to generate microbenchmarks"),
    keywords=KEYWORDS,
    url=WEBSITE,
    download_url=PACKAGEURL,
    install_requires=['microprobe_core>=%s' % VERSION,
                      'microprobe_doc>=%s' % VERSION,
                      'microprobe_target_riscv>=%s' % VERSION,
                      ],
    long_description=read(os.path.join(".", "ABOUT.rst")),
    classifiers=CLASSIFIERS,
    zip_safe=False,
    platforms=['none-any'],
    distclass=GenericDistribution
)

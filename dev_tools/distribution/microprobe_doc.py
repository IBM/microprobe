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
Setup script for microprobe_doc package
"""

from __future__ import absolute_import
import os
from setuptools import setup
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
    name="microprobe_doc",
    description=(
        "Microprobe: Microbenchmark generation framework: "
        "Documentation"),
    keywords=KEYWORDS,
    url=WEBSITE,
    # download_url=PACKAGEURL,
    package_dir={'': os.path.join(".", 'src')},
    packages=['microprobe.doc'],
    package_data={
        '': ["*.html", "*/*.html", "*/*/*.html", "*/*/*/*.html",
             "*/*/*/*/*.html",
             "*.js",
             "*.inv",
             "*/*png",
             "*/*txt",
             "*/*gif",
             "*/*css",
             "*/*js",
             "*/*ico",
             ],
    },
    install_requires=['microprobe_core>=%s' % VERSION],
    long_description=read(os.path.join(".", "ABOUT.rst")),
    classifiers=CLASSIFIERS,
    zip_safe=False,
    platforms=['none-any']
)

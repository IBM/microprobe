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
""":mod:`microprobe.utils.imp` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import imp
import inspect
import os

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError, \
    MicroprobeCacheError, MicroprobeImportDefinitionError, \
    MicroprobeImportError
from microprobe.property import PropertyHolder, list_property_files
from microprobe.utils.cache import cache_file, \
    read_cache_data, update_cache_needed, write_cache_data
from microprobe.utils.logger import get_logger


# Constants
LOG = get_logger(__name__)
__all__ = [
    "find_subclasses", "get_all_subclasses", "get_object_from_module",
    "get_attr_from_module", "get_dict_from_module", "import_definition",
    "import_cls_definition", "import_operand_definition", "load_source"
]


# Functions
def _fix_importname(mname):
    """

    :param mname:

    """
    mname = os.path.normpath(mname)
    mname = mname.replace(".", "")
    mname = mname.replace("-", "")
    mname = mname.replace("_", "")
    mname = mname.replace(os.path.sep, "")
    mname = mname.replace(os.path.pathsep, "")
    return mname


def find_subclasses(module_str, clazz, extra_import_name=None):
    """

    :param module_str:
    :param clazz:
    :param extra_import_name:  (Default value = None)

    """
    LOG.debug(
        "Start find subclasses of '%s' in '%s' ", clazz.__name__, module_str
    )

    import_name = _fix_importname(module_str + clazz.__name__)

    LOG.debug("Import name: '%s'", import_name)

    if extra_import_name is not None:
        import_name = _fix_importname(import_name + str(extra_import_name))

    LOG.debug("Extra import name: '%s'", import_name)

    module = imp.load_source(import_name, module_str)

    LOG.debug("Module imported")

    # Only look for exported (a.k.a public) values
    if '__all__' in dir(module):
        names = getattr(module, '__all__')
    else:
        names = dir(module)

    LOG.debug("Exported symbols: %s", names)

    for name in names:
        obj = getattr(module, name)
        try:
            if (obj != clazz) and issubclass(obj, clazz):
                yield obj
        except TypeError:
            pass


def get_all_subclasses(cls):
    """

    """
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses


def get_object_from_module(clsname, module):
    """

    :param clsname:
    :param module:

    """

    try:
        module = imp.load_source(_fix_importname(module + clsname), module)
    except IOError:
        raise MicroprobeArchitectureDefinitionError(
            "Module '%s' not found" % module
        )

    for name in dir(module):
        if name == clsname:
            obj = getattr(module, name)
            if inspect.isclass(obj) or inspect.isfunction(obj):
                return obj

    raise MicroprobeArchitectureDefinitionError(
        "Class '%s' not found in "
        "module '%s'" % (
            clsname, module
        )
    )


def get_attr_from_module(attr, module):
    """

    :param clsname:
    :param module:

    """

    try:
        module = imp.load_source(_fix_importname(module + attr), module)
    except IOError:
        raise MicroprobeImportDefinitionError("Module '%s' not found" % module)

    for name in dir(module):
        if name == attr:
            obj = getattr(module, name)
            return obj

    raise MicroprobeImportDefinitionError(
        "Class '%s' not found in "
        "module '%s'" % (
            attr, module
        )
    )


def get_dict_from_module(module):
    """

    :param clsname:
    :param module:

    """

    try:
        module = imp.load_source(_fix_importname(module), module)
    except IOError:
        raise MicroprobeImportDefinitionError("Module '%s' not found" % module)

    moddict = module.__dict__.copy()
    alldef = moddict.get('__all__', [])

    return dict([(k, v) for k, v in moddict.items() if k in alldef])


def load_source(name, path):
    try:
        module = imp.load_source(name, path)
    except ImportError as exc:
        raise MicroprobeImportError(str(exc))

    return module


def import_definition(defdict, yaml, key, base_module, args, force=False):
    """Import definition

    :param defdict:
    :param yaml:
    :param key:
    :param base_module:
    :param args:

    """

    try:
        entry = defdict[key]
        cls = get_object_from_module(entry["Class"], entry["Module"])
    except KeyError:
        raise MicroprobeArchitectureDefinitionError(
            "'%s' key in %s "
            "file missing or not defined "
            "correctly." % (key, yaml)
        )

    filenames = [yaml, entry["Module"]] + entry["YAML"]

    if issubclass(cls, PropertyHolder):
        for cfile in entry["YAML"]:
            filenames += list_property_files(cfile)

    cache_filename = cache_file("%s.%s" % (yaml, cls.__name__))

    result = update_cache_needed(filenames, cachefile=cache_filename)
    result = result or force

    if not result:
        LOG.debug("Reading cache contents for %s", cls.__name__)
        try:
            return read_cache_data(cache_filename), result
        except ImportError:
            LOG.exception("Unable to read cache contents for %s", cls.__name__)
        except MicroprobeCacheError:
            LOG.debug("Cache error when reading class %s", cls.__name__)

    try:
        data = base_module.import_definition(cls, entry["YAML"], args)
    except KeyError:
        raise MicroprobeArchitectureDefinitionError(
            "'%s' key in %s "
            "missing the YAML attribute." % (key, yaml)
        )

    try:
        write_cache_data(cache_filename, data)
    except MicroprobeCacheError:
        LOG.debug("Cache error when writing class %s", cls.__name__)

    return data, result


def import_cls_definition(isadef, yaml, key, base_module):
    """

    :param isadef:
    :param yaml:
    :param key:
    :param base_module:

    """

    try:
        entry = isadef[key]
        return base_module.import_classes_from(entry["Modules"])
    except KeyError:
        raise MicroprobeArchitectureDefinitionError(
            "'%s' key in %s "
            "file missing or not defined "
            "correctly." % (key, yaml)
        )


def import_operand_definition(
    defdict, yaml, key, base_module,
    regs, force=False
):
    """

    :param defdict:
    :param yaml:
    :param key:
    :param base_module:
    :param regs:

    """

    try:
        entry = defdict[key]
    except KeyError:
        raise MicroprobeArchitectureDefinitionError(
            "'%s' key in %s "
            "file missing or not defined "
            "correctly." % (key, yaml)
        )

    filenames = [yaml] + entry["YAML"]
    cache_filename = cache_file("%s.Operand" % (yaml))

    result = update_cache_needed(filenames, cachefile=cache_filename)
    result = result or force

    if not result:
        LOG.debug("Reading cache contents for Operand")
        try:
            return read_cache_data(cache_filename), result
        except ImportError:
            LOG.exception("Unable to read cache contents for Operand")
        except MicroprobeCacheError:
            LOG.debug("Cache error when reading cache contents for Operand")
    try:
        data = base_module.import_definition(entry["YAML"], regs)
    except KeyError:
        raise MicroprobeArchitectureDefinitionError(
            "'%s' key in %s "
            "file missing or not defined "
            "correctly." % (key, yaml)
        )

    try:
        write_cache_data(cache_filename, data)
    except MicroprobeCacheError:
        LOG.debug("Cache error when writing cache contents for Operand")

    return data, result

# Classes

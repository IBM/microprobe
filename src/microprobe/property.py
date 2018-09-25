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
""":mod:`microprobe.property` module

"""

# Futures
from __future__ import absolute_import

# Built-in modules
import os

# Third party modules
import six

# Own modules
from microprobe.exceptions import MicroprobeArchitectureDefinitionError
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict
from microprobe.utils.yaml import read_yaml


# Constants
SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "schemas", "property.yaml"
)

LOG = get_logger(__name__)
__all__ = [
    "import_properties", "list_property_files", "Property", "PropertyHolder"
]


# Functions
def import_properties(filename, objects):
    """

    :param filename:
    :param objects:

    """
    LOG.info("Start importing object properties")
    dirname = filename[::-1].replace('lmay.', 'sporp_', 1)[::-1]

    if not os.path.isdir(dirname):
        return

    for filename in os.listdir(dirname):

        if filename.startswith(".") or filename.endswith(".cache"):
            continue

        if not filename.endswith(".yaml"):
            continue

        property_definitions = read_yaml(
            os.path.join(
                dirname, filename
            ), SCHEMA
        )

        for property_def in property_definitions:
            property_objs = RejectingDict()
            property_name = property_def["Name"]
            property_description = property_def.get(
                "Description", "No description"
            )

            property_override = property_def.get("Override", False)

            property_default_value = property_def.get("Default", "__unset__")
            property_values = property_def.get("Values", {})

            property_class = Property

            LOG.debug(
                "Importing property '%s - %s'", property_name,
                property_description
            )

            if "Value" in property_def:
                # Single value
                property_value = property_def["Value"]
                default_property = property_class(
                    property_name, property_description, property_value
                )
                for obj in objects.values():
                    obj.register_property(
                        default_property,
                        force=property_override
                    )

                LOG.debug("Single value property")
                continue

            if (
                property_default_value != "__unset__" and
                property_default_value != "NO_DEFAULT"
            ):
                default_property = property_class(
                    property_name,
                    property_description,
                    property_default_value,
                    default=True
                )
                LOG.debug("Default value: %s", property_default_value)
            else:
                default_property = None
                LOG.debug("Default value: No default value set")

            for key, obj in objects.items():

                if key not in property_values:

                    if property_default_value == "NO_DEFAULT":
                        continue

                    if default_property is None:
                        raise MicroprobeArchitectureDefinitionError(
                            "Wrong property '%s' definition in file '%s'. "
                            "Value for '%s' is not provided and a default "
                            "value is not defined" % (
                                property_name, filename, key
                            )
                        )

                    obj.register_property(
                        default_property,
                        force=property_override
                    )

                else:

                    property_value = property_values[key]
                    del property_values[key]

                    property_value_key = property_value
                    if isinstance(property_value, list):
                        property_value_key = str(property_value)

                    if property_value_key in property_objs:
                        obj.register_property(
                            property_objs[property_value_key],
                            force=property_override
                        )
                    else:
                        new_property = property_class(
                            property_name,
                            property_description,
                            property_value,
                            default=False
                        )
                        obj.register_property(
                            new_property, force=property_override
                        )
                        property_objs[property_value_key] = new_property

            for key, value in property_values.items():
                LOG.warning(
                    "'%s' not found. Property '%s' not set to '%s'", key,
                    property_name, value
                )

            LOG.info("Property '%s' imported", property_name)

    LOG.info("End importing object properties")


def list_property_files(filename):
    """

    :param filename:

    """

    dirname = filename[::-1].replace('lmay', 'sporp', 1)[::-1]

    if not os.path.isdir(dirname):
        return []

    return [
        os.path.join(dirname, cfile)
        for cfile in os.listdir(dirname)
        if not cfile.startswith(".") and not cfile.endswith(".cache")
    ]


# Classes
class Property(object):
    """Class to represent an object property"""

    def __init__(self, name, description, value, default=False):
        """

        :param name:
        :param description:
        :param value:
        :param default:

        """
        self._name = name
        self._description = description
        self._value = value
        self._default = default

    @property
    def name(self):
        """ """
        return self._name

    @property
    def description(self):
        """ """
        return self._description

    @property
    def value(self):
        """ """
        return self._value

    def set_value(self, val):
        """ """
        self._value = val

    @property
    def default(self):
        """ """
        return self._default

    def __str__(self):
        """ """
        if self.default:
            return "%s (%s): %s (default)" % (
                self.name, self.description, self.value
            )
        else:
            return "%s (%s): %s" % (self.name, self.description, self.value)

    def __repr__(self):
        """ """
        return "Property('%s', '%s', %s)" % (
            self.name, self.description, self.value
        )


class PropertyHolder(object):
    """Class to represent an object containing properties"""

    def _init_properties(self):
        """ """
        if self.__dict__.get("_properties", None) is None:
            # pylint: disable=attribute-defined-outside-init
            self._properties = RejectingDict()
            # pylint: enable=attribute-defined-outside-init

    def register_property(self, prop, force=False):
        """

        :param prop:

        """

        self._init_properties()

        LOG.debug("Registering '%s' in '%s' (Force: '%s')", prop, self, force)

        if prop.name not in self._properties:
            self._properties[prop.name] = prop
        elif not prop.default:
            if force or self._properties[prop.name].default:
                del self._properties[prop.name]
                self._properties[prop.name] = prop
            else:
                self._properties[prop.name] = prop

    def unregister_property(self, prop):
        """

        :param prop:

        """

        self._init_properties()
        del self._properties[prop.name]

    def list_properties(self, tabs=0):
        """ """

        self._init_properties()
        rstr = ""

        if len(self._properties) == 0:
            rstr += "    No properties \n"
            return rstr

        maxname = max(
            [
                len(str(value.name)) for value in
                six.itervalues(self._properties)
            ]
        ) + 2
        maxvalue = max(
            [
                len(str(value.value)) for value in
                six.itervalues(self._properties)
            ]
        )
        maxdesc = max(
            [
                len(str(value.description))
                for value in six.itervalues(self._properties)
            ]
        )

        strfmt = "\t" * tabs
        strfmt += "%%-%ds:\t%%-%ds\t(%%-%ds)\n" % (maxname, maxvalue, maxdesc)

        for key in sorted(six.iterkeys(self._properties)):
            value = self._properties[key]
            rstr += strfmt % (value.name, value.value, value.description)
        return rstr

    @property
    def properties(self):
        """

        """
        return self._properties.copy()

    def __getattr__(self, name):
        """

        :param name:

        """

        self._init_properties()
        if name in self._properties:
            # Memoize properties
            # They can not change over the execution
            value = self._properties[name].value
            setattr(self, name, value)
            return value

        raise AttributeError(
            "'%s' object has no attribute '%s'" %
            (self.__class__.__name__, name)
        )

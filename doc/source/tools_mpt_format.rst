============================
Microprobe test (mpt) format
============================

--------
Overview
--------

In order to facilitate the task of specifying tests to be reproduced/generated
by Microprobe, we defined the Microprobe test (mpt) file format. The base
format is the `INI File format <https://en.wikipedia.org/wiki/INI_file>`_.

The `INI File format <https://en.wikipedia.org/wiki/INI_file>`_ is a well-known
file format for system configuration, it is human-readable and simple to parse.
Basic features include:

- User specifies properties using entries like ``name = value``.
- Properties are grouped into arbitrary sections, which are defined using
  entries like ``[SECTION_NAME]``.
- Section and properties are **NOT** case sensitive.
- Everything after a semi-colon (``;``) is not processed.

More information `here <https://en.wikipedia.org/wiki/INI_file>`_.

---------------------------------
Mandatory header: the MPT Section
---------------------------------

All MPT files should define the ``[MPT]`` section in order to be parsed correctly.
This mandatory section defines the MPT file format used in the rest of the 
MPT file.  This will  allow us to maximize portability in the future (e.g. if 
new features are  added/removed from the MPT file). So, a valid MPT file header 
would be::

    [MPT]
    mpt_version = 0.5 ;  Format version of this MPT file.

Then, other sections and properties could be specified. Next sections
provides further details.

------------------
Format definitions
------------------

.. toctree::
   :maxdepth: 1
   
   tools_mpt_format_v05

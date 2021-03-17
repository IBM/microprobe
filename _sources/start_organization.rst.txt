===============================
Microprobe package organization
===============================

Microprobe is distributed using Python wheels packages via 
the public `Python Package Index (PyPI) <https://pypi.org/>`_.

----------------------
Release version scheme
---------------------- 

The release scheme is simple. It is as follows:

- *stable* and *development* releases: ``<major>.<minor>.<tag>`` 
  (e.g. ``0.5.<tag>` , ``0.9.<tag>``, ``1.0.<tag>``, ``1.1.<tag>``). 

The release tag is a time-stamp of the release in the 
form of ``<year><month><day><hour><minute><second>``. So, it is 
straighforward to figure out the relation between releases.

--------
Packages
--------

In order to provide fine-grained granularity of the different features and 
target definitions provided by Microprobe, the code is split in several 
packages. You'll find them in the corresponding repositories. Meta-packages 
are also provided to avoid the tedious task of updating all the packages one 
by one. 

The list of packages is the following:

**Common packages**:

====================================  ============  ===========================================
Name                                  Type          Description
====================================  ============  ===========================================
microprobe_all                        Meta-Package  All Microprobe common packages
microprobe_core                       Package       Core modules
microprobe_doc                        Package       Documentation
microprobe_target_riscv               Package       All RISCV target/tools definitions
====================================  ============  ===========================================


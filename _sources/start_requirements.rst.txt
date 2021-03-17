============
Requirements
============

**Microprobe** is written in Python, so you need a  
`Python <http://www.python.org>`_ installation to run it. As a result,
the basic requirements are the following:

* **python** >= 2.7, 3.6: Older/Newer Python versions may work but 
  we have not tested them. 
* **virtualenv** : A Python environment virtualizer that provides all the
  necessary tools to manage Python packages and execution environment.

The code is targeted to be architecture agnostic and OS agnostic, so it 
should run on PPC, Z or x86 platforms as well as on Linux or AIX 
systems. The code has been validated on the following platforms:

- PPC64/Linux with Python 2.7, 3.5
- PPC64/AIX with Python 2.7
- Z/Linux with Python 2.7
- x86_64/Linux with Python 2.7.10, 3.6, 3.7, 3.8, 3.9

If you have another environment that you would like to be tested, let us
know (:doc:`support_contact`). 

-----------------------------------
Installation/Upgrading requirements
-----------------------------------

Microprobe is distributed using a package manager. This allows the centralized
management of new releases, updates and bug fixes via a set repositories. 

* **virtualenv** : Necessary to ensure a clean installation and avoid 
  environment related Python configuration issues. Check 
  the `documentation <https://virtualenv.pypa.io/en/stable/>`_ 
  to install it on your system if you do not already have it. 
* **pip** : `Python package manager <http://pip.readthedocs.org/en/latest/quickstart.html>`_. 
  It is included by default in Python >= 2.7 and wihtin any *virtualenv* environments
  created. You should have it installed in your *virtualenv* environment by
  default. Check the `installation guide <http://pip.readthedocs.org/en/latest/installing.html>`_
  if you want to customize your own setup.
  
--------------------
Runtime requirements
--------------------

Some of the functionalities implemented within Microprobe require extra
Python packages. The installation instructions provided in this documentation
already take care of installing them but we provide the information in 
case you want to do a custom manual Microprobe installation.

The extra Python packages required are the following:
 
* **PyYAML** : YAML parsing package.  This is usually included 
  in a typical installation of Python and it is available as a binary 
  package in major Linux distributions. In case you do not have it, this 
  package can be found at `PyYAML <http://pyyaml.org/>`_ or installed 
  using **pip** (e.g. ``pip install --pre pyaml``).
* **ordereddict** : A drop-in substitute for Py2.7's new collections.OrderedDict 
  that works in Python 2.4-2.6. This is usually included 
  in a typical installation of Python 2.4-2.6 and it is available as a binary 
  package in major Linux distributions. In case you do not have it, this 
  package can be found at `ordereddict <https://pypi.python.org/pypi/ordereddict/>`_ or installed 
  using **pip** (e.g. ``pip install --pre ordereddict``).
* **argparse** : Command line parsing package.  This is usually included 
  in a typical installation of Python and it is available as a binary 
  package in major Linux distributions. In case you do not have it, this 
  package can be found at `argparse <https://pypi.python.org/pypi/argparse/>`_ or installed 
  using **pip** (e.g. ``pip install --pre argparse``).
* **rxjson** : Schema validation package. In case you do not have it, this 
  package can be found at `rxjson <https://github.com/spiral-project/rxjson>`_ or 
  installed using **pip** (e.g. ``pip install --pre rxjson``).
* **six** : Python 2 and 3 compatibility package. In case you do not have it,
  this package can be found at `pyevolve <http://pyevolve.sourceforge.net/>`_ 
  or installed using **pip** (e.g. ``pip install --pre six``).

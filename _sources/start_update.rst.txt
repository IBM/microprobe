====================
Upgrading Microprobe
====================

The process for installing Microprobe depends on your type of installation:
PIP (python package manager) based installation or GIT (development mode)
installation.

----------------------------
Upgrading a PIP installation
----------------------------

You just need to activate your Microprobe virtual environment and execute the 
pip command as following::

   > source INSTALLDIRECTORY/bin/activate
   > pip install -U --pre microprobe_all

If you only want to upgrade some packages within Microprobe, use the following
commands::

   > source INSTALLDIRECTORY/bin/activate
   > pip install -U --pre <your_microprobe_packages>

Check :doc:`start_organization` to know the list of packages available. 
    
----------------------------
Upgrading a GIT installation
----------------------------

If you have installed Microprobe directly from the GIT repository (preferred
option for developers), then execute these commands::

   > cd INSTALLDIRECTORY/microprobe
   > git pull --update --recurse-submodules
   > find . -name \.*.yaml*cache -delete

Basically, we are pulling the latest copy of the repository and the 
submodules from the origin repository and cleaning up any cached files.


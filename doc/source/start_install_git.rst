=============================
Installing Microprobe via GIT
=============================

This is the preferred method if you need to modify the code
to implement new functionalities and quick fixes. This way you
can quickly share your improvements to the rest of the community
using the regular GIT procedures. Check the
:doc:`devel` for further details.

----------------
Pre-requirements
----------------

* Check that you can access **GitHub**

  * Set up your account and make sure you can create your own
    repositories. Check the entire flow: create your own repository,
    clone it in your working directory/environment, make changes and
    commit them. Finally, push the changes to the server.
    If that works, you are all set to work with GitHub.

  * Resources:

    * https://education.github.com/git-cheat-sheet-education.pdf
    * Search internet using your favourite search engine

* Check that you have the appropriate access rights

  * Check if you can read/clone the public repository at 
    https://github.com/IBM/microprobe

-----------------
Required commands
-----------------

* **git**
* **python** 2.7 or >=3.6
* **virtualenv**: https://virtualenv.pypa.io/en/stable/

-----------------
First-time set up
-----------------

We are assuming a bash environment throughout the process. You might
try to use other shells, although some commands might need to be
modified accordingly. 

Execute the following commands the first time::

   > git clone --recursive https://github.com/IBM/microprobe INSTALLDIRECTORY/microprobe
   > cd INSTALLDIRECTORY/microprobe
   > bootstrap_environment.sh
   > . activate_microprobe

Hopefully, the installation is complete. Otherwise, report the
error to the development team (:doc:`support_contact`).

With commands above we did the following.
First, we have checked out the repository and all of its submodules.
Then, we set up a virtual python environment and install all 
the Microprobe dependencies to avoid any system dependency issues 
(``bootstrap_environment.sh``) and then we activated it.

----------------
Using Microprobe
----------------

You just need to execute the following command to start using
Microprobe::

   > . INSTALLDIRECTORY/activate_microprobe

You will see that you command prompt changes. You should be able
to execute the Microprobe related commands. This should be the only
command you need to execute before using Microprobe related commands
in the future.


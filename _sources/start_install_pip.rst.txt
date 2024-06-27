======================================
Installing Microprobe via PIP packages
======================================

Microprobe is distributed using the standard Python 
`Wheels <http://pythonwheels.com/>`_ packages. We followed the 
standard `Python Packaging User Guide <https://packaging.python.org/en/latest/>`_
to create them. We **strongly** recommend to take a look to both of these
links in order to understand how package management works in Python. That said,
let's summarize how to install Microprobe packages.

We suggest to install Microprobe in a `virtualenv` environment. To
do so execute the following commands::

   > virtualenv INSTALLDIRECTORY --prompt="(Microprobe) "
   > source INSTALLDIRECTORY/bin/activate
   
This will create a virtual python environment in the directory specified and 
activate it.  And the next step is to install Microprobe:: 

   > pip install --pre -U microprobe_all

Otherwise, execute the following command::

   > pip install --pre -U <your_microprobe_packages>
   
Check :doc:`start_organization` to know the list of packages available. 

----------------
Using Microprobe
----------------

Once the installation is complete you only need to activate the virtual environment
before using Microprobe via::

   > source INSTALLDIRECTORY/bin/activate

----------------
More information
----------------

We use the standard and well documented tools provided with the Python eco-system.
Refer to the extensive documentation on the web 
(e.g. `Python Packaging User Guide <https://packaging.python.org/en/latest/>`_)
to get more information.

.. note::

   We can not track broken things on all the possible linux/AIX distributions 
   and architectures. If the installation instructions do not work in you 
   system contact the main developers (:doc:`support_contact`)
   

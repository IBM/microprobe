================================
Checking Microprobe installation
================================

Remember that you have to activate the Microprobe virtual environment 
if you have installed it on a virtual environment::

> source INSTALLDIRECTORY/bin/activate

and if you are using Microprobe from the git repository, you should follow the 
procedure defined in :doc:`start_install_git`.

Then, you can check if *microprobe* package can be seen by the Python run-time 
by executing::

   > python -c "import microprobe"
   
If no error is shown, installation and environment set up is correct. 

Also, you can check the correctness of the installation by executing one
of the command line tools provided::

   > mp_target --help
   
You should get something like:

.. program-output:: ../../targets/generic/tools/mp_target.py --help 

If you do not get any error, you are done and ready to go. Otherwise, 
double-check your installation. Check :doc:`start_install` for further details.

Finally, if something is still wrong, request :doc:`support`. 

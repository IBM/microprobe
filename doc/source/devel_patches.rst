==================
Submitting patches
==================

.. note::

   Only use this method to submit patches if you are in a PIP-based 
   installation. If you are in a development installation (direct installation
   from GitHub), you just need to follow the standard workflow procedures
   in GIT. The procedure is the following:

   #. Do code modifications and commit changes on your personal copy of 
      the repository
   #. Create a pull request to *master* branch
   
   Check the :doc:`devel` section for further details.

Since Microprobe is written in python and all target description files are
text based YAML files, the source code of the framework is available in the
framework installation directory. This enables users to inspect the code and
implement modifications directly, without requiring further installation or
compilation steps. That is, if you want a feature or you detected an issue, 
you can edit the source and start fixing/developing it right away!

Before making any edit to the files, you should do a copy of the file you are
going to modify so that you can generate a patch lately. After creating a 
backup copy of the original, you can start to edit and test your code. 
Once you are comfortable with it, generate a patch using the following command::

   > diff -Naur file new_file  > file.patch 

This will generate a ``file.patch`` file that you can attach to a GitHub
issue. When submitting patches/pull requests, you agree to the 
terms explained in :doc:`devel_contributing`. 

.. warning::

   Do not update your the installation without saving first the modified 
   files. Otherwise, you will lose the modifications.


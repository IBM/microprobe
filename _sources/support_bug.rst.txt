============================
Report bugs & Submit patches
============================

Microprobe is a framework that has been used internally at IBM for some years 
and it has established a reputation for systematizing code generation
tasks. During these initial years, the developers of Microprobe were 
the only users of it and consequently, any deficiency found in the software 
was fixed right away. Lately, Microprobe main effort has been to enable other
users to use the framework by improving the documentation and the 
interfaces provided. This is a time-consuming taks after so many years of
*research-like code* development. Meanwhile, we --the developers-- 
would like to know of any deficiencies you find in Microprobe.
Don't be shy and report anyting you consider that will improve the
framework!

------------------
Documentation bugs
------------------

If you find a bug in this documentation (typos, ...) or would like to propose 
an improvement (some explanation is not clear, ...), please open a bug issue
in the `Microprobe`_ repository (see instructions below). If you have 
a suggestion how to fix it, include that as well.

----------------------------
Using GitHub to report a bug
----------------------------

Bug reports for Microprobe itself should be submitted via the 
`Microprobe`_ GitHub . GitHub offers **issue** support which allows 
the user to enter information and share it to the developers. 

The first step in filing a report is to determine whether the problem has 
already been reported. The advantage in doing so, aside from saving the 
developers time, is that you learn what has been done to fix it; it may be 
that the problem has already been fixed for the next release, or additional 
information is needed (in which case you are welcome to provide it if you 
can!). To do this, search first for existing issues. 

If the problem you're reporting is not already reported, 
create a new issue at https://github.com/IBM/microprobe/issues. 

To create a new issue, just go to the *Issues* section and click the
*New issue* button. The new issue form has various fields. 
For the "Title" field, enter a **very** 
short description of the problem; less than ten words is good. 

In the "Rich text" field, describe the problem in detail, including what you 
expected to happen and what did happen. Be sure to include whether any 
extension modules were involved, and what hardware and software platform you 
were using (including version information as appropriate) if you
think the problem is related to that. 

Attach any necessary files to be able to reproduce the problem if needed. 
If you found the solution for the problem you can attach the patch in this
section as well. See the section **Submit patches** to check how to create 
patch files.    

In the 'labels' section on the right, select the ones that apply
to the current issue. You can also add any label as you wish to describe
better the problem. 

Each bug report will be reviewed by a developer who will determine what needs 
to be done to correct the problem. You will receive an update each time action 
is taken on the bug.

.. seealso::

   - `How to Report Bugs Effectively <http://www.chiark.greenend.org.uk/~sgtatham/bugs.html>`_
      Article which goes into some detail about how to create a useful bug report.
      This describes what kind of information is useful and why it is useful.

   - `Bug Writing Guidelines <https://developer.mozilla.org/en-US/docs/Mozilla/QA/Bug_writing_guidelines>`_
      Information about writing a good bug report.  Some of this is specific to the
      Mozilla project, but describes general good practices.
      
--------------
Submit patches
--------------

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
issue. 

.. warning::

   Do not update your the installation without saving first the modified 
   files. Otherwise, you will lose the modifications.

.. _`Microprobe`: https://github.com/IBM/microprobe 

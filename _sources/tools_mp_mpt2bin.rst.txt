================
Tool: mp_mpt2bin
================

--------
Overview
--------

MicroprobeTest (mpt) to BIN loop tool provides a command-line interface (CLI) to
convert code snippets to BINARY format. Using a test definition 
format (:doc:`tools_mpt_format`), the user can specify the initial state 
(initialization of the registers), the variables that have to be declared 
and the code snippet, which might contain references to those variables, 
branch labels, fixed addresses, etc. Check the :doc:`tools_mpt_format` for 
further details.

.. note::

   The microbenchmark generation policy implemented in this tool reproduces
   exactly the code provided. It resolves any symbolic 
   references (references to data, or branch targets), and only if specified
   by the user, it also modifies memory accesses to avoid segmentation fault 
   issues. The tool wraps the code provided within an endless loop. 

-----------
Basic usage
-----------

::

   > mp_mpt2bin -T TARGET -t MPT_DEFINITION_FILE -O MPT_OUTPUT_FILE

where:

========================================================================= =================================================================
Flag/Argument                                                             Description
========================================================================= =================================================================
``-T TARGET``, ``--target TARGET``                                        Target definition string. Check: :doc:`tools_target_definition`.
``-t MPT_DEFINITION_FILE``, ``--mpt-definition-file MPT_DEFINITION_FILE`` Microprobe test definition file. Check: :doc:`tools_mpt_format`.
``-O MPT_OUTPUT_FILE``, ``--bin-output-file MPT_OUTPUT_FILE``             Output file name.
========================================================================= =================================================================

----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_mpt2bin.py --help

---------
Fix flags
---------

As stated above, this tool does not ensure that the memory address accessed by
the assembly code access valid storage regions. For that, one has to declare 
the appropriate variables and initialize valid register contents. 
Also, it might be the case that the code still is not correct and extra
modifications are required. 

Going through the assembly to understand it and manually modify it to make 
sure it runs correctly can be a tedious task. This tool provide a set of flags
that perform predefined modifications on that code with the aim to make
sure that at least it will run correctly. One has to take into account that 
the modifications might change the performance profile of the code. So, we 
strongly suggest you to validate the code generated to make sure it is still
valid for your needs.  

In the table below, we summarize the flags that
enable extra modification to the code:

============================ =======================================================
Flag                         Description
============================ =======================================================
``--fix-memory-references``  Fix registers that are used to compute addresses in
                             instruction accessing that access storage locations.
``--fix-memory-registers``   Fix instructions touching registers used for storage
                             address computations. If an instruction modifies a 
                             register that is used for storage address computation, 
                             the instruction is modified to not modify such register.
                             Instead, a register that minimizes the dependency 
                             between instructions is used. Also, load and update
                             or store and update instructions are replaced by their
                             very same implementation without the update. Implies
                             --fix-memory-references flag. 
``--fix-indirect-branches``  Fix branches without known target. Any branch with 
                             unknown target is replaced by an unconditional branch 
                             to the next instruction. 
``--fix-branch-next``        Force target of branches to be the next sequential
                             instruction.
============================ =======================================================


================
Tool: mp_mpt2elf
================

--------
Overview
--------

MicroprobeTest (mpt) to ELF loop tool provides a command-line interface (CLI) to
convert code snippets to assembly and ELF format. Using a test definition 
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

   > mp_mpt2elf -T TARGET -t MPT_DEFINITION_FILE -O ASM_FILE --compiler COMPILER_PATH 

where:

========================================================================= =================================================================
Flag/Argument                                                             Description
========================================================================= =================================================================
``-T TARGET``, ``--target TARGET``                                        Target definition string. Check: :doc:`tools_target_definition`.
``-t MPT_DEFINITION_FILE``, ``--mpt-definition-file MPT_DEFINITION_FILE`` Microprobe test definition file. Check: :doc:`tools_mpt_format`.
``-O ASM_FILE``, ``--mpt-output-file ASM_FILE``                           Output file name.
``--compiler COMPILER_PATH``                                              Compiled binary. If provided the tools compiles the generated 
                                                                          assembly file.
========================================================================= =================================================================

----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_mpt2elf.py --help

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

-------------
Linker script
-------------

The assembly file generated provides the linker script required for compilation
in comments. To extract it you should execute the following command::

   > grep "MICROPROBE LD" assembly_file | cut -d '@' -f 2 > custom.ld.script

---------
Compiling
---------

In order to maintain the memory layout in the generated binary, should
provide the linker scripts during the program compilation::

   > gcc -o output input.s -static -T custom.ld.script -T default.system.ld.script
   
To obtain the default system ld script one can execute::

   > ld --verbose > default.system.ld.script
   
and then remove the comments in the file (header and footer).


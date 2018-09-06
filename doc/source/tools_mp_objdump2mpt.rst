====================
Tool: mp_objdump2mpt
====================

--------
Overview
--------

Objdump to MicroprobeTest (mpt) tool provides a command-line interface (CLI)
to interpret objdump outputs and generate the corresponding MPT file
(:doc:`tools_mpt_format`). From the MPT format the user can use existing
tools (:doc:`tools`) to produce test cases for different environments and
formats. 

.. note::

   The microbenchmark generation policy implemented in this tool reproduces
   exactly the code provided. It resolves any symbolic 
   references (references to data, or branch targets), and only if specified
   by the user, it initializes some registers to not break the target 
   Application Binary Interface.


-----------
Basic usage
-----------

::

   > mp_objdump2mpt -T TARGET -i OBJDUMP_FILE -O MPT_OUTPUT_FILE

where:

=============================================================== =================================================================
Flag/Argument                                                   Description
=============================================================== =================================================================
``-T TARGET``, ``--target TARGET``                              Target definition string. Check: :doc:`tools_target_definition`
``-i OBJDUMP_FILE``, ``--input-objdump-file OBJDUMP_FILE``      Objdump file generated with Objdump (see details in the following section)
``-O MPT_OUTPUT_FILE``, ``--mpt-output-file MPT_OUTPUT_FILE``   Output file name
=============================================================== =================================================================

------------------------------
How to obtain an objdump file?
------------------------------

**objdump** (part of the GNU Binutils) is a program for displaying various 
information about object files. An object file is a file containing object 
code, meaning relocatable format machine code that is usually not directly 
executable. There are various formats for object files, and the same object 
code can be packaged in different object files. In addition to the object code 
itself, object files may contain metadata used for linking or debugging, 
including: information to resolve symbolic cross-references between different 
modules, relocation information, stack unwinding information, comments, program
symbols, debugging or profiling information.
Consequently, **objdump** can be used as a disassembler to view an executable 
in assembly form. More details 
`on the wikipedia webpage <https://en.wikipedia.org/wiki/Objdump>`_.

The command to get an dump of a binary using **objdump** is the 
following::

   > objdump -D -z your_binary_file > mydump.dump
   
the ``-D`` flag forces the tool to dump also the data sections (not
only the executable ones) and the ``-z`` flag instructs the tool to dump 
everything (long regions of zero values are typically excluded). 

.. note:: 

   Only dumps from GNU Binutils **objdump** are currently supported.

-----------------------------------------
Ensuring the Application Binary Interface
-----------------------------------------

The ABI (Application Binary Interface) for a given environment (defined in 
`here <http://refspecs.linuxbase.org/>`_ ) specifies the semantics of registers
and the calling conventions. For instance, usually a register is reserved
to point to the stack. So, the code being extracted from the objdump output
requires that these registers contain appropriate values. It is up to the user
to initialize them correctly, although the tool provides some support for
that. 

Currently, this tool supports the automatic definition of the stack, 
the automatic initialization of the stack pointer and the definition of the
start symbol which will be called after initializing the environment. 
The user can use the following flags to change the different options:

================================= ======================================================
Flag/Argument                     Description
================================= ======================================================
``--elf-abi``                     Ensure ELF Application Binary Interface (e.g. define
                                  stack, stack pointer, etc.)
``--stack-size STACK_SIZE``       Stack size in bytes (default: 4096)
``--stack-name STACK_NAME``       Stack name (Default: microprobe_stack)
``--stack-address STACK_ADDRESS`` Stack address (Default: allocated in the data area)
``--start-symbol START_SYMBOL``   Symbol to call after initializing the stack. If not
                                  specified, no call is performed
``--end-branch-to-itself``        End the code with a branch to itself instruction
================================= ======================================================

.. note::

   The necessary instructions required for initializing the stack pointer
   will be added at the beginning of the code (on lower addresses) and the
   start code address will be modified accordingly.
   
.. note::

   If the start symbol is specified, function linkage instructions are used
   to call that symbol after initializing the environment. It is up to the
   user to define the behavior when the called function returns. That is, no
   specific instructions are added after the call (return address for the 
   called function) and therefore the behavior is not specified.  
   
----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_objdump2mpt.py --help

---------------
Example outputs
---------------

.. rubric:: Example 1:

Command::

   > mp_objdump2mpt.py -T riscv_v22-riscv_generic-riscv64_linux_gcc -O output.mpt -i input.objdump -s microprobe.text --elf-abi 
   
Input file ``input.objdump``:

.. literalinclude:: ./examples/example_mp_objdump2mpt.dump
    :linenos:
 
Output file ``output.mpt``:

.. literalinclude:: ./examples_outputs/example_mp_objdump2mpt.mpt
    :linenos:
 

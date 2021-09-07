==================
Tool: mp_mpt2trace
==================

--------
Overview
--------

MicroprobeTest (mpt) to trace loop tool provides a command-line interface (CLI) to
convert code snippets to execution trace format. Using a test definition 
format (:doc:`tools_mpt_format`), the user can specify the initial execution
address, the code to be executed as well as the execution and memory 
access patterns to be generated in the trace. 

.. note::

   The microbenchmark generation policy implemented in this tool reproduces
   exactly the execution pattern and memory access patterns indicated via
   command line parameters or using decorators in the MPT definition file. 
   This tools does not try to emulate what would be the execution pattern
   or the memory access pattern of the code. It is up to the user to provide
   the right pattern to be generated.

-------------
Trace formats
-------------

====== ========= =================================================================
Format Extension Description
====== ========= =================================================================
Qtrace ``qt``    `Qtrace format <https://github.com/antonblanchard/qtrace-tools>`_
====== ========= =================================================================

.. note::

   If the output filename provided ends with ``.gz`` or ``.bz2`` extensions,
   the trace generated is automatically compressed using the format
   specified. 

-----------
Basic usage
-----------

::

   > mp_mpt2trace -T TARGET -t MPT_DEFINITION_FILE -O TRACE_OUTPUT_FILE

where:

========================================================================= =================================================================
Flag/Argument                                                             Description
========================================================================= =================================================================
``-T TARGET``, ``--target TARGET``                                        Target definition string. Check: :doc:`tools_target_definition`.
``-t MPT_DEFINITION_FILE``, ``--mpt-definition-file MPT_DEFINITION_FILE`` Microprobe test definition file. Check: :doc:`tools_mpt_format`.
``-O TRACE_OUTPUT_FILE``, ``--trace-output-file MPT_OUTPUT_FILE``         Output file name.
========================================================================= =================================================================

----------
Full usage
----------

.. program-output:: ../../targets/power/tools/mp_mpt2trace.py --help

---------------
Example outputs
---------------

.. rubric:: Example 1:

Command::

   > mp_bin2trace -T power_v300-power9-ppc64_linux_gcc -i mpt2trace_test001.mpt --show-trace --default-memory-access-pattern 0x200000-0x200100-8
  
Input file:

.. literalinclude:: ../../targets/power/tests/tools/mpt2trace_test001.mpt
    :lines: 42-110
   
Output:

.. literalinclude:: ./examples_outputs/example_mpt2trace.output

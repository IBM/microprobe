===================
Tool: mp_coblst2mpt
===================

--------
Overview
--------

COBOL listing to MicroprobeTest (mpt) tool provides a command-line interface (CLI)
to interpret COBOL listings and generate the corresponding MPT file
(:doc:`tools_mpt_format`). From the MPT format the user can use existing
tools (:doc:`tools`) to produce test cases for different environments and
formats. 

.. note::

   The microbenchmark generation policy implemented in this tool reproduces
   exactly the code provided. 

-----------
Basic usage
-----------

::

   > mp_coblst2mpt -T TARGET -i COBOL_LST_FILE -O MPT_OUTPUT_FILE

where:

=============================================================== =================================================================
Flag/Argument                                                   Description
=============================================================== =================================================================
``-T TARGET``, ``--target TARGET``                              Target definition string. Check: :doc:`tools_target_definition`
``-i COBLST_FILE``, ``--input-coblst-file OBJDUMP_FILE``        COBOL Listing file
``-O MPT_OUTPUT_FILE``, ``--mpt-output-file MPT_OUTPUT_FILE``   Output file name
=============================================================== =================================================================

----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_coblst2mpt.py --help


====================
Tool: mp_dma2objdump
====================

--------
Overview
--------

The **mp_dma2objdump** tool provides an interface to disassemble raw DMA 
files. DMA file format is a simple format that specifies contents for each 
address of memory. E.g. each line of the file contains 
``D <address> <contents>``.  This format is used during early stages of 
bring-up and characterization to set up the contents of the processors cache 
directly, without requiring a fully operational system.   
  
-----------
Basic usage
-----------

::

   > mp_dma2objdump -T TARGET -i INPUT_DMA_FILE > OBJDUMP_FILE

where:

============================================================ =================================================================
Flag/Argument                                                Description
============================================================ =================================================================
``-T TARGET``, ``--target TARGET``                           Target definition string. Check: :doc:`tools_target_definition`.
``-i INPUT_DMA_FILE``, ``--input-dma-file INPUT_BIN_FILE``   Input DMA file.
============================================================ =================================================================

----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_dma2objdump.py --help


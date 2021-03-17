================
Tool: mp_bin2asm
================

--------
Overview
--------

The **mp_bin2asm** tool provides an interface to disassemble raw binary files.
Some of the back-ends for Microprobe generate ``*.bin`` files that contain
the generated codified instructions. In order to debug and check what it is
generated, one can use this tool and get the corresponding assembly.  

-----------
Basic usage
-----------

::

   > mp_bin2asm -T TARGET -i INPUT_BIN_FILE > ASM_FILE

where:

============================================================ =================================================================
Flag/Argument                                                Description
============================================================ =================================================================
``-T TARGET``, ``--target TARGET``                           Target definition string. Check: :doc:`tools_target_definition`.
``-i INPUT_BIN_FILE``, ``--input-bin-file INPUT_BIN_FILE``   Input binary file.
============================================================ =================================================================

----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_bin2asm.py --help


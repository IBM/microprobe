===============
Tool: mp_target
===============

--------
Overview
--------

Microprobe Target definition query tool. It provides an interface
to dump different aspects of the target definition such as:

- instruction information (input/ouput operands)
- instruction format
- instruction properties
- microarchitecture component hierarchy
- cache hierarchy details and properties
- ...  

-----------
Basic usage
-----------

::

   > mp_target -T TARGET

where:

================================== ================================================================
Flag/Argument                      Description
================================== ================================================================
``-T TARGET``, ``--target TARGET``  Target definition string. Check: :doc:`tools_target_definition`.
================================== ================================================================

----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_target.py --help

---------------
Example outputs
---------------


.. rubric:: Example 1:

Command::

   > mp_target -T riscv_v22-riscv_generic-riscv64_linux_gcc

Output:

.. program-output:: ../../targets/generic/tools/mp_target.py -P ../../targets/ -T riscv_v22-riscv_generic-riscv64_linux_gcc
 

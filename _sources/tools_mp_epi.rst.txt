============
Tool: mp_epi
============

--------
Overview
--------

The **mp_epi** tool provides an interface to generate instruction-based
stressmarks. Instruction-based stressmarks are loops with a particular 
instruction repeated several times. They are ideal to perform energy per
instruction characterizations as well as performance profile of the ISA.  
Users can control the level of instruction-level parallelism and the
loop size via configurable parameters.  

-----------
Basic usage
-----------

::

   > mp_epi -T TARGET -D OUTPUT_DIR 
       
where:

================================================================================================== =================================================================
Flag/Argument                                                                                      Description
================================================================================================== =================================================================
``-T TARGET``, ``--target TARGET``                                                                 Target definition string. Check: :doc:`tools_target_definition`.
``-D OUTPUT_DIR``, ``--epi-output-dir OUTPUTDIR``                                                  Output directory.                                         
================================================================================================== =================================================================

The parameters above are the minimum number of parameters required to generate
one stressmark with maximum ILP (no dependency) per instruction available 
in the architecture.  There are other parameters to tune
the code being generated. Check the rest of this document for details. 
    
----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_epi.py --help
 

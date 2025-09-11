================
Tool: mp_seqtune
================

--------
Overview
--------

The **mp_seqtune** tool provides an interface to generate stressmarks around
a base instruction sequence. Given a base instruction sequence, the
tool generates variations around it based on the user input parameters. One
can modify the memory access patterns, add instructions from time to time, 
replace other instructions from time to time, maximize the data switching 
factors, model the branch behavior, etc. All these transformations are usually
useful during the search of maximum power stressmarks.

-----------
Basic usage
-----------

::

   > mp_seqtune -T TARGET -D OUTPUT_DIR -seq INSTRUCTION_SEQUENCE
       
where:

================================================================================================== =================================================================
Flag/Argument                                                                                      Description
================================================================================================== =================================================================
``-seq INSTRS``, ``--sequence INSTRS``                                                             Comma separated list of instructions that define the base 
                                                                                                   sequence.
``-T TARGET``, ``--target TARGET``                                                                 Target definition string. Check: :doc:`tools_target_definition`.
``-D OUTPUT_DIR``, ``--seq-output-dir OUTPUTDIR``                                                  Output directory.                              
================================================================================================== =================================================================

There are other parameters to tune the code being generated. Check the 
rest of this document for details. The example section provides a
detailed use case scenario that uses some of the extra parameters.
    
----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_seqtune.py --help
 
----------------
Example use case
----------------

This use case is using the **power_v300-power9-ppc64_linux_gcc** target for
illustrative purposes. The same can be done on other targets.  

Let's assume that you have analyzed different instruction sequences 
(check :doc:`tools_mp_seq`) on the target and you have decided
a base instruction sequence to be the following::

  > SUBFIC_V0,LVXL_V0,LWA_V0,SUBFIC_V0,LXVW4X_V0,VMHADDSHS_V0 

Then, you want to generate variations around that base sequence that
generate different memory access patterns that do the following:

* Four memory access patterns that access, each of them, a memory range from 
  2K to 32K in steps of 1K.
* Each memory access pattern access its own memory range in a round-robin
  fashion using a minimum stride of 144 bytes.
* Each memory access pattern has the same probability to be used.
* Each memory access pattern use a single set for base/index registers.
* No added randomness in the memory access pattern.  
* No added temporal locality in the memory access pattern.

To do so, we need to issue the following command::

  > mp_seqtune -T power_v300-power9-ppc64_linux_gcc -D . -seq SUBFIC_V0,LVXL_V0,LWA_V0,SUBFIC_V0,LXVW4X_V0,VMHADDSHS_V0 -me 4:2048-32768-1024:1:144:1:0:1:0 

This will generate 31 microbenchmarks in the current directory. One with 
4 streams accessing each 2K memory region, one with 4 streams accessing each a
3K memory reagion, etc. up to 32K memory region. 

In the command above, we used the ``-me`` parameter to specify the 
variations to be generated around the memory behavior. The parameter value
is split in 8 fields using ``:`` symbol. The meaning of the fields is the 
following:

* 4 : number of memory streams
* 2048-32768-1024 : memory sizes for each stream. This tuple is interpreted as
  ``<start>-<end>-<step>``. Note that the ``<step>`` field is optional. 
  This format can be used in other parameters and fields. 
* 1 : weight these streams. This directly translates to the probability of a
  given stream to be used. E.g.
  if we define 3 memory streams with one having a weight of 2 and the other
  2 a weight of 1, the probability will be: 50%, 25% and 25% for each of them.  
  This results in that every 4 memory accesses 2 will use stream 1, and the 
  other 2 stream 2 and 3, respectively.
* 144 : stream stride in bytes. Stride between consecutive accesses in the same 
  stream. In this case, the stream will access positions 0, 144, 288, etc. 
  until the maximum size is reached. Then, it will start from zero again. 
* 1 : number of register sets to be use for the stream. Streams require the
  reservation of base/index registers for address computations. If there are
  enough registers available, one might want to increase this number to
  increase the ILP between address computation and usage.      
* 0 : No randomness. Memory accesses will be performance sequentially using
  stride specified. If the value is set to -1, the memory access stream is
  completelly random. If set to a value > 0, the memory access stream is
  random within the specified range. 
* 1:0 : No added temporaral locality since last 1 memory access will be repeated
  0 times before moving to next memory address.

.. note:: 

   One can use the ``-N`` flag to check the sequence definition and the number 
   of sequences that are going to be generated before starting the generation
   process.



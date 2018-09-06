============
Tool: mp_seq
============

--------
Overview
--------

The **mp_seq** tool provides an interface to generate stressmarks that
execute sequences that combine the instructions provided in a certain 
way to comply the requirements provided.  Sequence stressmarks are loops 
with a particular sequence repeated several times. They are ideal to perform 
core characterizations during the first steps of the maximum power generation
process (i.e. find the sequence that maximizes the power consumption of the
cores). Users can control the level of instruction-level parallelism and the
loop size via configurable parameters.  

-----------
Basic usage
-----------

::

   > mp_seq -T TARGET -D OUTPUT_DIR -ig group1 group2
       
where:

================================================================================================== =================================================================
Flag/Argument                                                                                      Description
================================================================================================== =================================================================
``-ig groups``, ``--instruction-groups groups``                                                    Comma separated list of instruction candidates per
                                                                                                   group. E.g. -ins ins1,ins2 ins3,ins4. Defines two
                                                                                                   groups of instruction candidates: group 1: ins1,ins2
                                                                                                   and group 2: ins3,ins4.
``-T TARGET``, ``--target TARGET``                                                                 Target definition string. Check: :doc:`tools_target_definition`.
``-D OUTPUT_DIR``, ``--seq-output-dir OUTPUTDIR``                                                  Output directory.                              
================================================================================================== =================================================================

There are other parameters to tune the code being generated. Check the 
rest of this document for details. The example section provides a very
detailed use case scenario that uses all the parameters.
    
----------
Full usage
----------

.. program-output:: ../../targets/generic/tools/mp_seq.py --help
 
----------------
Example use case
----------------

This use case is using the **power_v300-power9-ppc64_linux_gcc** target for
illustrative purposes. The same can be done on other targets.  

Let's assume that you have analyzed the ISA of the target and you have selected 
some instruction candidates you want to use for your exploration. For instance 
the following:

- Fix point instructions: ADDI_V0, ORI_V0, AND_V0
- Vector instructions: XVMULDP_V0, XVDIVDP_V0, XVMADDADP_V0
- Load instructions: LD_V0, LDX_V0, LBZ_V0
- Branch instructions: B_V0, BC_V0

Then, you have to decide the instruction sequence length. In this case we pick 6 
because we know that the target machine can commit up to 6 instruction per
cycle. You can increase that number further but the number of combinations
will explode.

To generate all the unique combination of length 6 of the instructions 
above you need to issue the following command:

::

  > mp_seq -T power_v300-power9-ppc64_linux_gcc -p -s -D <output_dir> -is 6 -ig ADDI_V0,ORI_V0,AND_V0 XVMULDP_V0,XVDIVDP_V0,XVMADDADP_V0 LD_V0,LDX_V0,LBZ_V0 B_V0,BC_V0

In the command above, we used the ``-ig`` parameter to specify 4 instruction 
groups (4 groups of comma-separated instructions names). Without any other
restrictions the number of combinations to generate is 1771561. 

It is better to constraint the design space and discard the sequences
that we know that will not be useful for our study. First, let's put some 
maximum to the number of instructions of each group we want 
in the sequence. Let's say that we want a maximum of 3 fix point instructions,
2 vector instructions, 2 load instructions and 1 branch instruction
per sequence.  We can specify that using the following command:

::

  > mp_seq -T power_v300-power9-ppc64_linux_gcc -p -s -D <output_dir> -is 6 -ig ADDI_V0,ORI_V0,AND_V0 XVMULDP_V0,XVDIVDP_V0,XVMADDADP_V0 LD_V0,LDX_V0,LBZ_V0 B_V0,BC_V0 -gM 3 2 2 1

That will reduce the number of combinations to 532170. We used the ``-gM``
parameter to specify a list of maximum instructions per group (``3 2 2 1``). 

Similarly, we can constrain further the design space by specifying that 
we need at least one fixed point, one vector, one load and one branch 
instruction per sequence. We can specify that using the following 
command:

::

  > mp_seq -T power_v300-power9-ppc64_linux_gcc -p -s -D <output_dir> -is 6 -ig ADDI_V0,ORI_V0,AND_V0 XVMULDP_V0,XVDIVDP_V0,XVMADDADP_V0 LD_V0,LDX_V0,LBZ_V0 B_V0,BC_V0 -gM 3 2 2 1 -gm 1 1 1 1

and the number of combinations is reduced to 320760 combinations.
We used the ``-gm`` parameter with to specify of list of maximum instructions 
per group (``1 1 1 1``).
 
Finally, we control further the number of combinations to generate. 
Let's say that we want the branches to be placed at the end of the 
sequence (position 6) and we want the vector instructions to be placed only 
at positions 1 or 4 of the sequence.  We can specify that using the following 
command:

::

  > mp_seq -T power_v300-power9-ppc64_linux_gcc -p -s -D <output_dir> -is 6 -ig ADDI_V0,ORI_V0,AND_V0 XVMULDP_V0,XVDIVDP_V0,XVMADDADP_V0 LD_V0,LDX_V0,LBZ_V0 B_V0,BC_V0 -gM 3 2 2 1 -gm 1 1 1 1 -im 1,2,3 1,3 1,3 1,2,3 1,3 4

We used the ``-im`` parameter to specify a list of the instructions groups 
allowed on each sequence slot (``1,2,3 1,3 1,3 1,2,3 1,3 4``). Notice that 
group 1 (fixed point instruction) is allowed at positions 1,2,3,4,5 ; 
the group 2 (vector instructions) is allowed at positions 1 and 4; and so on.
This instruction mask reduces the number of sequences to 12636.

This example showed you how to constraint the number of combination to your
needs. Notice that we use the ``-p`` flags to generate the microbenchmarks in
parallel, and the ``-s`` flag to skip the benchmarks if they are already 
generated. 

.. note:: 

   One can use the ``-N`` flag to check the sequence definition and the number 
   of sequences that are going to be generated before starting the generation
   process.



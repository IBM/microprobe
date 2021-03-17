==================
Command line tools
==================

Microprobe is a python package providing an API to generate microbenchmarks. 
The best interface to get all the flexibility is to write down your own
python scripts, as explained in the :doc:`tutorial` section.
This allows the control of the entire microbenchmark generation process. 

However, in some scenarios it is desirable to provide command line tools
and text-based input definition files 
--less flexible and tailored for particular goals-- to avoid the need to 
understand Microprobe internals or learn Python. Check the following 
sections for further details:

.. toctree::
   :maxdepth: 1
   
   tools_target_definition
   tools_mpt_format
   tools_ctest_format
   tools_mp_bin2asm
   tools_mp_bin2objdump
   tools_mp_c2mpt
   tools_mp_coblst2mpt
   tools_mp_dma2objdump
   tools_mp_epi
   tools_mp_mpt2test
   tools_mp_objdump2dma
   tools_mp_objdump2mpt
   tools_mp_seq
   tools_mp_seqtune
   tools_mp_target

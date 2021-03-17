========
MPT v0.5
========

=============== ========= ===========================
Section         Type      Description
=============== ========= ===========================
``[MPT]``       Mandatory MPT header
``[CODE]``      Mandatory Code snippet specification
``[REGISTERS]`` Optional  Register initialization
``[DATA]``      Optional  Variable initialization
``[RAW]``       Optional  RAW statements
``[STATE]``     Optional  State specification
``[TRACE]``     Optional  Tracing information
``[DAT]``       Optional  DAT specification
=============== ========= ===========================

-------------------
[REGISTERS] Section
-------------------

.. literalinclude:: ./examples/mpt.mpt
    :lines: 4-13
    
--------------
[DATA] Section
--------------

.. literalinclude:: ./examples/mpt.mpt
    :lines: 14-54

--------------
[CODE] Section
--------------

.. note::
   Notice that the contents of the **'instructions ='** entry are indented. 
   That is, all the instructions, labels or addresses should be specified in an
   indented line. Otherwise, the parser believes that each line is a 
   different entry.

.. literalinclude:: ./examples/mpt.mpt
    :lines: 54-107

.. note::
   Notice that the contents of the **'instructions ='** entry are indented. 
   That is, all the instructions, labels or addresses should be specified in an
   indented line. Otherwise, the parser believes that each line is a 
   different entry.

-------------
[RAW] Section
-------------

.. literalinclude:: ./examples/mpt.mpt
    :lines: 109-129
    
-------------
[DAT] Section
-------------
    
In general, microbenchmarks generated do not need to be aware of the
Dynamic Address Translation (DAT) as they typically are targeted
to generate addresses within their own logical address space. 
However, some backends support the generation of Dynamic Address 
Translation aware microbenchmarks. In such backends, the user can 
specify the address translation mappings. Check the example below::

    [DAT] ; Dynamic address translation

    # Translation mappings. One can specify manually the translation mappings, and the
    # instruction addresses will be generated accordingly. Whenever the instruction
    # address matches one of the mappings, it is translated accordingly.
    # Format is:  address, mapping_address, mask
    # e.g.: trans_map = [ (0x0123456700123000, 0x00000DFA76590000, 0xfffffffffffff000 ),
    #                     (0x0123456700124000, 0x00000DFA765A0000, 0xfffffffffffff000 ),
    #                     ... ] 

    dat_map = [ (0x0123456700123000, 0x00000DFA76590000, 0xfffffffffffff000 ) ]

    #
    # This entry will be automatically appended to the generated testcase. It is treated
    # like the code_footer entry in the [RAW] section
    #

    dat_raw = 
        * -------- DAT RAW ENTRY ----------------
        any code/set up required to generated the 
        expected DAT mappings
        * -------- DAT RAW ENTRY ----------------

Example code using DAT-related decorations to control when the dynamic
address translation mechanisms is used or not::

    [CODE] ; Section to specify the code

    default_address = 0x123456700123000

    instructions =           
        @ DAT=On                    ; Enable DAT 
        brc 0, 0x0                  ; At address: 0x123456700123000 --> 0x00000DFA76590000
        lpswe 0x0(2)                ; At address: 0x123456700123004 --> 0x00000DFA76590004
        @ DAT=Off                   ; Disable DAT 
      0x000000000123000:            ; New address
        ptlb                        ; At address: 0x0000000000123000 (no translation)
        lpswe 0x0(1)                ; At address: 0x0000000000123004 (no translation)       
        @ DAT=On                    ; Enable DAT 
      0x123456700123008:            ; New address
        brc 0, 0x0                  ; At address: 0x123456700123008 --> 0x00000DFA76590008
        brc 0, 0x0                  ; At address: 0x12345670012300C --> 0x00000DFA7659000C
        brc 0, 0x0                  ; At address: 0x123456700123010 --> 0x00000DFA76590010
        brc 15, 0x0                 ; At address: 0x123456700123014 --> 0x00000DFA76590014

---------------
[STATE] Section
---------------

The state section is used to define the initial state of the microbenchmark. 
Currently, it only has one entry::

  [STATE]
  contents = <path_to_state_file>

State files are text files where each line follows the following format:

  - a line starting by M, then an address and its contents separated by a single space (to specify memory contents)
  - a line starting by 'R', then the register name and then the value (to specify the reg. contents)

Example::

    M 0x012345677 01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF
    M 0x012345677 01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF
    ...
    M 0x012345677 01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF
    M 0x012345677 01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF01234567890ABCDEF
    ...
    R GR0 0x0123456789ABC
    R GR1 0x0123456789ABC
    R GR2 0x0123456789ABC
    ...
    R GR31 0x0123456789ABC

Clarifications on the format:

  - Register entries can appear at any point. 
  - Register entries do not need to be sorted. 
  - Register entries can have duplicates. The last value of seen 
    for a register will be used. A warning will be generated. 
  - Register values provided in ``[REGISTERS]`` section will take preference
    over registers values specified in the state file.
  - Memory entries can appear at any point but they should be sorted by memory 
    access order (the actual access order generated by the program). This information
    about order might be eventually used by Microprobe to implement different 
    data warm-up schemes. 
  - Size of memory contents is automatically inferred from the content string
    length.  
  - For readability, it is preferred to dump first the registers and then 
    the memory entries in program access order.
    
---------------
[TRACE] Section
---------------

MPTs can be generated from simulation/execution traces. Also, traces can be generated
from a given MPT. The trace section is used to define trace related information
such as the number of instructions/cycles executed/simulated or the information
(start/end) in cycles or instructions of the region of interest (ROI) to be
traced. Currently, this section supports the following entries::

  [TRACE]

  roi_start_instruction = <integer>     ; Start dynamic instruction of the region of interest
  roi_end_instruction = <integer>       ; End dynamic instruction of the region of interest
  roi_start_cycle = <integer>           ; Start cycle of the region of interest
  roi_end_cycle = <integer>             ; End cycle of the region of interest
  instruction_count = <integer>         ; Number of dynamic instructions readed/to_generate
  cycle_count = <integer>               ; Number of cycles processed in the source trace
  roi_memory_access_trace = <path_to_trace_file> ; Path to trace file containing the memory
                                                 ; access trace of the test cases.

Memory access trace files are text files where each line describes a memory access in
progrem execution order. Each line contains the following four fields separated by 
a space:

  - Type of data: data (D) or code (I) 
  - Type of access: read/load (R) or write/store (W)
  - Address in hexadecimal format (0x ....)
  - Length in bytes in decimal format

Lines can also include comments after the ';' character. Example::

    I R 0x0000000100001000 4 ; Code read of 4 bytes at address 0x100001000
    I R 0x0000000100001004 4 ; Code read of 4 bytes at address 0x100001004
    I R 0x0000000100001008 4 ; Code read of 4 bytes at address 0x100001008
    D R 0x0000000101000000 8 ; Data read of 8 bytes at address 0x101000000
    D W 0x0000000101000008 8 ; Data write of 8 bytes at address 0x101000008
    
----------------
Complete example
----------------
 
.. literalinclude:: ./examples/mpt.mpt
    :linenos:

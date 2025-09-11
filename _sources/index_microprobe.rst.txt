==========
Microprobe
==========

Microprobe is a **productive** microbenchmark generation framework that an user 
can **adapt** towards exercising a complex multi-core, multi-threaded computing
system in a variety of redundant ways for answering a range of questions 
related to energy and performance. 

The growth in complexity of microprocessor systems today --composed of 
multi-core, multi-threaded processors with multi-level cache hierarchies and 
giga-bytes of memory--, hardens the pre-silicon system modeling and the 
post-silicon system characterizations. We believe that microbenchmarks, 
generated with particular objectives in mind, hold the key to obtaining 
accurate characterizations of microprocessor systems. Specially crafted 
microbenchmarks may be run on simulators (pre-silicon stage) or real machines 
(post-silicon stage) to help understand, diagnose and fix deficiencies 
systematically. However, manual generation of such "stress-marks" is tedious, 
and requires intimate knowledge of the underlying microarchitecture pipeline 
semantics. Automated microbenchmark generation is therefore crucial in this 
regard. Microprobe is developed to fulfill that need.

------------
Key features
------------

The automated generation facility must maximize the productivity 
of the end-user, allowing the generation of different classes of 
microbenchmarks that are useful in answering a range of different 
(*unknown*/*future*) questions.  Therefore, we develop Microprobe with the 
following features in mind:

* **Adaptive and flexible**. We design the microbenchmark 
  synthesizer of Microprobe to work in a compiler-like fashion, i.e.
  applying a set of passes to a internal representation of the 
  microbenchmark. This allows the users to adapt the
  microbenchmark generation process to their needs,
  providing the flexibility and the extensibility required.

* **Microarchitecture semantics aware**. Microprobe includes
  low-level information of the target microarchitectures.
  This information is crucial to assist the generation of 
  microarchitecture aware microbenchmarks, allowing the definition
  of microbenchmark generation policies based on them.
  It provides a *white-box* solution to the users to define microbenchmarks 
  with very specific microarchitecture properties, avoiding the need to 
  master every detail of the complex underlying architectures.

* **Integrated design space exploration (DSE)**. Design space explorations 
  have become mandatory to understand the performance of computer architectures 
  due to their increase in complexity. In addition, DSE are required to 
  find microbenchmarks that fulfill a set of dynamic properties that cannot be
  ensured statically (during code generation). DSE support is therefore a basic 
  functionality that any productive microbenchmark generation framework 
  should have. Microprobe provides generic DSE support to be able to implement 
  different  customizable search strategies within the design space defined 
  by the user (*feature not yet released*)

* **Minimize tool-chain dependencies**. Microbenchmarks are required
  during early stage of processor designs or even during design concept
  phases, where new ISA proposals are evaluated. At these
  stages of development, compiler tool-chains are typically not ready. This
  reason, in conjunction with the fact that existing product-level tool-chains
  are much more complex, makes the generation of microbenchmarks in early-stage
  design phases a tedious task. 
  For this reason, Microprobe avoids having dependencies on existing
  tool-chains so that users can quickly add/modify instruction definitions 
  and generate microbenchmarks using them.

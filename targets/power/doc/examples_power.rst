=================
Examples on POWER
=================

In the ``definitions/power/examples`` directory of the **Microprobe** distribution
(if you installed the **microprobe_target_power** package),
you will find different examples showing the usage of **Microprobe**
for the power architecture. Although we have split the examples by 
architecture, the concepts we introduce in these examples are common in all 
the architectures.

We recommend users to go through the code of these examples to understand
specific details on how to use the framework. 

**Contents**:

- `isa_power_v206_info.py`_
- `power_v206_power7_ppc64_linux_gcc_profile.py`_
- `power_v206_power7_ppc64_linux_gcc_fu_stress.py`_
- `power_v206_power7_ppc64_linux_gcc_memory.py`_
- `power_v206_power7_ppc64_linux_gcc_random.py`_
- `power_v206_power7_ppc64_linux_gcc_custom.py`_
- `power_v206_power7_ppc64_linux_gcc_genetic.py`_


----------------------
isa_power_v206_info.py
----------------------

The first example we show is ``isa_power_v206_info.py``. This example 
shows how to search for architecture definitions (e.g. the ISA properties),
how to import the definitions and then how to dump the definition. 
If you execute the following command::

   > ./isa_power_v206_info.py

will generate the following output, which shows all the details of the 
**POWER v2.06** architecture (first and last 20 lines for brevity):

.. program-output:: ../../targets/power/examples/isa_power_v206_info.py
    :ellipsis: 20,-20

The following code is what has been executed:

.. literalinclude:: ../../targets/power/examples/isa_power_v206_info.py
    :linenos:
    :language: python

In this simple code, first the ``find_isa_definitions``, 
``import_isa_definition`` from the **microprobe.target.isa** module
are imported (line 14). Then, the first one is used to look for definitions of
architectures, a list returned and filtered and only the one with
name ``power_v206`` is imported using the second method: 
``import_isa_definition`` (lines 34-37). Finally, the full report of
the ``ISADEF`` object is printed to standard output in line 40. 

In the case, the full report is printed but the user can query any
information about the particular ISA that has been imported by using the 
:class:`microprobe.target.isa.ISA` API. 

--------------------------------------------
power_v206_power7_ppc64_linux_gcc_profile.py
--------------------------------------------

The aim of this example is to show how the code generation works in 
**Microprobe**. In particular, this example shows how to generate, 
for each instruction of the ISA, an endless loop containing such instruction. 
The size of the loop and the dependency distance between the instructions 
of the loop can specified as a parameter. Using **Microprobe** you can generate
thousands of microbenchmarks in few minutes. Let's start with 
the command line interface. Executing::

   > ./power_v206_power7_ppc64_linux_gcc_profile.py --help

will generate the following output:

.. program-output:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_profile.py --help

Lets look at the code to see how this command line tool is implemented.
This is the complete code of the script:

.. literalinclude:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_profile.py
    :linenos:
    :language: python

The code is self-documented. You can take a look to understand the basic 
concepts of the code generation in **Microprobe**. In order to help the 
readers, let us summarize and elaborate the explanations in the code. The 
following are the **suggested** steps required to implement 
a command line tool to generate microbenchmarks using **Microprobe**:

1. Define the command line interface and parameters (``main_setup()`` 
   function in the example). This includes:
   
   A. Create a command line interface object 
   
   #. Define parameters using the ``add_option`` interface 
   
   #. Call the actual main with the arguments 

#. Define the function to process the input parameters (``_main()`` function
   in the example). This includes:
   
   A. Import target definition
   
   #. Get processed arguments 
   
   #. Validate and use the arguments to call the actual microbenchmark 
      generation function 
      
#. Define the function to generate the microbenchmark (``_generate_benchmark``
   function in the example). The main elements are the following:
      
   A. Get the wrapper object. The wrapper object defines
      the general characteristics of code being generated (i.e. how the
      internal representation will be translated to the final file 
      being generated). General characteristics are, for instance, code prologs 
      such as ``#include <header.h>`` directives, the main
      function declaration, epilogs, etc.  In this case, the wrapper selected
      is the ``CInfGen``. This wrapper generates C code 
      with an infinite loop of instructions. This results in
      the following code:

      .. code-block:: c
         :emphasize-lines: 4,8,12

         #include <stdio.h>
         #include <string.h>

         // <declaration of variables>

         int main(int argc, char** argv, char** envp) {

             // <initialization_code>

             while(1) {

                 // <generated_code>

             } // end while
         }

      The user can subclass or define their own wrappers
      to fulfill their needs. See :class:`microprobe.code.wrapper.Wrapper` 
      for more details.

   #. Instantiate synthesizer. The benchmark synthesizer 
      object is in charge of driving the code generation object by applying 
      the set of transformation passes defined by the user.

   #. Define the transformation passes. The 
      transformation passes will fill the ``declaration of variables``, 
      ``<initialization_code>`` and ``<generated_code>`` sections of the 
      previous code block. Depending on 
      the  order and the type of passes applied, the code generated will be 
      different. The user has plenty of transformation passes to apply. 
      See :mod:`microprobe.passes` and all its submodules 
      for further details. Also, the use can define its own passes by
      subclassing the class :class:`microprobe.passes.Pass`.

   #. Finally, once the generation policy is defined, the user only has to 
      synthesize the benchmark and save it to a file.

----------------------------------------------
power_v206_power7_ppc64_linux_gcc_fu_stress.py
----------------------------------------------

The following example shows how to generate microbenchmarks that stress 
a particular functional unit of the architecture. The code is self explanatory:

.. literalinclude:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_fu_stress.py
    :linenos:
    :language: python

-------------------------------------------
power_v206_power7_ppc64_linux_gcc_memory.py
-------------------------------------------

The following example shows how to create microbenchmarks with different 
activity (stress levels) on the different levels of the cache hierarchy.
Note that it is not necessary to use the built-in command line interface 
provided by Microprobe, as the example shows.

.. literalinclude:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_memory.py
    :linenos:
    :language: python

-------------------------------------------
power_v206_power7_ppc64_linux_gcc_random.py
-------------------------------------------

The following example generates random microbenchmarks:

.. literalinclude:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_random.py
    :linenos:
    :language: python
    
-------------------------------------------
power_v206_power7_ppc64_linux_gcc_custom.py
-------------------------------------------

The following example shows different examples on how to customize
the generation of microbenchmarks:

.. literalinclude:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_custom.py
    :linenos:
    :language: python

--------------------------------------------
power_v206_power7_ppc64_linux_gcc_genetic.py
--------------------------------------------

.. deprecated:: 0.5
    Support for the PyEvolve and genetic algorithm based searches has
    been discontinued

The following example shows how to use the design exploration module and the 
genetic algorithm based searches to look for a solution. 
In particular, for each functional unit of the architecture 
and a range of IPCs (instruction per cycle), 
the example looks for a solution that stresses that functional unit at the
given IPC. External commands (*not included*) are needed to evaluate the 
generated microbenchmarks in the target platform. 

.. literalinclude:: ../../targets/power/examples/power_v206_power7_ppc64_linux_gcc_genetic.py
    :linenos:
    :language: python

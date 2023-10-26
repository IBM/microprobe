=============
C test format
=============

--------
Overview
--------

In order to facilitate the task of specifying tests to be reproduced/generated
by Microprobe, we defined a C code environment so that the users can write
down the test cases in C, and then let the compiler and the Microprobe 
framework to perform the code generation and all the *plumbing* required to
make it work. 

In brief, besides the actual implementation of the test 
case main function (named **c2mpt_function**), the user has to define a set 
of C macros so that the framework knows which variables and functions should 
also be included in the generated MPT. Optionally, the user can also 
define an initialization function, which will be called
before the test case main function, to initialize the data values. 
The following sections explain more details about this environment.

-------------------------------------
Variable declaration and registration
-------------------------------------

The variables have to be declared and registered using a set of macros 
provided by the C test environment (defined in ``c2mpt.h`` file shown below). 
This allows the environment to know which variables are required to be part of
the generated MPT. 

The following macros are defined to declare variables:

- ``DECLARE_VARIABLE(type, name, alignment)``
- ``DECLARE_VARIABLE_WITH_VALUE(type, name, alignment, init_value)``
- ``DECLARE_VARIABLE_ARRAY(type, name, name+dimension, alignment)``
- ``DECLARE_VARIABLE_ARRAY_WITH_VALUE(type, name, name+dimension alignment, init_value)``

where:

- **type**: is the variable type (e.g. char) 
- **name**: is the variable name (e.g. myvar)
- **name+dimension**: is the name of the array and the dimensions of the array 
  (e.g. myvar[10][20] )
- **alignment**: is the minimum alignment for the variable                 
- **init_value**: is the initial value

The following macros are defined to register the variables:

- ``BEGIN_VARIABLE_REGISTRATION``
- ``REGISTER_VARIABLE(name)``
- ``END_VARIABLE_REGISTRATION``

where:

- **name**: is the variable name to register

---------------------
Function registration
---------------------

Besides the variables, the functions that need to be placed in the generated
MPT also have to be declared using special macros. Instead of using regular
``fname(type1 arg1, type2 arg2,  ...  , type3 arg3)`` function signature 
declarations, the declarations should of the form  ``MPT_FUNCTION(fname(type1 
arg1, type2 arg2,  ...  , type3 arg3))``. That is, just wrap the function 
signatures using the ``MPT_FUNCTION`` macro.

-----------------------
Function implementation
-----------------------

After defining how to declare variables and define function signatures,
one needs to provide the implementation of the following function:

- ``void c2mpt_function()`` : This is the main test function, which will be
  converted to the MPT format. This function can not perform library calls and
  it only should access to local variables (that will be placed in the stack)
  or global MPT register variables. 
- ``void c2mpt_init_global_vars()`` (optional): Use this function to initialize any 
  global variables registered to the MPT. This function, since it is not
  going to be included in the generate MPT, can call any other functions and
  does not have any restriction. 
- Any other subroutine called by the **c2mpt_function**. Again, these 
  subroutines, like the **c2mpt_function** can not perform library calls or 
  access to global variables not registered in the MPT environment. 

--------
Examples
--------

A matrix multiply example:

.. literalinclude:: ../../targets/generic/tests/tools/c2mpt_mm.c
    :linenos:
    :language: c

A linked list code example:

.. literalinclude:: ../../targets/generic/tests/tools/c2mpt_ll.c
    :linenos:
    :language: c

--------
Template
--------

Copy and paste the following template (or use the ``--dump-c2mpt-template`` 
flag to get it) to start editing an empty C test format: 

.. literalinclude:: ../../targets/generic/templates/c2mpt_template.c
    :linenos:
    :language: c
    
----------------------
Implementation details
----------------------

The following two files are compiled along the C test file provided as input
by the user. Check them to understand the implementation details in case you 
want to debug the functionality:

.. literalinclude:: ../../targets/generic/templates/c2mpt.h
    :linenos:
    :language: c

.. literalinclude:: ../../targets/generic/templates/c2mpt.c
    :linenos:
    :language: c

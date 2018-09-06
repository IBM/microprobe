#include "c2mpt.h"

/****************************************************************************/
// Global variables
//
// Define in the section below the global variable to be used in the 
// "c2mpt_function" and its subroutines. Variables below are going to be
// imported to the mpt format. The variables have to be declared first
// and then they have to be registered (see example below).
//
// The following macros are defined to declare variables:
//
// DECLARE_VARIABLE(type, name, alignment)
// DECLARE_VARIABLE_WITH_VALUE(type, name, alignment, init_value)
// DECLARE_VARIABLE_ARRAY(type, name, name+dimension, alignment)
// DECLARE_VARIABLE_ARRAY_WITH_VALUE(type, name, name+dimension alignment, init_value)
//
// where:
//
// - type: is the variable type (e.g. char)
// - name: is the variable name (e.g. myvar)
// - name+dimension: is the name of the array and the dimensions of the array 
//                   (e.g. myvar[10][20] )
// - alignment: is the minimum algnment for the variable                 
// - init_value: is the initial value
//
// The following macros are defined to register the variables:
//
// BEGIN_VARIABLE_REGISTRATION
// REGISTER_VARIABLE(name)
// END_VARIABLE_REGISTRATION
//
// where:
//
// - name: is the variable name to register
//
// Example:
//
// #define N 10
//
// DECLARE_VARIABLE_ARRAY(int64_t,matA,matA[N][N],sizeof(int64_t))
// DECLARE_VARIABLE_ARRAY(int64_t,matB,matB[N][N],sizeof(int64_t))
// DECLARE_VARIABLE_ARRAY_WITH_VALUE(int64_t,matC,matC[N][N],sizeof(int64_t),
//                                   {[0][1]=2,[1][0]=1} )
//
// BEGIN_VARIABLE_REGISTRATION
// REGISTER_VARIABLE(matA)
// REGISTER_VARIABLE(matB)
// REGISTER_VARIABLE(matC)
// END_VARIABLE_REGISTRATION
//
/****************************************************************************/

<< DECLARE AND REGISTER YOUR VARIABLES HERE >>

/****************************************************************************/
// Subroutine declaration 
//
// Declare any subroutine to be included in the MPT generated using the 
// MPT_FUNCTION(signature) macro provided.
//
// Example:
//
// MPT_FUNCTION(int64_t my_subroutine(int64_t X, int64_t Y, int64_t Z))
//
/****************************************************************************/

<< DECLARE YOUR SUBROUTINES HERE >>

/****************************************************************************/
// Function implementation
//
// Include below the implementation of the routines defined above, which
// will be included in the MPT. They should not call functions that will not 
// be included in the MPT. That is, only call functions declared using the 
// MPT_FUNCTION macro.
//
// Remember to implement the "c2mpt_function", which will be the main test
// function.
//
/****************************************************************************/

void c2mpt_function()
{

    << IMPLEMENT THE MAIN FUNCTION HERE >>

}

<< IMPLEMENT ANY SUBROUTINES HERE >>

/****************************************************************************/
// Initialization function 
//
// In case you need to initialize the global variables, you can do that in
// the function below. This function can use any external function
// including IO (e.g. reading values from disk) . This function will not
// be included the MPT generated.
//
// If you initialize variable pointers, they should point to addresses of 
// variables defined to be included in the MPT.
// 
/****************************************************************************/

void c2mpt_init_global_vars()
{ 

    << INITIALIZE THE GLOBAL VARIABLES HERE >>
    
}


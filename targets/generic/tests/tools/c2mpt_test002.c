#include "c2mpt.h"

/****************************************************************************/
// Global variables
//
// Define in the section below the global variable to be used in the 
// "c2mpt_function" and its subroutines. Variable below are going to be
// imported to the mpt format. The variables have to be declared first
// and then, they have to be registered (see example below).
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
/****************************************************************************/

#define N 10

DECLARE_VARIABLE_ARRAY(int64_t,matA,matA[N][N],sizeof(int64_t))
DECLARE_VARIABLE_ARRAY(int64_t,matB,matB[N][N],sizeof(int64_t))
DECLARE_VARIABLE_ARRAY_WITH_VALUE(int64_t,matC,matC[N][N],sizeof(int64_t), {[0][1]=2,[1][0]=1} )

BEGIN_VARIABLE_REGISTRATION
REGISTER_VARIABLE(matA)
REGISTER_VARIABLE(matB)
REGISTER_VARIABLE(matC)
END_VARIABLE_REGISTRATION

/****************************************************************************/
// Function declaration 
//
// Declare the functions to be converted to the MPT format. It is mandatory 
// to define a "c2mpt_function", which will be the "main" of the test. Also
// include any related subroutines. The related subroutines have to be
// defined using the MPT_FUNCTION(signature) macro provided.
//
// The function signature for the main c2mpt_function should not be modified.
// It does not have any parameter. One can use global variables to pass parameters
// to the function (see the example).
//
/****************************************************************************/

MPT_FUNCTION(int64_t my_subroutine(int64_t X, int64_t Y, int64_t Z))

/****************************************************************************/
// Function implementation
//
// Include below the implementation of the routines defined above, which
// should be included in the mpt. They should not call functions not defined 
// here because the test should be self-contained to be reproduced safely.
//
// Remember to defined the "c2mpt_function" main function.
//
/****************************************************************************/

int64_t __attribute__ ((noinline)) my_subroutine(int64_t X, int64_t Y, int64_t Z)
{
    return Z + (X * Y);
}

void c2mpt_function()
{
    int i,j,k;

    for(i=0;i<N;i++){
        for(j=0;j<N;j++){
            matC[i][j]=0;
            for(k=0;k<N;k++){
                matC[i][j]=my_subroutine(matA[i][k], matB[k][j], matC[i][j]);
            }
        }
    }
}


/****************************************************************************/
// Initialization function 
//
// In case you need to initialize the global variables, you can do that in
// the function below. This function can use any external function
// including IO (e.g. reading values from disk) . This function will not
// be included the mpt.
//
// If you initialize variable pointers, they should point to addresses of 
// variables defined to be included in the MPT.
// 
/****************************************************************************/

void c2mpt_init_global_vars()
{ 
    for(int i=0; i < N; i++){
        for(int j=0; j < N; j++){
            matA[i][j] = i;
            matB[i][j] = j;
            matC[i][j] = i+j;
        }
    }
}


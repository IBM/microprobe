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

#define N 5

struct node {
      int64_t x;
      struct node *next;
};

typedef struct node node_t;
node_t array[N];

DECLARE_VARIABLE_ARRAY(node_t,linkedlist,linkedlist[N],sizeof(node_t))
DECLARE_VARIABLE_WITH_VALUE(int64_t,count,sizeof(int64_t), 0xCAFECAFE)

BEGIN_VARIABLE_REGISTRATION
REGISTER_VARIABLE(count)
REGISTER_VARIABLE(linkedlist)
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

MPT_FUNCTION(void my_subroutine(int64_t count))

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

void c2mpt_function()
{

    node_t* node = & linkedlist[0];
    while(node->next != NULL)
    {
        node = node->next;
        count += node->x;
    }

    my_subroutine(count);

}

void my_subroutine(int64_t lcount)
{
    count=lcount+lcount;
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
        linkedlist[i].x = 0x0102030405060708;
       
        if(i<N-1)
        {
            linkedlist[i].next = &(linkedlist[i+1]);
        }
        else
        {
            linkedlist[i].next = NULL;
        }
    }
}


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <strings.h>
#include <string.h>
#include <assert.h>

typedef struct c2mpt_var {           
    char vartype[50];        
    char varname[50];       
    void * address;                
    uint_fast64_t nelems;         
    uint_fast64_t elems_size;    
    uint_fast64_t alignment;    
} c2mpt_var ;                  

void c2mpt_dump_data(void);

#define DECLARE_VARIABLE_ARRAY(type,name,array,alignment)                      \
    type array                                                                 \
        __attribute__ ((section ("microprobe.data")))                          \
        __attribute__ ((aligned (alignment)))                                  \
    ;                                                                          \
    c2mpt_var c2mpt_var_##name = { #type, #name,                               \
                                 (void * ) & name[0],                          \
                                        sizeof(name)/                          \
                                     sizeof(type),                             \
                                          alignment }; 

#define DECLARE_VARIABLE_ARRAY_WITH_VALUE(type,name,array,alignment, ...)      \
    type array                                                                 \
        __attribute__ ((section ("microprobe.data")))                          \
        __attribute__ ((aligned (alignment)))                                  \
    = __VA_ARGS__;                                                             \
    c2mpt_var c2mpt_var_##name = { #type, #name,                               \
                                 (void * ) & name[0],                          \
                                        sizeof(name)/                          \
                                     sizeof(type),                             \
                                          alignment }; 

#define DECLARE_VARIABLE(type,name,alignment)                                  \
    type name                                                                  \
        __attribute__ ((section ("microprobe.data")))                          \
        __attribute__ ((aligned (alignment)))                                  \
    ;                                                                          \
    c2mpt_var c2mpt_var_##name = { #type, #name,                               \
                                 (void * ) & name, 1,                          \
                                         sizeof(name),                         \
                                          alignment }; 

#define DECLARE_VARIABLE_WITH_VALUE(type,name,alignment, value)                \
    type name                                                                  \
        __attribute__ ((section ("microprobe.data")))                          \
        __attribute__ ((aligned (alignment)))                                  \
    = value;                                                                   \
    c2mpt_var c2mpt_var_##name = { #type, #name,                               \
                                 (void * ) & name, 1,                          \
                                         sizeof(name),                         \
                                          alignment }; 

#define BEGIN_VARIABLE_REGISTRATION                                            \
    c2mpt_var* c2mpt_vars[] = {                        

#define REGISTER_VARIABLE(name) &c2mpt_var_##name,
        
#define END_VARIABLE_REGISTRATION                                              \
    };                                                                         \
    extern void c2mpt_dump_var(c2mpt_var var);                                 \
    MPT_DUMP_FUNCTION 
    
#define MPT_FUNCTION(signature)                                                \
    signature                                                                  \
    __attribute__ ((section ("microprobe.text")));

MPT_FUNCTION(void c2mpt_function(void))

#define MPT_DUMP_FUNCTION                                                      \
    void c2mpt_dump_data(void)                                                 \
    {                                                                          \
        uint_fast64_t i = 0;                                                   \
        uint_fast64_t nvars = 0;                                               \
        nvars = sizeof(c2mpt_vars) / sizeof(c2mpt_vars[0]);                    \
        for(i=0; i < nvars; i++)                                               \
        {                                                                      \
            c2mpt_dump_var(*(c2mpt_vars[i]));                                  \
        }                                                                      \
    }                                                                          \

#ifndef MPT_BASE_ADDRESS
    #define MPT_BASE_ADDRESS 0x0
#endif

#include "c2mpt.h"

extern c2mpt_var* c2mpt_vars; 
extern void c2mpt_function(void);
extern void c2mpt_dump_data(void);
extern void c2mpt_init_global_vars(void);

/****************************************************************************/
// Dump data functions
/****************************************************************************/

void c2mpt_print_value(void * value, uint_fast64_t size, char* vartype)
{
    // pointers
    if(index(vartype, '*') != NULL)
    {
        assert(size == sizeof(void *));
        printf("%p", value);
    }
    // C generic data types
    else if(strcasecmp(vartype, "char") == 0)
    {
        assert(size == sizeof(char));
        printf("%hhu", *((char *) value));
    }
    else if(strcasecmp(vartype, "signed char") == 0)
    {
        assert(size == sizeof(signed char));
        printf("%hhi", *((signed char *) value));
    }
    else if(strcasecmp(vartype, "unsigned char") == 0)
    {
        assert(size == sizeof(unsigned char));
        printf("%hhu", *((unsigned char *) value));
    }
    else if(strcasecmp(vartype, "short") == 0)
    {
        assert(size == sizeof(short));
        printf("%hi", *((short *) value));
    }
    else if(strcasecmp(vartype, "short int") == 0)
    {
        assert(size == sizeof(short int));
        printf("%hi", *((short int *) value));
    }
    else if(strcasecmp(vartype, "signed short") == 0)
    {
        assert(size == sizeof(signed short));
        printf("%hi", *((signed short *) value));
    }
    else if(strcasecmp(vartype, "signed short int") == 0)
    {
        assert(size == sizeof(signed short int));
        printf("%hi", *((signed short int *) value));
    }
    else if(strcasecmp(vartype, "unsigned short") == 0)
    {
        assert(size == sizeof(unsigned short));
        printf("%hu", *((unsigned short *) value));
    }
    else if(strcasecmp(vartype, "unsigned short int") == 0)
    {
        assert(size == sizeof(unsigned short int));
        printf("%hu", *((unsigned short int *) value));
    }
    else if(strcasecmp(vartype, "int") == 0)
    {
        assert(size == sizeof(int));
        printf("%d", *((int *) value));
    }
    else if(strcasecmp(vartype, "signed") == 0)
    {
        assert(size == sizeof(signed));
        printf("%d", *((signed *) value));
    }
    else if(strcasecmp(vartype, "signed int") == 0)
    {
        assert(size == sizeof(signed int));
        printf("%d", *((signed int *) value));
    }
    else if(strcasecmp(vartype, "unsigned") == 0)
    {
        assert(size == sizeof(unsigned));
        printf("%u", *((unsigned *) value));
    }
    else if(strcasecmp(vartype, "unsigned int") == 0)
    {
        assert(size == sizeof(unsigned int));
        printf("%u", *((unsigned int *) value));
    }
    else if(strcasecmp(vartype, "long") == 0)
    {
        assert(size == sizeof(long));
        printf("%li", *((long *) value));
    }
    else if(strcasecmp(vartype, "long int") == 0)
    {
        assert(size == sizeof(long int));
        printf("%li", *((long int *) value));
    }
    else if(strcasecmp(vartype, "signed long") == 0)
    {
        assert(size == sizeof(signed long));
        printf("%li", *((signed long *) value));
    }
    else if(strcasecmp(vartype, "signed long int") == 0)
    {
        assert(size == sizeof(signed long int));
        printf("%li", *((signed long int *) value));
    }
    else if(strcasecmp(vartype, "unsigned long") == 0)
    {
        assert(size == sizeof(unsigned long));
        printf("%lu", *((unsigned long *) value));
    }
    else if(strcasecmp(vartype, "unsigned long int") == 0)
    {
        assert(size == sizeof(unsigned long int));
        printf("%lu", *((unsigned long int *) value));
    }
    else if(strcasecmp(vartype, "long long") == 0)
    {
        assert(size == sizeof(long long));
        printf("%lli", *((long long *) value));
    }
    else if(strcasecmp(vartype, "long long int") == 0)
    {
        assert(size == sizeof(long long int));
        printf("%lli", *((long long int *) value));
    }
    else if(strcasecmp(vartype, "signed long long") == 0)
    {
        assert(size == sizeof(signed long long));
        printf("%lli", *((signed long long *) value));
    }
    else if(strcasecmp(vartype, "signed long long int") == 0)
    {
        assert(size == sizeof(signed long long int));
        printf("%lli", *((signed long long int *) value));
    }
    else if(strcasecmp(vartype, "float") == 0)
    {
        assert(size == sizeof(float));
        printf("%f", *((float *) value));
    }
    else if(strcasecmp(vartype, "double") == 0)
    {
        assert(size == sizeof(double));
        printf("%f", *((double *) value));
    }
    else if(strcasecmp(vartype, "long double") == 0)
    {
        assert(size == sizeof(long double));
        printf("%Lf", *((long double *) value));
    }
    // C width fixed data types
    else if(strcasecmp(vartype, "int8_t") == 0)
    {
        assert(size == sizeof(int8_t));
        printf("%hhi", *((int8_t *) value));
    }
    else if(strcasecmp(vartype, "int_least8_t") == 0)
    {
        assert(size == sizeof(int_least8_t));
        printf("%"PRIdLEAST8, *((int_least8_t *) value));
    }
    else if(strcasecmp(vartype, "int_fast8_t") == 0)
    {
        assert(size == sizeof(int_fast8_t));
        printf("%"PRIdFAST8, *((int_fast8_t *) value));
    }
    else if(strcasecmp(vartype, "uint8_t") == 0)
    {
        assert(size == sizeof(uint8_t));
        printf("%hhu", *((uint8_t *) value));
    }
    else if(strcasecmp(vartype, "uint_least8_t") == 0)
    {
        assert(size == sizeof(uint_least8_t));
        printf("%"PRIuLEAST8, *((uint_least8_t *) value));
    }
    else if(strcasecmp(vartype, "uint_fast8_t") == 0)
    {
        assert(size == sizeof(uint_fast8_t));
        printf("%"PRIuFAST8, *((uint_fast8_t *) value));
    }
    else if(strcasecmp(vartype, "int16_t") == 0)
    {
        assert(size == sizeof(int16_t));
        printf("%hi", *((int16_t *) value));
    }
    else if(strcasecmp(vartype, "int_least16_t") == 0)
    {
        assert(size == sizeof(int_least16_t));
        printf("%"PRIdLEAST16, *((int_least16_t *) value));
    }
    else if(strcasecmp(vartype, "int_fast16_t") == 0)
    {
        assert(size == sizeof(int_fast16_t));
        printf("%"PRIdFAST16, *((int_fast16_t *) value));
    }
    else if(strcasecmp(vartype, "uint16_t") == 0)
    {
        assert(size == sizeof(uint16_t));
        printf("%hu", *((uint16_t *) value));
    }
    else if(strcasecmp(vartype, "uint_least16_t") == 0)
    {
        assert(size == sizeof(uint_least16_t));
        printf("%"PRIuLEAST16, *((uint_least16_t *) value));
    }
    else if(strcasecmp(vartype, "uint_fast16_t") == 0)
    {
        assert(size == sizeof(uint_fast16_t));
        printf("%"PRIuFAST16, *((uint_fast16_t *) value));
    }
    else if(strcasecmp(vartype, "int32_t") == 0)
    {
        assert(size == sizeof(int32_t));
        printf("%d", *((int32_t *) value));
    }
    else if(strcasecmp(vartype, "int_least32_t") == 0)
    {
        assert(size == sizeof(int_least32_t));
        printf("%"PRIdLEAST32, *((int_least32_t *) value));
    }
    else if(strcasecmp(vartype, "int_fast32_t") == 0)
    {
        assert(size == sizeof(int_fast32_t));
        printf("%"PRIdFAST32, *((int_fast32_t *) value));
    }
    else if(strcasecmp(vartype, "uint32_t") == 0)
    {
        assert(size == sizeof(uint32_t));
        printf("%u", *((uint32_t *) value));
    }
    else if(strcasecmp(vartype, "uint_least32_t") == 0)
    {
        assert(size == sizeof(uint_least32_t));
        printf("%"PRIuLEAST32, *((uint_least32_t *) value));
    }
    else if(strcasecmp(vartype, "uint_fast32_t") == 0)
    {
        assert(size == sizeof(uint_fast32_t));
        printf("%"PRIdFAST32, *((uint_fast32_t *) value));
    }
    else if(strcasecmp(vartype, "int64_t") == 0)
    {
        assert(size == sizeof(int64_t));
        printf("%li", *((int64_t *) value));
    }
    else if(strcasecmp(vartype, "int_least64_t") == 0)
    {
        assert(size == sizeof(int_least64_t));
        printf("%"PRIdLEAST64, *((int_least64_t *) value));
    }
    else if(strcasecmp(vartype, "int_fast64_t") == 0)
    {
        assert(size == sizeof(int_fast64_t));
        printf("%"PRIdFAST64, *((int_fast64_t *) value));
    }
    else if(strcasecmp(vartype, "uint64_t") == 0)
    {
        assert(size == sizeof(uint64_t));
        printf("%lu", *((uint64_t *) value));
    }
    else if(strcasecmp(vartype, "uint_least64_t") == 0)
    {
        assert(size == sizeof(uint_least64_t));
        printf("%"PRIuLEAST64, *((uint_least64_t *) value));
    }
    else if(strcasecmp(vartype, "uint_fast64_t") == 0)
    {
        assert(size == sizeof(uint_fast64_t));
        printf("%"PRIuFAST64, *((uint_fast64_t *) value));
    }
    // Fall back to char 
    else
    {
        for(int i=0; i < size; i++)
        {
            if ((i>0) && (i < size)) printf(", ");
            printf("%hhu", *((char *) value));
            value = (void *) ((uint64_t) value + sizeof(char));
        }
    }

}

void c2mpt_fix_vartype(char* fix_vartype, char* vartype)
{
    if((index(vartype, '*') != NULL)||
    (strcasecmp(vartype, "char") == 0)||
    (strcasecmp(vartype, "signed char") == 0)||
    (strcasecmp(vartype, "unsigned char") == 0)||
    (strcasecmp(vartype, "short") == 0)||
    (strcasecmp(vartype, "short int") == 0)||
    (strcasecmp(vartype, "signed short") == 0)||
    (strcasecmp(vartype, "signed short int") == 0)||
    (strcasecmp(vartype, "unsigned short") == 0)||
    (strcasecmp(vartype, "unsigned short int") == 0)||
    (strcasecmp(vartype, "int") == 0)||
    (strcasecmp(vartype, "signed") == 0)||
    (strcasecmp(vartype, "signed int") == 0)||
    (strcasecmp(vartype, "unsigned") == 0)||
    (strcasecmp(vartype, "unsigned int") == 0)||
    (strcasecmp(vartype, "long") == 0)||
    (strcasecmp(vartype, "long int") == 0)||
    (strcasecmp(vartype, "signed long") == 0)||
    (strcasecmp(vartype, "signed long int") == 0)||
    (strcasecmp(vartype, "unsigned long") == 0)||
    (strcasecmp(vartype, "unsigned long int") == 0)||
    (strcasecmp(vartype, "long long") == 0)||
    (strcasecmp(vartype, "long long int") == 0)||
    (strcasecmp(vartype, "signed long long") == 0)||
    (strcasecmp(vartype, "signed long long int") == 0)||
    (strcasecmp(vartype, "float") == 0)||
    (strcasecmp(vartype, "double") == 0)||
    (strcasecmp(vartype, "long double") == 0)||
    (strcasecmp(vartype, "int8_t") == 0)||
    (strcasecmp(vartype, "int_least8_t") == 0)||
    (strcasecmp(vartype, "int_fast8_t") == 0)||
    (strcasecmp(vartype, "uint8_t") == 0)||
    (strcasecmp(vartype, "uint_least8_t") == 0)||
    (strcasecmp(vartype, "uint_fast8_t") == 0)||
    (strcasecmp(vartype, "int16_t") == 0)||
    (strcasecmp(vartype, "int_least16_t") == 0)||
    (strcasecmp(vartype, "int_fast16_t") == 0)||
    (strcasecmp(vartype, "uint16_t") == 0)||
    (strcasecmp(vartype, "uint_least16_t") == 0)||
    (strcasecmp(vartype, "uint_fast16_t") == 0)||
    (strcasecmp(vartype, "int32_t") == 0)||
    (strcasecmp(vartype, "int_least32_t") == 0)||
    (strcasecmp(vartype, "int_fast32_t") == 0)||
    (strcasecmp(vartype, "uint32_t") == 0)||
    (strcasecmp(vartype, "uint_least32_t") == 0)||
    (strcasecmp(vartype, "uint_fast32_t") == 0)||
    (strcasecmp(vartype, "int64_t") == 0)||
    (strcasecmp(vartype, "int_least64_t") == 0)||
    (strcasecmp(vartype, "int_fast64_t") == 0)||
    (strcasecmp(vartype, "uint64_t") == 0)||
    (strcasecmp(vartype, "uint_least64_t") == 0)||
    (strcasecmp(vartype, "uint_fast64_t") == 0))
    {
        strcpy(fix_vartype, vartype);
    }
    else
    {
        strcpy(fix_vartype, "uint8_t");
    }

}


void c2mpt_dump_var(c2mpt_var var)
{
    uint_fast64_t i = 0;
    uint_fast64_t multiplier = 1;

    void * cval;
    char fix_vartype[50];        

    c2mpt_fix_vartype(fix_vartype, var.vartype);

    if(strcasecmp(fix_vartype, var.vartype) != 0)
    {
        printf("WARNING: Variable '%s' is not a base type ('%s'). You might"
                " hit endianness issues if the host and target platforms"
                " have different endianness. Double check your initialization"
                " data in the generated MPT file\n",
                var.varname, var.vartype);
        multiplier = var.elems_size;

    }


    #if __64BIT__ ||  __x86_64__ || __ppc64__ || __aarch64__ || __powerpc64__ || __s390x__
        printf("%s = [ \"%s\", %"PRIu64", 0x%"PRIx64", %"PRIu64", ", 
                var.varname, fix_vartype, var.nelems * multiplier,
                (uint64_t) var.address - (uint64_t) MPT_BASE_ADDRESS, 
                var.alignment);
    #else
	printf("%s = [ \"%s\", %"PRIu64", 0x%"PRIx32", %"PRIu64", ", 
                var.varname, fix_vartype, var.nelems * multiplier,
                (uint32_t) var.address - (uint64_t) MPT_BASE_ADDRESS,
                var.alignment);
    #endif

    if (var.nelems > 1)
    {
        printf("[ ");
    }

    cval = (void *) var.address;
    for(i=0; i < var.nelems; i++) 
    {
        if ((i>0) && (i < var.nelems)) printf(", ");
        c2mpt_print_value(cval, var.elems_size, var.vartype);
        cval = (void *) ((uint_fast64_t) cval + var.elems_size);
    }

    if (var.nelems > 1)
    {
    printf(" ]");
    }

    printf(" ]\n");

}

/****************************************************************************/
// Main c2mpt function
/****************************************************************************/

int main(int argc, char** argv)
{
    c2mpt_init_global_vars();
    c2mpt_dump_data();
    c2mpt_function();
    exit(0);
}

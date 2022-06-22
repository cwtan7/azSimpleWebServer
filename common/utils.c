#include "utils.h"
#include "exitcodes.h"

/* Define the base64 letters.  */
static char _util_base64_array[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _util_base64_encode                                 PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function encodes the input string into a base64                */
/*    representation.                                                     */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    name                                  Name string                   */
/*    name_size                             Size of name                  */
/*    base64name                            Encoded base64 name string    */
/*    base64name_size                       Size of encoded base64 name   */
/*    bytes_copied                          Number of bytes copied        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/**************************************************************************/
unsigned int _util_base64_encode(unsigned char *name, unsigned int name_size, unsigned char *base64name, unsigned int base64name_size, unsigned int *bytes_copied)
{
    unsigned int    pad;
    unsigned int    i, j;
    unsigned int    step;


    /* Check for invalid input pointers.  */
    if ((name == NX_NULL) || (base64name == NX_NULL) || (bytes_copied == NX_NULL))
    {
        return(ExitCode_Util_Ptr_Error);
    }

    /* Check the size.  */
    if ((name_size == 0) || (base64name_size == 0))
    {
        return(ExitCode_Util_Size_Error);
    }

    /* Adjust the length to represent the base64 name.  */
    name_size = ((name_size * 8) / 6);

    /* Default padding to none.  */
    pad = 0;

    /* Determine if an extra conversion is needed.  */
    if ((name_size * 6) % 24)
    {

        /* Some padding is needed.  */

        /* Calculate the number of pad characters.  */
        pad = (name_size * 6) % 24;
        pad = (24 - pad) / 6;
        pad = pad - 1;

        /* Adjust the length to pickup the character fraction.  */
        name_size++;
    }

    /* Check the buffer size.  */
    if (base64name_size <= (name_size + pad))
    {
        return(ExitCode_Util_Size_Error);
    }

    /* Setup index into the base64name.  */
    j = 0;

    /* Compute the base64name.  */
    step = 0;
    i = 0;
    while (j < name_size)
    {

        /* Determine which step we are in.  */
        if (step == 0)
        {

            /* Use first 6 bits of name character for index.  */
            base64name[j++] = (unsigned char)_util_base64_array[((unsigned char)name[i]) >> 2];
            step++;
        }
        else if (step == 1)
        {

            /* Use last 2 bits of name character and first 4 bits of next name character for index.  */
            base64name[j++] = (unsigned char)_util_base64_array[((((unsigned char)name[i]) & 0x3) << 4) | (((unsigned char)name[i + 1]) >> 4)];
            i++;
            step++;
        }
        else if (step == 2)
        {

            /* Use last 4 bits of name character and first 2 bits of next name character for index.  */
            base64name[j++] = (unsigned char)_util_base64_array[((((unsigned char)name[i]) & 0xF) << 2) | (((unsigned char)name[i + 1]) >> 6)];
            i++;
            step++;
        }
        else /* Step 3 */
        {

            /* Use last 6 bits of name character for index.  */
            base64name[j++] = (unsigned char)_util_base64_array[(((unsigned char)name[i]) & 0x3F)];
            i++;
            step = 0;
        }
    }

    /* Determine if the index needs to be advanced.  */
    if (step != 3)
    {
        i++;
    }

    /* Now add the PAD characters.  */
    while (pad--)
    {

        /* Pad base64name with '=' characters.  */
        base64name[j++] = '=';
    }

    /* Put a NULL character in.  */
    base64name[j] = NX_NULL;
    *bytes_copied = j;

    return(ExitCode_Success);
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _util_base64_decode                                 PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function decodes the input base64 ASCII string and converts    */
/*    it into a standard ASCII representation.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    base64name                            Encoded base64 name string    */ 
/*    base64name_size                       Size of encoded base64 name   */ 
/*    name                                  Name string                   */ 
/*    name_size                             Size of name                  */ 
/*    bytes_copied                          Number of bytes copied        */
/*                                                                        */
/**************************************************************************/
unsigned int _util_base64_decode(unsigned char *base64name, unsigned int base64name_size, unsigned char *name, unsigned int name_size, unsigned int *bytes_copied)
{
    unsigned int    i, j;
    unsigned int    value1, value2;
    unsigned int    step;
    unsigned int    source_size = base64name_size;

    /* Check for invalid input pointers.  */
    if ((base64name == NX_NULL) || (name == NX_NULL) || (bytes_copied == NX_NULL))
    {
        return(ExitCode_Util_Ptr_Error);
    }

    /* Check the size.  */
    if ((base64name_size == 0) || (name_size == 0))
    {
        return(ExitCode_Util_Size_Error);
    }

    /* Adjust the length to represent the ASCII name.  */
    base64name_size = ((base64name_size * 6) / 8);

    if ((base64name_size) && (base64name[source_size - 1] == '='))
    {
        base64name_size--;

        if ((base64name_size) && (base64name[source_size - 2] == '='))
        {
            base64name_size--;
        }
    }

    /* Check the buffer size.  */
    if (name_size <= base64name_size)
    {
        return(ExitCode_Util_Size_Error);
    }

    /* Setup index into the ASCII name.  */
    j = 0;

    /* Compute the ASCII name.  */
    step = 0;
    i =  0;
    while ((j < base64name_size) && (base64name[i]) && (base64name[i] != '='))
    {

        /* Derive values of the Base64 name.  */
        if ((base64name[i] >= 'A') && (base64name[i] <= 'Z'))
            value1 =  (unsigned int) (base64name[i] - 'A');
        else if ((base64name[i] >= 'a') && (base64name[i] <= 'z'))
            value1 =  (unsigned int) (base64name[i] - 'a') + 26;
        else if ((base64name[i] >= '0') && (base64name[i] <= '9'))
            value1 =  (unsigned int) (base64name[i] - '0') + 52;
        else if ((base64name[i] == '+') ||
                 (base64name[i] == '-')) /* Base64 URL.  */
            value1 =  62;
        else if ((base64name[i] == '/') ||
                 (base64name[i] == '_')) /* Base64 URL.  */
            value1 =  63;
        else
            value1 =  0;

        /* Derive value for the next character.  */
        if ((base64name[i + 1] >= 'A') && (base64name[i + 1] <= 'Z'))
            value2 =  (unsigned int) (base64name[i+1] - 'A');
        else if ((base64name[i + 1] >= 'a') && (base64name[i + 1] <= 'z'))
            value2 =  (unsigned int) (base64name[i+1] - 'a') + 26;
        else if ((base64name[i + 1] >= '0') && (base64name[i + 1] <= '9'))
            value2 =  (unsigned int) (base64name[i+1] - '0') + 52;
        else if ((base64name[i + 1] == '+') ||
                 (base64name[i + 1] == '-')) /* Base64 URL.  */
            value2 =  62;
        else if ((base64name[i + 1] == '/') ||
                 (base64name[i + 1] == '_')) /* Base64 URL.  */
            value2 =  63;
        else
            value2 =  0;

        /* Determine which step we are in.  */
        if (step == 0)
        {

            /* Use first value and first 2 bits of second value.  */
            name[j++] = (unsigned char) (((value1 & 0x3f) << 2) | ((value2 >> 4) & 3));
            i++;
            step++;
        }
        else if (step == 1)
        {

            /* Use last 4 bits of first value and first 4 bits of next value.  */
            name[j++] = (unsigned char) (((value1 & 0xF) << 4) | (value2 >> 2));
            i++;
            step++;
        }
        else
        {

            /* Use first 2 bits and following 6 bits of next value.  */
            name[j++] = (unsigned char) (((value1 & 3) << 6) | (value2 & 0x3f));
            i++;
            i++;
            step =  0;
        }
    }

    /* Put a NULL character in.  */
    name[j] = NX_NULL;
    *bytes_copied = j;

    return(ExitCode_Success);
}
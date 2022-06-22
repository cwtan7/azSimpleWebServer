/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _util_base64_encode                                  PORTABLE C     */
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
unsigned int _util_base64_encode(unsigned char *name, unsigned int name_size, unsigned char *base64name, unsigned int base64name_size, unsigned int *bytes_copied);

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
unsigned int _util_base64_decode(unsigned char *base64name, unsigned int base64name_size, unsigned char *name, unsigned int name_size, unsigned int *bytes_copied);
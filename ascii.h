#ifndef VSFTP_ASCII_H
#define VSFTP_ASCII_H

struct mystr;

/* vsf_ascii_ascii_to_bin()
 * PURPOSE
 * This function converts an input buffer from ascii format to binary format.
 * This entails ripping out all occurences of '\r'. The result is stored in
 * "p_out".
 * PARAMETERS
 * p_in         - the input buffer, which is not modified
 * p_out        - the output buffer, which MUST BE at least as big as "in_len"
 * in_len       - the length in bytes of the input buffer
 * RETURNS
 * The number of characters stored in the output buffer.
 */
unsigned int vsf_ascii_ascii_to_bin(const char* p_in, char* p_out,
                                    unsigned int in_len);
/* vsf_ascii_bin_to_ascii()
 * PURPOSE
 * This function converts an input buffer from binary format to ascii format.
 * This entails replacing all occurences of '\n' with '\r\n'. The result is
 * stored in "p_out".
 * PARAMETERS
 * p_in         - the input buffer, which is not modified
 * p_out        - the output buffer, which MUST BE at least TWICE as big as
 *                "in_len"
 * in_len       - the length in bytes of the input buffer
 * RETURNS
 * The number of characters stored in the output buffer
 */
unsigned int vsf_ascii_bin_to_ascii(const char* p_in, char* p_out,
                                    unsigned int in_len);

#endif /* VSFTP_ASCII_H */


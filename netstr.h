#ifndef VSFTP_NETSTR_H
#define VSFTP_NETSTR_H

struct mystr;

/* str_netfd_alloc()
 * PURPOSE
 * Read a string from a network socket into a string buffer object. The string
 * is delimited by a specified string terminator character.
 * If any network related errors occur trying to read the string, this call
 * will exit the program.
 * This method avoids reading one character at a time from the network.
 * PARAMETERS
 * p_str        - the destination string object
 * fd           - the file descriptor of the remote network socket
 * term         - the character which will terminate the string. This character
 *                is included in the returned string.
 * p_readbuf    - pointer to a scratch buffer into which to read from the
 *                network. This buffer must be at least "maxlen" characters!
 * maxlen       - maximum length of string to return. If this limit is passed,
 *                an empty string will be returned.
 */
void str_netfd_alloc(struct mystr* p_str, int fd, char term,
                     char* p_readbuf, unsigned int maxlen);

/* str_netfd_write()
 * PURPOSE
 * Write the contents of a string buffer object out to a network file
 * descriptor. Failure will cause this call to exit the program.
 * PARAMETERS
 * p_str        - the string object to send
 * fd           - the file descriptor of the remote network socket
 * RETURNS
 * 0 on success, -1 on failure
 */
int str_netfd_write(const struct mystr* p_str, int fd);

/* str_netfd_write_noblock()
 * PURPOSE
 * Write the contents of a string buffer object out to a network file
 * descriptor. This call will NOT BLOCK. Furthermore, any errors encountered
 * will be ignored.
 * PARAMETERS
 * p_str        - the string object to send
 * fd           - the file descriptor of the remote network socket
 * RETURNS
 * 0 on success, -1 on failure
 */
int str_netfd_write_noblock(const struct mystr* p_str, int fd);

#endif /* VSFTP_NETSTR_H */


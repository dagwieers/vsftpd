#ifndef VSF_PRIVSOCK_H
#define VSF_PRIVSOCK_H

struct mystr;
struct vsf_session;

/* priv_sock_init()
 * PURPOSE
 * Initialize the priv_sock system, by opening the communications sockets.
 * PARAMETERS
 * p_sess       - the current session object
 */
void priv_sock_init(struct vsf_session* p_sess);

/* priv_sock_send_cmd()
 * PURPOSE
 * Sends a command to the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * cmd          - the command to send
 */
void priv_sock_send_cmd(struct vsf_session* p_sess, char cmd);

/* priv_sock_send_str()
 * PURPOSE
 * Sends a string to the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * p_str        - the string to send
 */
void priv_sock_send_str(struct vsf_session* p_sess, const struct mystr* p_str);

/* priv_sock_get_result()
 * PURPOSE
 * Receives a response from the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * RETURNS
 * The response code.
 */
char priv_sock_get_result(struct vsf_session* p_sess);

/* priv_sock_get_cmd()
 * PURPOSE
 * Receives a command on the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * RETURNS
 * The command that was sent.
 */
char priv_sock_get_cmd(struct vsf_session* p_sess);

/* priv_sock_get_str()
 * PURPOSE
 * Receives a string on the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * p_dest       - where to copy the received string
 */
void priv_sock_get_str(struct vsf_session* p_sess, struct mystr* p_dest);

/* priv_sock_send_result()
 * PURPOSE
 * Sends a command result to the unprivileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * res          - the result to send
 */
void priv_sock_send_result(struct vsf_session* p_sess, char res);

/* priv_sock_child_send_fd()
 * PURPOSE
 * Sends a file descriptor to the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * fd           - the descriptor to send
 */
void priv_sock_child_send_fd(struct vsf_session* p_sess, int fd);

/* priv_sock_parent_recv_fd()
 * PURPOSE
 * Receives a file descriptor on the privileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * RETURNS
 * The received file descriptor
 */
int priv_sock_parent_recv_fd(struct vsf_session* p_sess);

/* priv_sock_parent_send_fd()
 * PURPOSE
 * Sends a file descriptor to the unprivileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * fd           - the descriptor to send
 */
void priv_sock_parent_send_fd(struct vsf_session* p_sess, int fd);

/* priv_sock_child_recv_fd()
 * PURPOSE
 * Receives a file descriptor on the unprivileged side of the channel.
 * PARAMETERS
 * p_sess       - the current session object
 * RETURNS
 * The received file descriptor
 */
int priv_sock_child_recv_fd(struct vsf_session* p_sess);

#define PRIV_SOCK_LOGIN             1
#define PRIV_SOCK_CHOWN             2
#define PRIV_SOCK_GET_DATA_SOCK     3

#define PRIV_SOCK_RESULT_OK         1
#define PRIV_SOCK_RESULT_BAD        2

#endif /* VSF_PRIVSOCK_H */


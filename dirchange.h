#ifndef VSF_DIRCHANGE_H
#define VSF_DIRCHANGE_H

struct vsf_session;

/* dir_changed()
 * PURPOSE
 * This function, when called, will check if the current directory has just
 * been entered for the first time in this session. If so, and message file
 * support is on, a message file is looked for (default .message), and output
 * to the FTP control connection with the FTP code prefix specified by
 * "ftpcode".
 * PARAMETERS
 * p_sess         - the current FTP session object
 * ftpcode        - the FTP code to show with the message
 */
void dir_changed(struct vsf_session* p_sess, int ftpcode);

#endif /* VSF_DIRCHANGE_H */


/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * privsock.c
 *
 * This file contains code for a simple message and file descriptor passing
 * API, over a pair of UNIX sockets.
 * The messages are typically travelling across a privilege boundary, with
 * heavy distrust of messages on the side of more privilege.
 */

#include "privsock.h"

#include "utility.h"
#include "defs.h"
#include "str.h"
#include "netstr.h"
#include "sysutil.h"
#include "sysdeputil.h"
#include "secbuf.h"
#include "session.h"

void
priv_sock_init(struct vsf_session* p_sess)
{
  const struct vsf_sysutil_socketpair_retval retval =
    vsf_sysutil_unix_dgram_socketpair();
  if (p_sess->privsock_inited)
  {
    bug("priv_sock_init called twice");
  }
  p_sess->parent_fd = retval.socket_one;
  p_sess->child_fd = retval.socket_two;
  p_sess->privsock_inited = 1;
}

void
priv_sock_send_cmd(struct vsf_session* p_sess, char cmd)
{
  /* DGRAM socket -> message boundaries retained -> use plain write */
  int retval = vsf_sysutil_write(p_sess->child_fd, &cmd, sizeof(cmd));
  if (retval != sizeof(cmd))
  {
    die("vsf_sysutil_write");
  }
}

void
priv_sock_send_str(struct vsf_session* p_sess, const struct mystr* p_str)
{
  struct mystr null_term_str = INIT_MYSTR;
  str_copy(&null_term_str, p_str);
  str_append_char(&null_term_str, '\0');
  str_netfd_write(&null_term_str, p_sess->child_fd);
  str_free(&null_term_str);
}

char
priv_sock_get_result(struct vsf_session* p_sess)
{
  char res;
  /* DGRAM socket -> message boundaries retained -> use plain read */
  int retval = vsf_sysutil_read(p_sess->child_fd, &res, sizeof(res));
  if (retval != sizeof(res))
  {
    die("vsf_sysutil_read");
  }
  return res;
}

char
priv_sock_get_cmd(struct vsf_session* p_sess)
{
  char res;
  /* DGRAM socket -> message boundaries retained -> use plain read */
  int retval = vsf_sysutil_read(p_sess->parent_fd, &res, sizeof(res));
  if (retval != sizeof(res))
  {
    die("vsf_sysutil_read");
  }
  return res;
}

void
priv_sock_get_str(struct vsf_session* p_sess, struct mystr* p_dest)
{
  static char* s_p_privsock_str_buf;
  if (s_p_privsock_str_buf == 0)
  {
    vsf_secbuf_alloc(&s_p_privsock_str_buf, VSFTP_PRIVSOCK_MAXSTR);
  }
  /* XXX - alert - will return truncated string if sender embedded a \0 */
  str_netfd_alloc(p_dest, p_sess->parent_fd, '\0', s_p_privsock_str_buf,
                  VSFTP_PRIVSOCK_MAXSTR);
}

void
priv_sock_send_result(struct vsf_session* p_sess, char res)
{
  /* DGRAM socket -> message boundaries retained -> use plain write */
  int retval = vsf_sysutil_write(p_sess->parent_fd, &res, sizeof(res));
  if (retval != sizeof(res))
  {
    die("vsf_sysutil_write");
  }
}

void
priv_sock_child_send_fd(struct vsf_session* p_sess, int fd)
{
  vsf_sysutil_send_fd(p_sess->child_fd, fd);
}

void
priv_sock_parent_send_fd(struct vsf_session* p_sess, int fd)
{
  vsf_sysutil_send_fd(p_sess->parent_fd, fd);
}

int
priv_sock_parent_recv_fd(struct vsf_session* p_sess)
{
  return vsf_sysutil_recv_fd(p_sess->parent_fd);
}

int
priv_sock_child_recv_fd(struct vsf_session* p_sess)
{
  return vsf_sysutil_recv_fd(p_sess->child_fd);
}


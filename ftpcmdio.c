/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * ftpcmdio.c
 *
 * Routines applicable to reading and writing the FTP command stream.
 */

#include "ftpcmdio.h"
#include "ftpcodes.h"
#include "str.h"
#include "netstr.h"
#include "sysutil.h"
#include "tunables.h"
#include "defs.h"
#include "secbuf.h"
#include "utility.h"
#include "logging.h"
#include "session.h"

/* Internal functions */
static void ftp_getline(struct mystr* p_str);
static void ftp_write_text_common(struct vsf_session* p_sess, int status,
                                  const char* p_text, int noblock);
static void ftp_write_str_common(struct vsf_session* p_sess, int status,
                                 char sep, const struct mystr* p_str,
                                 int noblock);
static void handle_alarm_timeout(void* p_private);

void
vsf_cmdio_sock_setup(void)
{
  vsf_sysutil_activate_keepalive(VSFTP_COMMAND_FD);
  vsf_sysutil_set_nodelay(VSFTP_COMMAND_FD);
  vsf_sysutil_activate_oobinline(VSFTP_COMMAND_FD);
}

static void
handle_alarm_timeout(void* p_private)
{
  struct vsf_session* p_sess = (struct vsf_session*) p_private;
  vsf_cmdio_write_noblock(p_sess, FTP_IDLE_TIMEOUT, "Timeout. Pay attention.");
  vsf_sysutil_exit(0);
}

void
vsf_cmdio_write(struct vsf_session* p_sess, int status, const char* p_text)
{
  ftp_write_text_common(p_sess, status, p_text, 0);
}

void
vsf_cmdio_write_noblock(struct vsf_session* p_sess, int status,
                        const char* p_text)
{
  ftp_write_text_common(p_sess, status, p_text, 1);
}

static void
ftp_write_text_common(struct vsf_session* p_sess, int status,
                      const char* p_text, int noblock)
{
  /* XXX - could optimize */
  static struct mystr s_the_str;
  str_alloc_text(&s_the_str, p_text);
  ftp_write_str_common(p_sess, status, ' ', &s_the_str, noblock);
}

void
vsf_cmdio_write_str_hyphen(struct vsf_session* p_sess, int status,
                           const struct mystr* p_str)
{
  ftp_write_str_common(p_sess, status, '-', p_str, 0);
}

void
vsf_cmdio_write_str(struct vsf_session* p_sess, int status,
                    const struct mystr* p_str)
{
  ftp_write_str_common(p_sess, status, ' ', p_str, 0);
}

static void
ftp_write_str_common(struct vsf_session* p_sess, int status, char sep,
                     const struct mystr* p_str, int noblock)
{
  static struct mystr s_write_buf_str;
  static struct mystr s_text_mangle_str;
  if (tunable_log_ftp_protocol)
  {
    str_alloc_ulong(&s_write_buf_str, (unsigned long) status);
    str_append_char(&s_write_buf_str, sep);
    str_append_str(&s_write_buf_str, p_str);
    vsf_log_line(p_sess, kVSFLogEntryFTPOutput, &s_write_buf_str);
  }
  str_copy(&s_text_mangle_str, p_str);
  /* Process the output response according to the specifications.. */
  /* Escape telnet characters properly */
  str_replace_text(&s_text_mangle_str, "\377", "\377\377");
  /* Change \n for \0 in response */
  str_replace_char(&s_text_mangle_str, '\n', '\0');
  /* Build string to squirt down network */
  str_alloc_ulong(&s_write_buf_str, (unsigned long) status);
  str_append_char(&s_write_buf_str, sep);
  str_append_str(&s_write_buf_str, &s_text_mangle_str);
  str_append_text(&s_write_buf_str, "\r\n");
  if (noblock)
  {
    (void) str_netfd_write_noblock(&s_write_buf_str, VSFTP_COMMAND_FD);
  }
  else
  {
    int retval = str_netfd_write(&s_write_buf_str, VSFTP_COMMAND_FD);
    if (retval != 0)
    {
      die("str_netfd_write");
    }
  }
}

void
vsf_cmdio_set_alarm(struct vsf_session* p_sess)
{
  if (tunable_idle_session_timeout > 0)
  {
    vsf_sysutil_install_sighandler(kVSFSysUtilSigALRM, handle_alarm_timeout,
                                   p_sess);
    vsf_sysutil_set_alarm(tunable_idle_session_timeout);
  }
}

void
vsf_cmdio_get_cmd_and_arg(struct vsf_session* p_sess, struct mystr* p_cmd_str,
                          struct mystr* p_arg_str, int set_alarm)
{
  /* Prepare an alarm to timeout the session.. */
  if (set_alarm)
  {
    vsf_cmdio_set_alarm(p_sess);
  }
  /* Blocks */
  ftp_getline(p_cmd_str);
  str_split_char(p_cmd_str, p_arg_str, ' ');
  str_upper(p_cmd_str);
  if (tunable_log_ftp_protocol)
  {
    static struct mystr s_log_str;
    if (str_equal_text(p_cmd_str, "PASS"))
    {
      str_alloc_text(&s_log_str, "PASS <password>");
    }
    else
    {
      str_copy(&s_log_str, p_cmd_str);
      if (!str_isempty(p_arg_str))
      {
        str_append_char(&s_log_str, ' ');
        str_append_str(&s_log_str, p_arg_str);
      }
    }
    vsf_log_line(p_sess, kVSFLogEntryFTPInput, &s_log_str);
  }
}

static void
ftp_getline(struct mystr* p_str)
{
  static char* s_p_readline_buf;
  if (s_p_readline_buf == 0)
  {
    vsf_secbuf_alloc(&s_p_readline_buf, VSFTP_MAX_COMMAND_LINE);
  }
  str_netfd_alloc(p_str, VSFTP_COMMAND_FD, '\n', s_p_readline_buf,
                  VSFTP_MAX_COMMAND_LINE);
  /* As mandated by the FTP specifications.. */
  str_replace_char(p_str, '\0', '\n');
  /* If the last character is a \r, strip it */
  {
    unsigned int len = str_getlen(p_str);
    if (len > 0 && str_get_char_at(p_str, len - 1) == '\r')
    {
      str_trunc(p_str, len - 1);
    }
  }
}


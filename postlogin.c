/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * postlogin.c
 */

#include "postlogin.h"
#include "session.h"
#include "oneprocess.h"
#include "twoprocess.h"
#include "ftpcodes.h"
#include "ftpcmdio.h"
#include "ftpdataio.h"
#include "utility.h"
#include "tunables.h"
#include "defs.h"
#include "str.h"
#include "sysstr.h"
#include "banner.h"
#include "sysutil.h"
#include "logging.h"
#include "sysdeputil.h"

/* Private local functions */
static void handle_pwd(struct vsf_session* p_sess);
static void handle_cwd(struct vsf_session* p_sess);
static void handle_pasv(struct vsf_session* p_sess);
static void handle_retr(struct vsf_session* p_sess);
static void handle_cdup(struct vsf_session* p_sess);
static void handle_list(struct vsf_session* p_sess);
static void handle_type(struct vsf_session* p_sess);
static void handle_port(struct vsf_session* p_sess);
static void handle_stor(struct vsf_session* p_sess);
static void handle_mkd(struct vsf_session* p_sess);
static void handle_rmd(struct vsf_session* p_sess);
static void handle_dele(struct vsf_session* p_sess);
static void handle_rest(struct vsf_session* p_sess);
static void handle_rnfr(struct vsf_session* p_sess);
static void handle_rnto(struct vsf_session* p_sess);
static void handle_nlst(struct vsf_session* p_sess);
static void handle_size(struct vsf_session* p_sess);
static void handle_site(struct vsf_session* p_sess);
static void handle_appe(struct vsf_session* p_sess);
static void handle_mdtm(struct vsf_session* p_sess);
static void handle_site_chmod(struct vsf_session* p_sess,
                              struct mystr* p_arg_str);
static void handle_site_umask(struct vsf_session* p_sess,
                              struct mystr* p_arg_str);

static int pasv_active(struct vsf_session* p_sess);
static int port_active(struct vsf_session* p_sess);
static void pasv_cleanup(struct vsf_session* p_sess);
static void port_cleanup(struct vsf_session* p_sess);
static void handle_dir_common(struct vsf_session* p_sess, int full_details);
static void prepend_path_to_filename(struct mystr* p_str);
static int get_remote_transfer_fd(struct vsf_session* p_sess);
static int dispose_remote_transfer_fd(struct vsf_session* p_sess);
static void handle_sigurg(void* p_private);
static void handle_upload_common(struct vsf_session* p_sess, int is_append);

void
process_post_login(struct vsf_session* p_sess)
{
  if (p_sess->is_anonymous)
  {
    vsf_sysutil_set_umask(tunable_anon_umask);
    p_sess->bw_rate_max = tunable_anon_max_rate;
  }
  else
  {
    vsf_sysutil_set_umask(tunable_local_umask);
    p_sess->bw_rate_max = tunable_local_max_rate;
  }
  if (tunable_async_abor_enable)
  {
    vsf_sysutil_install_sighandler(kVSFSysUtilSigURG, handle_sigurg, p_sess);
    vsf_sysutil_activate_sigurg(VSFTP_COMMAND_FD);
  }
  /* Handle any login message */
  vsf_banner_dir_changed(p_sess, FTP_LOGINOK);
  vsf_cmdio_write(p_sess, FTP_LOGINOK, "Login successful. Have fun.");
  while(1)
  {
    if (tunable_setproctitle_enable)
    {
      vsf_sysutil_setproctitle("IDLE");
    }
    /* Blocks */
    vsf_cmdio_get_cmd_and_arg(p_sess, &p_sess->ftp_cmd_str,
                              &p_sess->ftp_arg_str, 1);
    if (tunable_setproctitle_enable)
    {
      struct mystr proctitle_str = INIT_MYSTR;
      str_copy(&proctitle_str, &p_sess->ftp_cmd_str);
      if (!str_isempty(&p_sess->ftp_arg_str))
      {
        str_append_char(&proctitle_str, ' ');
        str_append_str(&proctitle_str, &p_sess->ftp_arg_str);
      }
      /* Suggestion from Solar */
      str_replace_unprintable(&proctitle_str, '?');
      vsf_sysutil_setproctitle_str(&proctitle_str);
      str_free(&proctitle_str);
    }
    if (str_equal_text(&p_sess->ftp_cmd_str, "QUIT"))
    {
      vsf_cmdio_write(p_sess, FTP_GOODBYE, "Goodbye.");
      vsf_sysutil_exit(0);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "PWD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XPWD"))
    {
      handle_pwd(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "CWD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XCWD"))
    {
      handle_cwd(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "CDUP") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XCUP"))
    {
      handle_cdup(p_sess);
    }
    else if (tunable_pasv_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "PASV"))
    {
      handle_pasv(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "RETR"))
    {
      handle_retr(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "NOOP"))
    {
      vsf_cmdio_write(p_sess, FTP_NOOPOK, "Mary had a little lamb.");
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "SYST"))
    {
      vsf_cmdio_write(p_sess, FTP_SYSTOK, "UNIX Type: L8");
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "HELP"))
    {
      vsf_cmdio_write(p_sess, FTP_BADHELP, "Sorry, I don't do help.");
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "LIST"))
    {
      handle_list(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "TYPE"))
    {
      handle_type(p_sess);
    }
    else if (tunable_port_enable &&
             str_equal_text(&p_sess->ftp_cmd_str, "PORT"))
    {
      handle_port(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_upload_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "STOR"))
    {
      handle_stor(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_mkdir_write_enable || !p_sess->is_anonymous) &&
             (str_equal_text(&p_sess->ftp_cmd_str, "MKD") ||
              str_equal_text(&p_sess->ftp_cmd_str, "XMKD")))
    {
      handle_mkd(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             (str_equal_text(&p_sess->ftp_cmd_str, "RMD") ||
              str_equal_text(&p_sess->ftp_cmd_str, "XRMD")))
    {
      handle_rmd(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "DELE"))
    {
      handle_dele(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "REST"))
    {
      handle_rest(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "RNFR"))
    {
      handle_rnfr(p_sess);
    }
    else if (tunable_write_enable &&
             (tunable_anon_other_write_enable || !p_sess->is_anonymous) &&
             str_equal_text(&p_sess->ftp_cmd_str, "RNTO"))
    {
      handle_rnto(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "NLST"))
    {
      handle_nlst(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "SIZE"))
    {
      handle_size(p_sess);
    }
    else if (!p_sess->is_anonymous &&
             str_equal_text(&p_sess->ftp_cmd_str, "SITE"))
    {
      handle_site(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "ABOR"))
    {
      vsf_cmdio_write(p_sess, FTP_ABOR_NOCONN, "Duh. No transfer to ABOR.");
    }
    /* SECURITY: for now, no APPE in anonymous mode */
    else if (!p_sess->is_anonymous &&
             str_equal_text(&p_sess->ftp_cmd_str, "APPE"))
    {
      handle_appe(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "MDTM"))
    {
      handle_mdtm(p_sess);
    }
    else if (str_equal_text(&p_sess->ftp_cmd_str, "PASV") ||
             str_equal_text(&p_sess->ftp_cmd_str, "PORT") ||
             str_equal_text(&p_sess->ftp_cmd_str, "STOR") ||
             str_equal_text(&p_sess->ftp_cmd_str, "MKD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XMKD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RMD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "XRMD") ||
             str_equal_text(&p_sess->ftp_cmd_str, "DELE") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RNFR") ||
             str_equal_text(&p_sess->ftp_cmd_str, "RNTO") ||
             str_equal_text(&p_sess->ftp_cmd_str, "SITE") ||
             str_equal_text(&p_sess->ftp_cmd_str, "APPE"))
    {
      vsf_cmdio_write(p_sess, FTP_NOPERM, "Permission denied.");
    }
    else
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, "Unknown command.");
    }
  }
}

static void
handle_pwd(struct vsf_session* p_sess)
{
  static struct mystr s_cwd_buf_mangle_str;
  static struct mystr s_pwd_res_str;
  str_getcwd(&s_cwd_buf_mangle_str);
  /* Double up any double-quotes in the pathname! */
  str_replace_text(&s_cwd_buf_mangle_str, "\"", "\"\"");
  /* Enclose pathname in quotes */
  str_alloc_text(&s_pwd_res_str, "\"");
  str_append_str(&s_pwd_res_str, &s_cwd_buf_mangle_str);
  str_append_text(&s_pwd_res_str, "\"");
  vsf_cmdio_write_str(p_sess, FTP_PWDOK, &s_pwd_res_str);
}

static void
handle_cwd(struct vsf_session* p_sess)
{
  int retval = str_chdir(&p_sess->ftp_arg_str);
  if (retval == 0)
  {
    /* Handle any messages */
    vsf_banner_dir_changed(p_sess, FTP_CWDOK);
    vsf_cmdio_write(p_sess, FTP_CWDOK, "Directory successfully changed.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Failed to change directory.");
  }
}

static void
handle_cdup(struct vsf_session* p_sess)
{
  int retval = vsf_sysutil_chdir("..");
  if (retval == 0)
  {
    vsf_cmdio_write(p_sess, FTP_CWDOK, "Directory successfully changed.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Failed to change directory.");
  }
}

static int
port_active(struct vsf_session* p_sess)
{
  int ret = 0;
  if (p_sess->p_port_sockaddr != 0)
  {
    ret = 1;
    if (pasv_active(p_sess))
    {
      bug("port and pasv both active");
    }
  }
  return ret;
}

static int
pasv_active(struct vsf_session* p_sess)
{
  int ret = 0;
  if (p_sess->pasv_listen_fd != -1)
  {
    ret = 1;
    if (port_active(p_sess))
    {
      bug("pasv and port both active");
    }
  }
  return ret;
}

static void
port_cleanup(struct vsf_session* p_sess)
{
  vsf_sysutil_sockaddr_clear(&p_sess->p_port_sockaddr);
}

static void
pasv_cleanup(struct vsf_session* p_sess)
{
  if (p_sess->pasv_listen_fd != -1)
  {
    vsf_sysutil_close(p_sess->pasv_listen_fd);
    p_sess->pasv_listen_fd = -1;
  }
}

static void
handle_pasv(struct vsf_session* p_sess)
{
  static struct mystr s_pasv_res_str;
  static struct vsf_sysutil_sockaddr* s_p_sockaddr;
  struct vsf_sysutil_ipv4port listen_port;
  struct vsf_sysutil_ipv4addr listen_ipaddr;
  int bind_retries = 10;
  pasv_cleanup(p_sess);
  port_cleanup(p_sess);
  p_sess->pasv_listen_fd = vsf_sysutil_get_ipv4_sock();
  while (--bind_retries)
  {
    int retval;
    unsigned short the_port;
    double scaled_port;
    /* IPPORT_RESERVED */
    unsigned short min_port = 1024;
    unsigned short max_port = 65535;
    if (tunable_pasv_min_port > min_port && tunable_pasv_min_port < max_port)
    {
      min_port = tunable_pasv_min_port;
    }
    if (tunable_pasv_max_port > min_port && tunable_pasv_max_port < max_port)
    {
      max_port = tunable_pasv_max_port;
    }
    the_port = vsf_sysutil_get_random_byte();
    the_port <<= 8;
    the_port |= vsf_sysutil_get_random_byte();
    scaled_port = (double) min_port;
    scaled_port += ((double) the_port / (double) 65535) *
                   ((double) max_port - min_port);
    the_port = (unsigned short) scaled_port;
    vsf_sysutil_sockaddr_alloc_ipv4(&s_p_sockaddr);
    vsf_sysutil_sockaddr_set_port(s_p_sockaddr,
                                  vsf_sysutil_ipv4port_from_int(the_port));
    /* Bind to same address we got the incoming connect on */
    vsf_sysutil_sockaddr_set_ipaddr(s_p_sockaddr,
      vsf_sysutil_sockaddr_get_ipaddr(p_sess->p_local_addr));
    retval = vsf_sysutil_bind(p_sess->pasv_listen_fd, s_p_sockaddr);
    if (!vsf_sysutil_retval_is_error(retval))
    {
      break;
    }
    if (vsf_sysutil_get_error() == kVSFSysUtilErrADDRINUSE)
    {
      continue;
    }
    die("vsf_sysutil_bind");
  }
  if (!bind_retries)
  {
    die("vsf_sysutil_bind");
  }
  vsf_sysutil_listen(p_sess->pasv_listen_fd, 1);
  /* Get the address of the bound socket, for the port */
  vsf_sysutil_getsockname(p_sess->pasv_listen_fd, &s_p_sockaddr);
  if (tunable_pasv_address != 0)
  {
    /* Report passive address as specified in configuration */
    if (vsf_sysutil_inet_aton(tunable_pasv_address, &listen_ipaddr) == 0)
    {
      die("invalid pasv_address");
    }
  }
  else
  {
    /* Use address of bound socket for passive address */
    listen_ipaddr = vsf_sysutil_sockaddr_get_ipaddr(s_p_sockaddr);
  }
  listen_port = vsf_sysutil_sockaddr_get_port(s_p_sockaddr);
  str_alloc_text(&s_pasv_res_str, "Entering Passive Mode (");
  str_append_ulong(&s_pasv_res_str, listen_ipaddr.data[0]);
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, listen_ipaddr.data[1]);
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, listen_ipaddr.data[2]);
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, listen_ipaddr.data[3]);
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, listen_port.data[0]);
  str_append_text(&s_pasv_res_str, ",");
  str_append_ulong(&s_pasv_res_str, listen_port.data[1]);
  str_append_text(&s_pasv_res_str, ")");
  vsf_cmdio_write_str(p_sess, FTP_PASVOK, &s_pasv_res_str);
}

static void
handle_retr(struct vsf_session* p_sess)
{
  static struct mystr s_mark_str;
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  struct vsf_transfer_ret trans_ret;
  int retval;
  int remote_fd;
  int opened_file;
  int is_ascii = 0;
  filesize_t offset = p_sess->restart_pos;
  p_sess->restart_pos = 0;
  if (!pasv_active(p_sess) && !port_active(p_sess))
  {
    vsf_cmdio_write(p_sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
    return;
  }
  if (p_sess->is_ascii && offset != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                    "No support for resume of ASCII transfer.");
    return;
  }
  opened_file = str_open(&p_sess->ftp_arg_str, kVSFSysStrOpenReadOnly);
  if (vsf_sysutil_retval_is_error(opened_file))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Failed to open file.");
    return;
  }
  vsf_sysutil_fstat(opened_file, &s_p_statbuf);
  /* No games please */
  if (!vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
  {
    /* Note - pretend open failed */
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Failed to open file.");
    goto file_close_out;
  }
  /* Optionally, we'll be paranoid and only serve publicly readable stuff */
  if (p_sess->is_anonymous && tunable_anon_world_readable_only &&
      !vsf_sysutil_statbuf_is_readable_other(s_p_statbuf))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Failed to open file.");
    goto file_close_out;
  }
  /* Set the download offset (from REST) if any */
  if (offset != 0)
  {
    vsf_sysutil_lseek_to(opened_file, offset);
  }
  remote_fd = get_remote_transfer_fd(p_sess);
  if (vsf_sysutil_retval_is_error(remote_fd))
  {
    goto port_pasv_cleanup_out;
  }
  vsf_log_start_entry(p_sess, kVSFLogEntryDownload);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  str_alloc_text(&s_mark_str, "Opening ");
  if (tunable_ascii_download_enable && p_sess->is_ascii)
  {
    str_append_text(&s_mark_str, "ASCII");
    is_ascii = 1;
  }
  else
  {
    str_append_text(&s_mark_str, "BINARY");
  }
  str_append_text(&s_mark_str, " mode data connection for ");
  str_append_str(&s_mark_str, &p_sess->ftp_arg_str);
  str_append_text(&s_mark_str, " (");
  str_append_filesize_t(&s_mark_str,
                        vsf_sysutil_statbuf_get_size(s_p_statbuf));
  str_append_text(&s_mark_str, " bytes).");
  vsf_cmdio_write_str(p_sess, FTP_DATACONN, &s_mark_str);
  trans_ret = vsf_ftpdataio_transfer_file(p_sess, remote_fd,
                                          opened_file, 0, is_ascii);
  p_sess->transfer_size = trans_ret.transferred;
  retval = dispose_remote_transfer_fd(p_sess);
  /* Log _after_ the blocking dispose call, so we get transfer times right */
  if (trans_ret.retval == 0 && retval == 0)
  {
    vsf_log_do_log(p_sess, 1);
  }
  else
  {
    vsf_log_do_log(p_sess, 0);
  }
port_pasv_cleanup_out:
  port_cleanup(p_sess);
  pasv_cleanup(p_sess);
file_close_out:
  vsf_sysutil_close(opened_file);
}

static void
handle_list(struct vsf_session* p_sess)
{
  handle_dir_common(p_sess, 1);
}

static void
handle_dir_common(struct vsf_session* p_sess, int full_details)
{
  static struct mystr s_option_str;
  static struct mystr s_filter_str;
  static struct mystr s_dir_name_str;
  static struct vsf_sysutil_statbuf* s_p_dirstat;
  int remote_fd;
  int dir_allow_read = 1;
  struct vsf_sysutil_dir* p_dir = 0;
  str_empty(&s_option_str);
  str_empty(&s_filter_str);
  /* By default open the current directory */
  str_alloc_text(&s_dir_name_str, ".");
  if (!pasv_active(p_sess) && !port_active(p_sess))
  {
    vsf_cmdio_write(p_sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
    return;
  }
  /* Do we have an option? Going to be strict here - the option must come
   * first. e.g. "ls -a .." fine, "ls .. -a" not fine
   */
  if (!str_isempty(&p_sess->ftp_arg_str) &&
      str_get_char_at(&p_sess->ftp_arg_str, 0) == '-')
  {
    /* Chop off the '-' */
    str_mid_to_end(&p_sess->ftp_arg_str, &s_option_str, 1);
    /* A space will separate options from filter (if any) */
    str_split_char(&s_option_str, &s_filter_str, ' ');
  }
  else
  {
    /* The argument, if any, is just a filter */
    str_copy(&s_filter_str, &p_sess->ftp_arg_str);
  }
  if (!str_isempty(&s_filter_str))
  {
    /* First check - is it an outright directory, as in "ls /pub" */
    p_dir = str_opendir(&s_filter_str);
    if (p_dir != 0)
    {
      /* Listing a directory! */
      str_copy(&s_dir_name_str, &s_filter_str);
      str_free(&s_filter_str);
    }
    else
    {
      struct str_locate_result locate_result =
        str_locate_char(&s_filter_str, '/');
      if (locate_result.found)
      {
        /* Includes a path! Reverse scan for / in the arg, to get the
         * base directory and filter (if any)
         */
        str_copy(&s_dir_name_str, &s_filter_str);
        str_split_char_reverse(&s_dir_name_str, &s_filter_str, '/');
        /* If we have e.g. "ls /.message", we just ripped off the leading
         * slash because it is the only one!
         */
        if (str_isempty(&s_dir_name_str))
        {
          str_alloc_text(&s_dir_name_str, "/");
        }
      }
    }
  }
  if (p_dir == 0)
  {
    /* NOTE - failure check done below, it's not forgotten */
    p_dir = str_opendir(&s_dir_name_str);
  }
  /* Fine, do it */
  remote_fd = get_remote_transfer_fd(p_sess);
  if (vsf_sysutil_retval_is_error(remote_fd))
  {
    goto dir_close_out;
  }
  vsf_cmdio_write(p_sess, FTP_DATACONN, "Here comes the directory listing.");
  if (p_sess->is_anonymous && p_dir && tunable_anon_world_readable_only)
  {
    vsf_sysutil_dir_stat(p_dir, &s_p_dirstat);
    if (!vsf_sysutil_statbuf_is_readable_other(s_p_dirstat))
    {
      dir_allow_read = 0;
    }
  }
  if (p_dir == 0 || !dir_allow_read)
  {
    vsf_cmdio_write(p_sess, FTP_TRANSFEROK,
                    "Transfer done (but failed to open directory).");
  }
  else
  {
    (void) vsf_ftpdataio_transfer_dir(p_sess, remote_fd, p_dir,
                                      &s_dir_name_str, &s_option_str,
                                      &s_filter_str, full_details);
  }
  (void) dispose_remote_transfer_fd(p_sess);
dir_close_out:
  if (p_dir)
  {
    vsf_sysutil_closedir(p_dir);
  }
  port_cleanup(p_sess);
  pasv_cleanup(p_sess);
}

static void
handle_type(struct vsf_session* p_sess)
{
  str_upper(&p_sess->ftp_arg_str);
  if (str_equal_text(&p_sess->ftp_arg_str, "I") ||
      str_equal_text(&p_sess->ftp_arg_str, "L8") ||
      str_equal_text(&p_sess->ftp_arg_str, "L 8"))
  {
    p_sess->is_ascii = 0;
    vsf_cmdio_write(p_sess, FTP_TYPEOK, "Binary it is, then.");
  }
  else if (str_equal_text(&p_sess->ftp_arg_str, "A") ||
           str_equal_text(&p_sess->ftp_arg_str, "A N"))
  {
    p_sess->is_ascii = 1;
    vsf_cmdio_write(p_sess, FTP_TYPEOK, "ASCII tastes bad, dude.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, "Unrecognised TYPE command.");
  }
}

static void
handle_port(struct vsf_session* p_sess)
{
  static struct mystr s_tmp_str;
  struct vsf_sysutil_ipv4addr the_addr;
  struct vsf_sysutil_ipv4port the_port;
  unsigned char vals[6];
  int i;
  struct vsf_sysutil_ipv4addr remote_addr =
    vsf_sysutil_sockaddr_get_ipaddr(p_sess->p_remote_addr);
  pasv_cleanup(p_sess);
  port_cleanup(p_sess);
  str_copy(&s_tmp_str, &p_sess->ftp_arg_str);
  for (i=0; i<6; i++)
  {
    static struct mystr s_rhs_comma_str;
    int this_number;
    /* This puts a single , delimited field in tmp_str */
    str_split_char(&s_tmp_str, &s_rhs_comma_str, ',');
    /* Sanity - check for too many or two few commas! */
    if ( (i<5 && str_isempty(&s_rhs_comma_str)) ||
         (i==5 && !str_isempty(&s_rhs_comma_str)))
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, "Illegal PORT command.");
      return;
    }
    this_number = str_atoi(&s_tmp_str);
    if (this_number < 0 || this_number > 255)
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, "Illegal PORT command.");
      return;
    }
    /* If this truncates from int to uchar, we don't care */
    vals[i] = (unsigned char) this_number;
    /* The right hand side of the comma now becomes the new string to
     * breakdown
     */
    str_copy(&s_tmp_str, &s_rhs_comma_str);
  }
  vsf_sysutil_memcpy(the_addr.data, vals, sizeof(the_addr.data));
  vsf_sysutil_memcpy(the_port.data, &vals[4], sizeof(the_port.data));
  /* SECURITY:
   * 1) Reject requests not connecting to the control socket IP
   * 2) Reject connects to privileged ports
   */
  if (!tunable_port_promiscuous)
  {
    if (vsf_sysutil_memcmp(the_addr.data, remote_addr.data,
                           sizeof(the_addr.data)) != 0 ||
        vsf_sysutil_is_port_reserved(the_port))
    {
      vsf_cmdio_write(p_sess, FTP_BADCMD, "Illegal PORT command.");
      port_cleanup(p_sess);
      return;
    }
  }
  vsf_sysutil_sockaddr_alloc_ipv4(&p_sess->p_port_sockaddr);
  vsf_sysutil_sockaddr_set_port(p_sess->p_port_sockaddr, the_port);
  vsf_sysutil_sockaddr_set_ipaddr(p_sess->p_port_sockaddr, the_addr);
  vsf_cmdio_write(p_sess, FTP_PORTOK,
                  "PORT command successful. Consider using PASV.");
}

static void
handle_stor(struct vsf_session* p_sess)
{
  handle_upload_common(p_sess, 0);
}

static void
handle_upload_common(struct vsf_session* p_sess, int is_append)
{
  struct vsf_transfer_ret trans_ret;
  int new_file_fd;
  int remote_fd;
  int retval;
  filesize_t offset = p_sess->restart_pos;
  p_sess->restart_pos = 0;
  if (!pasv_active(p_sess) && !port_active(p_sess))
  {
    vsf_cmdio_write(p_sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
    return;
  }
  /* NOTE - actual file permissions will be governed by the tunable umask */
  /* XXX - do we care about race between create and chown() of anonymous
   * upload?
   */
  if (p_sess->is_anonymous)
  {
    new_file_fd = str_create(&p_sess->ftp_arg_str);
  }
  else
  {
    /* For non-anonymous, allow open() to overwrite or append existing files */
    if (!is_append && offset == 0)
    {
      new_file_fd = str_create_overwrite(&p_sess->ftp_arg_str);
    }
    else
    {
      new_file_fd = str_create_append(&p_sess->ftp_arg_str);
    }
  }
  if (vsf_sysutil_retval_is_error(new_file_fd))
  {
    vsf_cmdio_write(p_sess, FTP_UPLOADFAIL, "Could not create file.");
    return;
  }
  /* Are we required to chown() this file for security? */
  if (p_sess->is_anonymous && tunable_chown_uploads)
  {
    if (tunable_one_process_model)
    {
      vsf_one_process_chown_upload(p_sess, new_file_fd);
    }
    else
    {
      vsf_two_process_chown_upload(p_sess, new_file_fd);
    }
  }
  if (!is_append && offset != 0)
  {
    /* XXX - warning, allows seek past end of file! Check for seek > size? */
    vsf_sysutil_lseek_to(new_file_fd, offset);
  }
  remote_fd = get_remote_transfer_fd(p_sess);
  if (vsf_sysutil_retval_is_error(remote_fd))
  {
    goto port_pasv_cleanup_out;
  }
  vsf_cmdio_write(p_sess, FTP_DATACONN,
                  "Go ahead make my day^W^W^Wsend me the data.");
  vsf_log_start_entry(p_sess, kVSFLogEntryUpload);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  if (tunable_ascii_upload_enable && p_sess->is_ascii)
  {
    trans_ret = vsf_ftpdataio_transfer_file(p_sess, remote_fd,
                                            new_file_fd, 1, 1);
  }
  else
  {
    trans_ret = vsf_ftpdataio_transfer_file(p_sess, remote_fd,
                                            new_file_fd, 1, 0);
  }
  p_sess->transfer_size = trans_ret.transferred;
  /* XXX - handle failure, delete file? */
  retval = dispose_remote_transfer_fd(p_sess);
  /* Log _after_ the blocking dispose call, so we get transfer times right */
  if (trans_ret.retval == 0 && retval == 0)
  {
    vsf_log_do_log(p_sess, 1);
  }
  else
  {
    vsf_log_do_log(p_sess, 0);
  }
port_pasv_cleanup_out:
  port_cleanup(p_sess);
  pasv_cleanup(p_sess);
  vsf_sysutil_close(new_file_fd);
}

static void
handle_mkd(struct vsf_session* p_sess)
{
  int retval;
  vsf_log_start_entry(p_sess, kVSFLogEntryMkdir);
  str_copy(&p_sess->log_str, &p_sess->ftp_arg_str);
  prepend_path_to_filename(&p_sess->log_str);
  /* NOTE! Actual permissions will be governed by the tunable umask */
  retval = str_mkdir(&p_sess->ftp_arg_str, 0777);
  if (retval != 0)
  {
    vsf_log_do_log(p_sess, 0);
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                    "Create directory operation failed.");
    return;
  }
  vsf_log_do_log(p_sess, 1);
  {
    static struct mystr s_mkd_res;
    static struct mystr s_tmp_str;
    str_copy(&s_tmp_str, &p_sess->ftp_arg_str);
    prepend_path_to_filename(&s_tmp_str);
    /* Double up double quotes */
    str_replace_text(&s_tmp_str, "\"", "\"\"");
    /* Build result string */
    str_alloc_text(&s_mkd_res, "\"");
    str_append_str(&s_mkd_res, &s_tmp_str);
    str_append_text(&s_mkd_res, "\" created");
    vsf_cmdio_write_str(p_sess, FTP_MKDIROK, &s_mkd_res);
  }
}

static void
handle_rmd(struct vsf_session* p_sess)
{
  int retval = str_rmdir(&p_sess->ftp_arg_str);
  if (retval != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                    "Remove directory operation failed.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_RMDIROK,
                    "Remove directory operation successful.");
  }
}

static void
handle_dele(struct vsf_session* p_sess)
{
  int retval = str_unlink(&p_sess->ftp_arg_str);
  if (retval != 0)
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Delete operation failed.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_DELEOK, "Delete operation successful.");
  }
}

static void
handle_rest(struct vsf_session* p_sess)
{
  filesize_t val = str_a_to_filesize_t(&p_sess->ftp_arg_str);
  if (val < 0)
  {
    val = 0;
  }
  p_sess->restart_pos = val;
  vsf_cmdio_write(p_sess, FTP_RESTOK, "Restart position accepted.");
}

static void
handle_rnfr(struct vsf_session* p_sess)
{
  static struct vsf_sysutil_statbuf* p_statbuf;
  int retval;
  /* Clear old value */
  str_free(&p_sess->rnfr_filename_str);
  /* Does it exist? */
  retval = str_stat(&p_sess->ftp_arg_str, &p_statbuf);
  if (retval == 0)
  {
    /* Yes */
    str_copy(&p_sess->rnfr_filename_str, &p_sess->ftp_arg_str);
    vsf_cmdio_write(p_sess, FTP_RNFROK, "Ready for RNTO.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "RNFR command failed.");
  }
}

static void
handle_rnto(struct vsf_session* p_sess)
{
  int retval;
  /* If we didn't get a RNFR, throw a wobbly */
  if (str_isempty(&p_sess->rnfr_filename_str))
  {
    vsf_cmdio_write(p_sess, FTP_NEEDRNFR,
                    "Dude, get it sorted, I need RNFR first.");
    return;
  }
  /* NOTE - might overwrite destination file. Not a concern because the same
   * could be accomplished with DELE.
   */
  retval = str_rename(&p_sess->rnfr_filename_str, &p_sess->ftp_arg_str);
  /* Clear the RNFR filename; start the two stage process again! */
  str_free(&p_sess->rnfr_filename_str);
  if (retval == 0)
  {
    vsf_cmdio_write(p_sess, FTP_RENAMEOK, "Rename successful.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Rename failed.");
  }
}

static void
handle_nlst(struct vsf_session* p_sess)
{
  handle_dir_common(p_sess, 0);
}

static void
prepend_path_to_filename(struct mystr* p_str)
{
  static struct mystr s_tmp_str;
  /* Only prepend current working directory if the incoming filename is
   * relative
   */
  str_empty(&s_tmp_str);
  if (str_isempty(p_str) || str_get_char_at(p_str, 0) != '/')
  {
    str_getcwd(&s_tmp_str);
    /* Careful to not emit // if we are in directory / (common with chroot) */
    if (str_isempty(&s_tmp_str) ||
        str_get_char_at(&s_tmp_str, str_getlen(&s_tmp_str) - 1) != '/')
    {
      str_append_char(&s_tmp_str, '/');
    }
  }
  str_append_str(&s_tmp_str, p_str);
  str_copy(p_str, &s_tmp_str);
}


static void
handle_sigurg(void* p_private)
{
  struct mystr async_cmd_str = INIT_MYSTR;
  struct mystr async_arg_str = INIT_MYSTR;
  struct mystr real_cmd_str = INIT_MYSTR;
  unsigned int len;
  struct vsf_session* p_sess = (struct vsf_session*) p_private;
  /* Did stupid client sent something OOB without a data connection? */
  if (p_sess->data_fd == -1)
  {
    return;
  }
  /* Get the async command - blocks (use data timeout alarm) */
  vsf_cmdio_get_cmd_and_arg(p_sess, &async_cmd_str, &async_arg_str, 0);
  /* Chop off first four characters; they are telnet characters. The client
   * should have sent the first two normally and the second two as urgent
   * data.
   */
  len = str_getlen(&async_cmd_str);
  if (len >= 4)
  {
    str_right(&async_cmd_str, &real_cmd_str, len - 4);
  }
  if (str_equal_text(&real_cmd_str, "ABOR"))
  {
    p_sess->abor_received = 1;
    vsf_sysutil_shutdown_failok(p_sess->data_fd);
  }
  else
  {
    /* Sorry! */
    vsf_cmdio_write(p_sess, FTP_BADCMD, "Unknown command.");
  }
  str_free(&async_cmd_str);
  str_free(&async_arg_str);
  str_free(&real_cmd_str);
}

static int
get_remote_transfer_fd(struct vsf_session* p_sess)
{
  int remote_fd;
  if (!pasv_active(p_sess) && !port_active(p_sess))
  {
    bug("neither PORT nor PASV active in get_remote_transfer_fd");
  }
  p_sess->abor_received = 0;
  if (pasv_active(p_sess))
  {
    remote_fd = vsf_ftpdataio_get_pasv_fd(p_sess);
  }
  else
  {
    remote_fd = vsf_ftpdataio_get_port_fd(p_sess);
  }
  return remote_fd;
}

static int
dispose_remote_transfer_fd(struct vsf_session* p_sess)
{
  vsf_ftpdataio_dispose_transfer_fd(p_sess);
  /* If the client sent ABOR, respond to it here */
  if (p_sess->abor_received)
  {
    p_sess->abor_received = 0;
    vsf_cmdio_write(p_sess, FTP_ABOROK, "ABOR successful.");
    return -1;
  }
  return 0;
}

static void
handle_size(struct vsf_session* p_sess)
{
  /* Note - in ASCII mode, are supposed to return the size after taking into
   * account ASCII linefeed conversions. At least this is what wu-ftpd does in
   * version 2.6.1. Proftpd-1.2.0pre fails to do this.
   * I will not do it because it is a potential I/O DoS.
   */
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  int retval = str_stat(&p_sess->ftp_arg_str, &s_p_statbuf);
  if (retval != 0 || !vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "Could not get file size.");
  }
  else
  {
    static struct mystr s_size_res_str;
    str_alloc_filesize_t(&s_size_res_str,
                         vsf_sysutil_statbuf_get_size(s_p_statbuf));
    vsf_cmdio_write_str(p_sess, FTP_SIZEOK, &s_size_res_str);
  }
}

static void
handle_site(struct vsf_session* p_sess)
{
  static struct mystr s_site_args_str;
  /* What SITE sub-command is it? */
  str_split_char(&p_sess->ftp_arg_str, &s_site_args_str, ' ');
  str_upper(&p_sess->ftp_arg_str);
  if (tunable_write_enable &&
      str_equal_text(&p_sess->ftp_arg_str, "CHMOD"))
  {
    handle_site_chmod(p_sess, &s_site_args_str);
  }
  else if (str_equal_text(&p_sess->ftp_arg_str, "UMASK"))
  {
    handle_site_umask(p_sess, &s_site_args_str);
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, "Unknown SITE command.");
  }
}

static void
handle_site_chmod(struct vsf_session* p_sess, struct mystr* p_arg_str)
{
  static struct mystr s_chmod_file_str;
  unsigned int perms;
  int retval;
  if (str_isempty(p_arg_str))
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
    return;
  }
  str_split_char(p_arg_str, &s_chmod_file_str, ' ');
  if (str_isempty(&s_chmod_file_str))
  {
    vsf_cmdio_write(p_sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
    return;
  }
  /* Don't worry - our chmod() implementation only allows 0 - 0777 */
  perms = str_octal_to_uint(p_arg_str);
  retval = str_chmod(&s_chmod_file_str, perms);
  if (vsf_sysutil_retval_is_error(retval))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL, "SITE CHMOD command failed.");
  }
  else
  {
    vsf_cmdio_write(p_sess, FTP_CHMODOK, "SITE CHMOD command ok.");
  }
}

static void
handle_site_umask(struct vsf_session* p_sess, struct mystr* p_arg_str)
{
  static struct mystr s_umask_resp_str;
  if (str_isempty(p_arg_str))
  {
    /* Empty arg => report current umask */
    str_alloc_text(&s_umask_resp_str, "Your current UMASK is ");
    str_append_text(&s_umask_resp_str,
                    vsf_sysutil_uint_to_octal(vsf_sysutil_get_umask()));
  }
  else
  {
    /* Set current umask */
    unsigned int new_umask = str_octal_to_uint(p_arg_str);
    vsf_sysutil_set_umask(new_umask);
    str_alloc_text(&s_umask_resp_str, "UMASK set to ");
    str_append_text(&s_umask_resp_str,
                    vsf_sysutil_uint_to_octal(vsf_sysutil_get_umask()));
  }
  vsf_cmdio_write_str(p_sess, FTP_UMASKOK, &s_umask_resp_str);
}

static void
handle_appe(struct vsf_session* p_sess)
{
  handle_upload_common(p_sess, 1);
}

static void
handle_mdtm(struct vsf_session* p_sess)
{
  static struct vsf_sysutil_statbuf* s_p_statbuf;
  int retval = str_stat(&p_sess->ftp_arg_str, &s_p_statbuf);
  if (retval != 0 || !vsf_sysutil_statbuf_is_regfile(s_p_statbuf))
  {
    vsf_cmdio_write(p_sess, FTP_FILEFAIL,
                    "Could not get file modification time.");
  }
  else
  {
    static struct mystr s_mdtm_res_str;
    str_alloc_text(&s_mdtm_res_str,
                   vsf_sysutil_statbuf_get_numeric_date(
                     s_p_statbuf, tunable_use_localtime));
    vsf_cmdio_write_str(p_sess, FTP_MDTMOK, &s_mdtm_res_str);
  }
}


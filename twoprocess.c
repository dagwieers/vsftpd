/*
 * Part of Very Secure FTPd
 * License: GPL
 * Author: Chris Evans
 * twoprocess.c
 *
 * Code implementing the standard, secure two process security model.
 */

#include "twoprocess.h"
#include "privops.h"
#include "prelogin.h"
#include "postlogin.h"
#include "postprivparent.h"
#include "session.h"
#include "privsock.h"
#include "secutil.h"
#include "sysutil.h"
#include "filestr.h"
#include "str.h"
#include "sysstr.h"
#include "utility.h"
#include "tunables.h"
#include "defs.h"
#include "parseconf.h"

static void drop_all_privs(void);
static void handle_sigchld(int duff);
static void process_login_req(struct vsf_session* p_sess);
static void common_do_login(struct vsf_session* p_sess,
                            const struct mystr* p_user_str, int do_chroot,
                            int anon);
static void handle_per_user_config(const struct mystr* p_user_str);
static void calculate_chdir_dir(int anon, struct mystr* p_chroot_str,
                                const struct mystr* p_user_str);

static void
handle_sigchld(int duff)
{
  /* WARNING - async handler. Must not call anything which might have
   * re-entrancy issues
   */
  struct vsf_sysutil_wait_retval wait_retval = vsf_sysutil_wait();
  (void) duff;
  /* Child died, so we'll do the same! Report it as an error unless the child
   * exited normally with zero exit code
   */
  if (vsf_sysutil_retval_is_error(vsf_sysutil_wait_get_retval(&wait_retval)) ||
      !vsf_sysutil_wait_exited_normally(&wait_retval) ||
      vsf_sysutil_wait_get_exitcode(&wait_retval) != 0)
  { 
    die("child died");
  }
  else
  {
    vsf_sysutil_exit(0);
  }
}

void
vsf_two_process_start(struct vsf_session* p_sess)
{
  /* Create the comms channel between privileged parent and no-priv child */
  priv_sock_init(p_sess);
  vsf_sysutil_install_async_sighandler(kVSFSysUtilSigCHLD, handle_sigchld);
  {
    int newpid = vsf_sysutil_fork();
    if (newpid != 0)
    {
      /* Parent - go into pre-login parent process mode */
      while (1)
      {
        process_login_req(p_sess);
      }
      /* NOTREACHED */
      bug("should not get here: vsf_two_process_start");
    }
  }
  /* Child process - time to lose as much privilege as possible and do the
   * login processing
   */
  if (tunable_local_enable && tunable_userlist_enable)
  {
    int retval = str_fileread(&p_sess->userlist_str, tunable_userlist_file,
                              VSFTP_CONF_FILE_MAX);
    if (vsf_sysutil_retval_is_error(retval))
    {
      die("cannot open user list file");
    }
  }
  drop_all_privs();
  init_connection(p_sess);
  /* NOTREACHED */
}

static void
drop_all_privs(void)
{
  struct mystr user_str = INIT_MYSTR;
  struct mystr dir_str = INIT_MYSTR;
  str_alloc_text(&user_str, tunable_nopriv_user);
  str_alloc_text(&dir_str, tunable_secure_chroot_dir);
  /* Be kind: give good error message if the secure dir is missing */
  {
    struct vsf_sysutil_statbuf* p_statbuf = 0;
    if (vsf_sysutil_retval_is_error(str_lstat(&dir_str, &p_statbuf)))
    {
      die("vsftpd: not found: directory given in 'secure_chroot_dir'");
    }
    vsf_sysutil_free(p_statbuf);
  }
  vsf_secutil_change_credentials(&user_str, &dir_str, 0, 0,
                                 VSF_SECUTIL_OPTION_CHROOT);
  str_free(&user_str);
  str_free(&dir_str);
}

void
vsf_two_process_login(struct vsf_session* p_sess,
                      const struct mystr* p_pass_str)
{
  char result;
  priv_sock_send_cmd(p_sess, PRIV_SOCK_LOGIN);
  priv_sock_send_str(p_sess, &p_sess->user_str);
  priv_sock_send_str(p_sess, p_pass_str);
  result = priv_sock_get_result(p_sess);
  if (result == PRIV_SOCK_RESULT_OK)
  {
    /* Miracle. We don't emit the success message here. That is left to
     * process_post_login().
     * Exit normally, parent will wait for this and launch new child
     */
    vsf_sysutil_exit(0);
  }
  else if (result == PRIV_SOCK_RESULT_BAD)
  {
    /* Continue the processing loop.. */
    return;
  }
  else
  {
    die("priv_sock_get_result");
  }
}

int
vsf_two_process_get_priv_data_sock(struct vsf_session* p_sess)
{
  char res;
  priv_sock_send_cmd(p_sess, PRIV_SOCK_GET_DATA_SOCK);
  res = priv_sock_get_result(p_sess);
  if (res != PRIV_SOCK_RESULT_OK)
  {
    die("could not get privileged socket");
  }
  return priv_sock_child_recv_fd(p_sess);
}

void
vsf_two_process_chown_upload(struct vsf_session* p_sess, int fd)
{
  char res;
  priv_sock_send_cmd(p_sess, PRIV_SOCK_CHOWN);
  priv_sock_child_send_fd(p_sess, fd);
  res = priv_sock_get_result(p_sess);
  if (res != PRIV_SOCK_RESULT_OK)
  {
    die("unexpected failure in vsf_two_process_chown_upload");
  }
}

static void
process_login_req(struct vsf_session* p_sess)
{
  enum EVSFPrivopLoginResult e_login_result = kVSFLoginNull;
  /* Blocks */
  if (priv_sock_get_cmd(p_sess) != PRIV_SOCK_LOGIN)
  {
    die("bad request");
  }
  /* Get username and password - we must distrust these */
  {
    struct mystr password_str = INIT_MYSTR;
    priv_sock_get_str(p_sess, &p_sess->user_str);
    priv_sock_get_str(p_sess, &password_str);
    e_login_result = vsf_privop_do_login(p_sess, &password_str);
    str_free(&password_str);
  }
  switch (e_login_result)
  {
    case kVSFLoginFail:
      priv_sock_send_result(p_sess, PRIV_SOCK_RESULT_BAD);
      return;
      break;
    case kVSFLoginAnon:
      str_alloc_text(&p_sess->user_str, tunable_ftp_username);
      common_do_login(p_sess, &p_sess->user_str, 1, 1);
      break;
    case kVSFLoginReal:
      {
        int do_chroot = 0;
        if (tunable_chroot_local_user)
        {
          do_chroot = 1;
        }
        if (tunable_chroot_list_enable)
        {
          struct mystr chroot_list_file = INIT_MYSTR;
          int retval = str_fileread(&chroot_list_file,
                                    tunable_chroot_list_file,
                                    VSFTP_CONF_FILE_MAX);
          if (vsf_sysutil_retval_is_error(retval))
          {
            die("cannot open chroot() user list file");
          }
          if (str_contains_line(&chroot_list_file, &p_sess->user_str))
          {
            if (do_chroot)
            {
              do_chroot = 0;
            }
            else
            {
              do_chroot = 1;
            }
          }
          str_free(&chroot_list_file);
        }
        common_do_login(p_sess, &p_sess->user_str, do_chroot, 0);
      }
      break;
    default:
      bug("weird state in process_login_request");
      break;
  }
  /* NOTREACHED */
}

static void
common_do_login(struct vsf_session* p_sess, const struct mystr* p_user_str,
                int do_chroot, int anon)
{
  int was_anon = anon;
  int newpid;
  vsf_sysutil_default_sig(kVSFSysUtilSigCHLD);
  /* Asks the pre-login child to go away (by exiting) */
  priv_sock_send_result(p_sess, PRIV_SOCK_RESULT_OK);
  (void) vsf_sysutil_wait();
  /* Handle loading per-user config options */
  handle_per_user_config(p_user_str);
  vsf_sysutil_install_async_sighandler(kVSFSysUtilSigCHLD, handle_sigchld);
  newpid = vsf_sysutil_fork(); 
  if (newpid == 0)
  {
    struct mystr guest_user_str = INIT_MYSTR;
    struct mystr chdir_str = INIT_MYSTR;
    unsigned int secutil_option = VSF_SECUTIL_OPTION_USE_GROUPS;
    calculate_chdir_dir(anon, &chdir_str, p_user_str);
    if (do_chroot)
    {
      secutil_option |= VSF_SECUTIL_OPTION_CHROOT;
    }
    /* Child - drop privs and start proper FTP! */
    if (tunable_guest_enable && !anon)
    {
      /* Remap to the guest user */
      str_alloc_text(&guest_user_str, tunable_guest_username);
      p_user_str = &guest_user_str;
      /* SECURITY: For now, apply the anonymous restrictions to
       * guest users
       */
      anon = 1;
    }
    if (!anon)
    {
      secutil_option |= VSF_SECUTIL_OPTION_CHANGE_EUID;
    }
    vsf_secutil_change_credentials(p_user_str, 0, &chdir_str,
                                   0, secutil_option);
    str_free(&guest_user_str);
    str_free(&chdir_str);
    /* Guard against the config error of having the anonymous ftp tree owned
     * by the user we are running as
     */
    if (was_anon && vsf_sysutil_write_access("/"))
    {
      die("vsftpd: refusing to run with writable anonymous root");
    }
    p_sess->is_anonymous = anon;
    process_post_login(p_sess);
    bug("should not get here: common_do_login");
  }
  /* Parent */
  vsf_priv_parent_postlogin(p_sess);
  bug("should not get here in common_do_login");
}

static void
handle_per_user_config(const struct mystr* p_user_str)
{
  if (tunable_user_config_dir)
  {
    struct mystr filename_str = INIT_MYSTR;
    struct vsf_sysutil_statbuf* p_statbuf = 0;
    int retval;
    str_alloc_text(&filename_str, tunable_user_config_dir);
    str_append_char(&filename_str, '/');
    str_append_str(&filename_str, p_user_str);
    retval = str_stat(&filename_str, &p_statbuf);
    /* Security - ignore unless owned by root */
    if (!vsf_sysutil_retval_is_error(retval) &&
        vsf_sysutil_statbuf_get_uid(p_statbuf) == VSFTP_ROOT_UID)
    {
      vsf_parseconf_load_file(str_getbuf(&filename_str));
    }
    str_free(&filename_str);
    vsf_sysutil_free(p_statbuf);
  }
}

static void
calculate_chdir_dir(int anon, struct mystr* p_chroot_str,
                    const struct mystr* p_user_str)
{
  if (anon && tunable_anon_root)
  {
    str_alloc_text(p_chroot_str, tunable_anon_root);
  }
  else if (!anon && tunable_local_root)
  {
    str_alloc_text(p_chroot_str, tunable_local_root);
  }
  /* If enabled, the chroot() location embedded in the HOMEDIR takes
   * precedence.
   */
  if (!anon && tunable_passwd_chroot_enable)
  {
    struct mystr homedir_str = INIT_MYSTR;
    const struct vsf_sysutil_user* p_user = str_getpwnam(p_user_str);
    struct str_locate_result loc_result;
    if (p_user == 0)
    {
      struct mystr death_str = INIT_MYSTR;
      str_alloc_text(&death_str, "str_getpwnam: ");
      str_append_str(&death_str, p_user_str);
      die(str_getbuf(&death_str));
    }
    str_alloc_text(&homedir_str, vsf_sysutil_user_get_homedir(p_user));
    loc_result = str_locate_text(&homedir_str, "/./");
    if (loc_result.found)
    {
      struct mystr tmp_str = INIT_MYSTR;
      str_split_text(&homedir_str, &tmp_str, "/./");
      str_free(&tmp_str);
      str_copy(p_chroot_str, &homedir_str);
    }
    str_free(&homedir_str);
  }
}


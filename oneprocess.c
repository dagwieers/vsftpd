/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * oneprocess.c
 *
 * Code for the "one process" security model. The one process security model
 * is born for the purposes of raw speed at the expense of compromising the
 * purity of the security model.
 * The one process model will typically be disabled, for security reasons.
 * Only sites with huge numbers of concurrent users are likely to feel the
 * pain of two processes per session.
 */

#include "prelogin.h"
#include "postlogin.h"
#include "privops.h"
#include "session.h"
#include "secutil.h"
#include "str.h"
#include "tunables.h"
#include "utility.h"
#include "sysdeputil.h"

void
vsf_one_process_start(struct vsf_session* p_sess)
{
  unsigned int caps = 0;
  if (tunable_chown_uploads)
  {
    caps |= kCapabilityCAP_CHOWN;
  }
  if (tunable_connect_from_port_20)
  {
    caps |= kCapabilityCAP_NET_BIND_SERVICE;
  }
  {
    struct mystr user_name = INIT_MYSTR;
    str_alloc_text(&user_name, tunable_ftp_username);
    vsf_secutil_change_credentials(&user_name, 0, 1, 1, caps);
    str_free(&user_name);
  }
  init_connection(p_sess);
}

void
vsf_one_process_login(struct vsf_session* p_sess,
                      const struct mystr* p_pass_str)
{
  enum EVSFPrivopLoginResult login_result =
    vsf_privop_do_login(p_sess, p_pass_str);
  switch (login_result)
  {
    case kVSFLoginFail:
      return;
      break;
    case kVSFLoginAnon:
      p_sess->is_anonymous = 1;
      process_post_login(p_sess);
      break;
    default:
      bug("bad state in vsf_one_process_login");
      break;
  }
}

int
vsf_one_process_get_priv_data_sock(struct vsf_session* p_sess)
{
  return vsf_privop_get_ftp_port_sock(p_sess);
}

void
vsf_one_process_chown_upload(struct vsf_session* p_sess, int fd)
{
  vsf_privop_do_file_chown(p_sess, fd);
}


/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * sysdeputil.c
 *
 * Highly system dependent utilities - e.g. authentication, capabilities.
 */

#include "sysdeputil.h"
#include "str.h"
#include "sysutil.h"
#include "utility.h"
#include "secbuf.h"
#include "defs.h"
#include "tunables.h"

/* For Linux, this adds nothing :-) */
#include "port/porting_junk.h"

/* For INT_MAX */
#include <limits.h>

/* For fd passing */
#include <sys/types.h>
#include <sys/socket.h>
/* For FreeBSD */
#include <sys/param.h>
#include <sys/uio.h>

/* Configuration.. here are the possibilities */
#undef VSF_SYSDEP_HAVE_CAPABILITIES
#undef VSF_SYSDEP_HAVE_SETKEEPCAPS
#undef VSF_SYSDEP_HAVE_LINUX_SENDFILE
#undef VSF_SYSDEP_HAVE_FREEBSD_SENDFILE
#undef VSF_SYSDEP_HAVE_HPUX_SENDFILE
#undef VSF_SYSDEP_HAVE_SETPROCTITLE
#undef VSF_SYSDEP_TRY_LINUX_SETPROCTITLE_HACK
#undef VSF_SYSDEP_HAVE_HPUX_SETPROCTITLE
#undef VSF_SYSDEP_HAVE_MAP_ANON
#undef VSF_SYSDEP_NEED_OLD_FD_PASSING
#define VSF_SYSDEP_HAVE_PAM
#define VSF_SYSDEP_HAVE_SHADOW
#define VSF_SYSDEP_HAVE_USERSHELL

/* BEGIN config */
#ifdef __linux__
  #define VSF_SYSDEP_TRY_LINUX_SETPROCTITLE_HACK
  #include <linux/version.h>
  #if defined(LINUX_VERSION_CODE) && defined(KERNEL_VERSION)
    #if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,2,0))
      #define VSF_SYSDEP_HAVE_CAPABILITIES
      #define VSF_SYSDEP_HAVE_LINUX_SENDFILE
      #include <sys/prctl.h>
      #ifdef PR_SET_KEEPCAPS
        #define VSF_SYSDEP_HAVE_SETKEEPCAPS
      #endif
    #endif
  #endif
#endif

#if (defined(__FreeBSD__) && __FreeBSD__ >= 3)
  #define VSF_SYSDEP_HAVE_FREEBSD_SENDFILE
  #define VSF_SYSDEP_HAVE_SETPROCTITLE
#endif

#ifdef __hpux
  #include <sys/socket.h>
  #ifdef SF_DISCONNECT
    #define VSF_SYSDEP_HAVE_HPUX_SENDFILE
  #endif
  #include <sys/param.h>
  #include <sys/pstat.h>
  #ifdef PSTAT_SETCMD
    #define VSF_SYSDEP_HAVE_HPUX_SETPROCTITLE
  #endif
#endif

#include <unistd.h>
#include <sys/mman.h>
#ifdef MAP_ANON
  #define VSF_SYSDEP_HAVE_MAP_ANON
#endif

#ifdef __sgi
  #undef VSF_SYSDEP_HAVE_USERSHELL
#endif

#if (defined(__sgi) || defined(__hpux))
  #define VSF_SYSDEP_NEED_OLD_FD_PASSING
#endif
/* END config */

/* PAM support - we include our own dummy version if the system lacks this */
#include <security/pam_appl.h>

/* No PAM? Try getspnam() with a getpwnam() fallback */
#ifndef VSF_SYSDEP_HAVE_PAM
/* This may hit our own "dummy" include and undef VSF_SYSDEP_HAVE_SHADOW */
#include <shadow.h>
#include <pwd.h>
#include <unistd.h>
#endif

#ifdef VSF_SYSDEP_HAVE_CAPABILITIES
#include <linux/capability.h>
#include <errno.h>
#include <syscall.h>
_syscall2(int, capset, cap_user_header_t, header, const cap_user_data_t, data)
/* Gross HACK to avoid warnings - linux headers overlap glibc headers */
#undef __NFDBITS
#undef __FDMASK
#endif /* VSF_SYSDEP_HAVE_CAPABILITIES */

#ifdef VSF_SYSDEP_HAVE_LINUX_SENDFILE
#include <sys/sendfile.h>
#elif defined(VSF_SYSDEP_HAVE_FREEBSD_SENDFILE)
#include <sys/types.h>
#include <sys/socket.h>
#elif defined(VSF_SYSDEP_HAVE_HPUX_SENDFILE)
#include <sys/socket.h>
#else /* VSF_SYSDEP_HAVE_LINUX_SENDFILE */
#include <unistd.h>
#endif /* VSF_SYSDEP_HAVE_LINUX_SENDFILE */

#ifdef VSF_SYSDEP_HAVE_SETPROCTITLE
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef VSF_SYSDEP_TRY_LINUX_SETPROCTITLE_HACK
extern char** environ;
static unsigned int s_proctitle_space = 0;
static int s_proctitle_inited = 0;
static char* s_p_proctitle = 0;
#endif

#ifndef VSF_SYSDEP_HAVE_MAP_ANON
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
static int s_zero_fd = -1;
#endif

/* File private functions/variables */
static int do_sendfile(const int out_fd, const int in_fd,
                       long* p_offset, unsigned int num_send);
static void vsf_sysutil_setproctitle_internal(const char* p_text);
static struct mystr s_proctitle_prefix_str;

#ifndef VSF_SYSDEP_HAVE_PAM
int
vsf_sysdep_check_auth(const struct mystr* p_user_str,
                      const struct mystr* p_pass_str,
                      const struct mystr* p_remote_host)
{
  const char* p_shell;
  const char* p_crypted;
  (void) p_remote_host;
  const struct passwd* p_pwd = getpwnam(str_getbuf(p_user_str));
  if (p_pwd == NULL)
  {
    return 0;
  }
  #ifdef VSF_SYSDEP_HAVE_USERSHELL
  while ((p_shell = getusershell()) != NULL)
  {
    if (!vsf_sysutil_strcmp(p_shell, p_pwd->pw_shell))
    {
      break;
    }
  }
  endusershell();
  if (p_shell == NULL)
  {
    return 0;
  }
  #endif
  #ifdef VSF_SYSDEP_HAVE_SHADOW
  {
    const struct spwd* p_spwd = getspnam(str_getbuf(p_user_str));
    if (p_spwd != NULL)
    {
      long curr_time;
      int days;
      vsf_sysutil_update_cached_time();
      curr_time = vsf_sysutil_get_cached_time_sec();
      days = curr_time / (60 * 60 * 24);
      if (p_spwd->sp_expire > 0 && p_spwd->sp_expire < days)
      {
        return 0;
      }
      if (p_spwd->sp_lstchg > 0 && p_spwd->sp_max > 0 &&
          p_spwd->sp_lstchg + p_spwd->sp_max < days)
      {
        return 0;
      }
      p_crypted = crypt(str_getbuf(p_pass_str), p_spwd->sp_pwdp);
      if (!vsf_sysutil_strcmp(p_crypted, p_spwd->sp_pwdp))
      {
        return 1;
      }
    }
  }
  #endif /* VSF_SYSDEP_HAVE_SHADOW */
  p_crypted = crypt(str_getbuf(p_pass_str), p_pwd->pw_passwd);
  if (!vsf_sysutil_strcmp(p_crypted, p_pwd->pw_passwd))
  {
    return 1;
  }
  return 0;
}

#else /* VSF_SYSDEP_HAVE_PAM */

static struct mystr s_pword_str;
static int pam_conv_func(int nmsg, const struct pam_message** p_msg,
                         struct pam_response** p_reply, void* p_addata);

int
vsf_sysdep_check_auth(const struct mystr* p_user_str,
                      const struct mystr* p_pass_str,
                      const struct mystr* p_remote_host)
{
  int retval;
  pam_handle_t* pamh = 0;
  struct pam_conv the_conv =
  {
    &pam_conv_func,
    0
  };
  str_copy(&s_pword_str, p_pass_str);
  retval = pam_start(tunable_pam_service_name,
                     str_getbuf(p_user_str), &the_conv, &pamh);
  if (retval != PAM_SUCCESS)
  {
    pam_end(pamh, 0);
    return 0;
  }
  #ifdef PAM_RHOST
  retval = pam_set_item(pamh, PAM_RHOST, str_getbuf(p_remote_host));
  if (retval != PAM_SUCCESS)
  {
    pam_end(pamh, 0);
    return 0;
  }
  #endif
  retval = pam_authenticate(pamh, 0);
  if (retval != PAM_SUCCESS)
  {
    pam_end(pamh, 0);
    return 0;
  }
  retval = pam_acct_mgmt(pamh, 0);
  if (retval != PAM_SUCCESS)
  {
    pam_end(pamh, 0);
    return 0;
  }
  retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
  if (retval != PAM_SUCCESS)
  {
    pam_end(pamh, 0);
    return 0;
  }
  retval = pam_end(pamh, PAM_SUCCESS);
  if (retval != PAM_SUCCESS)
  {
    return 0;
  }
  /* It worked, cool */
  return 1;
}

static int
pam_conv_func(int nmsg, const struct pam_message** p_msg,
              struct pam_response** p_reply, void* p_addata)
{
  int i;
  struct pam_response* p_resps = 0;
  (void) p_addata;
  if (nmsg < 0)
  {
    bug("dodgy nmsg in pam_conv_func");
  }
  /* XXX sometimes leaks */
  p_resps = vsf_sysutil_malloc(sizeof(struct pam_response) * nmsg);
  if (p_resps == 0)
  {
    return PAM_CONV_ERR;
  }
  for (i=0; i<nmsg; i++)
  {
    switch (p_msg[i]->msg_style)
    {
      case PAM_PROMPT_ECHO_ON:
        return PAM_CONV_ERR;
        break;
      case PAM_PROMPT_ECHO_OFF:
        p_resps[i].resp_retcode = PAM_SUCCESS;
        p_resps[i].resp = (char*) str_strdup(&s_pword_str);
        break;
      case PAM_TEXT_INFO:
      case PAM_ERROR_MSG:
        p_resps[i].resp_retcode = PAM_SUCCESS;
        p_resps[i].resp = 0;
        break;
      default:
        return PAM_CONV_ERR;
        break;
    }
  }
  *p_reply = p_resps;
  return PAM_SUCCESS;
}

#endif /* VSF_SYSDEP_HAVE_PAM */

/* Capabilities support (or lack thereof) */
void
vsf_sysdep_keep_capabilities(void)
{
  if (!vsf_sysdep_has_capabilities_as_non_root())
  {
    bug("asked to keep capabilities, but no support exists");
  }
#ifdef VSF_SYSDEP_HAVE_SETKEEPCAPS
  {
    int retval = prctl(PR_SET_KEEPCAPS, 1);
    if (vsf_sysutil_retval_is_error(retval))
    {
      die("prctl");
    }
  }
#endif /* VSF_SYSDEP_HAVE_SETKEEPCAPS */
}
#ifndef VSF_SYSDEP_HAVE_CAPABILITIES

int
vsf_sysdep_has_capabilities(void)
{
  return 0;
}

int
vsf_sysdep_has_capabilities_as_non_root(void)
{
  return 0;
}

void
vsf_sysdep_adopt_capabilities(unsigned int caps)
{
  (void) caps;
  bug("asked to adopt capabilities, but no support exists");
}

#else /* VSF_SYSDEP_HAVE_CAPABILITIES */

int
vsf_sysdep_has_capabilities(void)
{
  /* Even though compiled with capabilities, the runtime system may lack them.
   * Also, RH7.0 kernel headers advertise a 2.4.0 box, but on a 2.2.x kernel!
   */
  static int s_caps_checked;
  static int s_runtime_has_caps;
  if (!s_caps_checked)
  {
    /* EFAULT (EINVAL if page 0 mapped) vs. ENOSYS */
    int retval = capset(0, 0);
    if (!vsf_sysutil_retval_is_error(retval) ||
        vsf_sysutil_get_error() != kVSFSysUtilErrNOSYS)
    {
      s_runtime_has_caps = 1;
    }
    s_caps_checked = 1;
  }
  return s_runtime_has_caps;
}

int
vsf_sysdep_has_capabilities_as_non_root(void)
{
  static int s_prctl_checked;
  static int s_runtime_prctl_works;
  if (!s_prctl_checked)
  {
  #ifdef VSF_SYSDEP_HAVE_SETKEEPCAPS
    /* Clarity: note embedded call to prctl() syscall */
    if (!vsf_sysutil_retval_is_error(prctl(PR_SET_KEEPCAPS, 0)))
    {
      s_runtime_prctl_works = 1;
    }
  #endif /* VSF_SYSDEP_HAVE_SETKEEPCAPS */
    s_prctl_checked = 1;
  }
  return s_runtime_prctl_works;
}

void
vsf_sysdep_adopt_capabilities(unsigned int caps)
{
  /* n.b. yes I know I should be using libcap!! */
  int retval;
  struct __user_cap_header_struct cap_head;
  struct __user_cap_data_struct cap_data;
  __u32 cap_mask = 0;
  if (!caps)
  {
    bug("asked to adopt no capabilities");
  }
  vsf_sysutil_memclr(&cap_head, sizeof(cap_head));
  vsf_sysutil_memclr(&cap_data, sizeof(cap_data));
  cap_head.version = _LINUX_CAPABILITY_VERSION;
  cap_head.pid = 0;
  if (caps & kCapabilityCAP_CHOWN)
  {
    cap_mask |= (1 << CAP_CHOWN);
  }
  if (caps & kCapabilityCAP_NET_BIND_SERVICE)
  {
    cap_mask |= (1 << CAP_NET_BIND_SERVICE);
  }
  cap_data.effective = cap_data.permitted = cap_mask;
  cap_data.inheritable = 0;
  retval = capset(&cap_head, &cap_data);
  if (retval != 0)
  {
    die("capset");
  }
}

#endif /* VSF_SYSDEP_HAVE_CAPABILITIES */

int
vsf_sysutil_sendfile(const int out_fd, const int in_fd,
                     unsigned long* p_offset, unsigned long num_send,
                     unsigned int max_chunk)
{
  /* Grr - why is off_t signed? */
  long real_offset = *p_offset;
  if (real_offset < 0)
  {
    die("invalid offset in vsf_sysutil_sendfile");
  }
  while (num_send > 0)
  {
    int retval;
    unsigned int send_this_time;
    /* For 64-bit platforms */
    if (num_send > INT_MAX)
    {
      send_this_time = INT_MAX;
    }
    else
    {
      send_this_time = (unsigned int) num_send;
    }
    if (max_chunk != 0 && send_this_time > max_chunk)
    {
      send_this_time = max_chunk;
    }
    retval = do_sendfile(out_fd, in_fd, &real_offset, send_this_time);
    if (real_offset < 0)
    {
      die("invalid offset returned in vsf_sysutil_sendfile");
    }
    *p_offset = real_offset;
    if (vsf_sysutil_retval_is_error(retval) || retval == 0)
    {
      return retval;
    }
    num_send -= (unsigned long) retval;
  }
  return 0;
}

static int do_sendfile(const int out_fd, const int in_fd,
                       long* p_offset, unsigned int num_send)
{
  /* Probably should one day be shared with instance in ftpdataio.c */
  static char* p_recvbuf;
  unsigned int total_written = 0;
  int retval;
#if defined(VSF_SYSDEP_HAVE_LINUX_SENDFILE) || \
    defined(VSF_SYSDEP_HAVE_FREEBSD_SENDFILE) || \
    defined(VSF_SYSDEP_HAVE_HPUX_SENDFILE)
  {
    static int s_sendfile_checked;
    static int s_runtime_sendfile_works;
    if (!s_sendfile_checked || s_runtime_sendfile_works)
    {
      do
      {
  #ifdef VSF_SYSDEP_HAVE_LINUX_SENDFILE
        retval = sendfile(out_fd, in_fd, p_offset, num_send);
  #elif defined(VSF_SYSDEP_HAVE_FREEBSD_SENDFILE)
        {
          off_t written = 0;
          retval = sendfile(in_fd, out_fd, *p_offset, num_send, NULL,
                            &written, 0);
          /* Translate to Linux-like retval */
          if (written > 0)
          {
            retval = (int) written;
            *p_offset += retval;
          }
        }
  #else /* must be VSF_SYSDEP_HAVE_HPUX_SENDFILE */
        {
          retval = sendfile(out_fd, in_fd, *p_offset, num_send, NULL, 0);
          /* Translate to Linux-like retval */
          if (retval > 0)
          {
            *p_offset += retval;
          }
        }
  #endif /* VSF_SYSDEP_HAVE_LINUX_SENDFILE */
        vsf_sysutil_check_pending_actions(kVSFSysUtilIO, retval, out_fd);
      }
      while (vsf_sysutil_retval_is_error(retval) &&
             vsf_sysutil_get_error() == kVSFSysUtilErrINTR);
      if (!s_sendfile_checked)
      {
        s_sendfile_checked = 1;
        if (!vsf_sysutil_retval_is_error(retval) ||
            vsf_sysutil_get_error() != kVSFSysUtilErrNOSYS)
        {
          s_runtime_sendfile_works = 1;
        }
      }
      if (s_runtime_sendfile_works)
      {
        return retval;
      }
      /* Fall thru to normal implementation. We won't check again. */
    }
  }
#endif /* VSF_SYSDEP_HAVE_LINUX_SENDFILE || VSF_SYSDEP_HAVE_FREEBSD_SENDFILE */
  if (p_recvbuf == 0)
  {
    vsf_secbuf_alloc(&p_recvbuf, VSFTP_DATA_BUFSIZE);
  }
  while (1)
  {
    unsigned int num_read;
    unsigned int num_written;
    unsigned int num_read_this_time = VSFTP_DATA_BUFSIZE;
    if (num_read_this_time > num_send)
    {
      num_read_this_time = num_send;
    }
    retval = vsf_sysutil_read(in_fd, p_recvbuf, num_read_this_time);
    if (retval < 0)
    {
      return retval;
    }
    else if (retval == 0)
    {
      return -1;
    }
    num_read = (unsigned int) retval;
    *p_offset += num_read;
    retval = vsf_sysutil_write_loop(out_fd, p_recvbuf, num_read);
    if (retval < 0)
    {
      return retval;
    }
    num_written = (unsigned int) retval;
    total_written += num_written;
    if (num_written != num_read)
    {
      return -1;
    }
    if (num_written > num_send)
    {
      bug("num_written bigger than num_send in do_sendfile");
    }
    num_send -= num_written;
    if (num_send == 0)
    {
      /* Bingo! */
      return total_written;
    }
  }
}

void
vsf_sysutil_set_proctitle_prefix(const struct mystr* p_str)
{
  str_copy(&s_proctitle_prefix_str, p_str);
}

/* This delegation is common to all setproctitle() implementations */
void
vsf_sysutil_setproctitle_str(const struct mystr* p_str)
{
  vsf_sysutil_setproctitle(str_getbuf(p_str));
}

void
vsf_sysutil_setproctitle(const char* p_text)
{
  struct mystr proctitle_str = INIT_MYSTR;
  str_copy(&proctitle_str, &s_proctitle_prefix_str);
  if (!str_isempty(&proctitle_str))
  {
    str_append_text(&proctitle_str, ": ");
  }
  str_append_text(&proctitle_str, p_text);
  vsf_sysutil_setproctitle_internal(str_getbuf(&proctitle_str));
  str_free(&proctitle_str);
}

#ifdef VSF_SYSDEP_HAVE_SETPROCTITLE
void
vsf_sysutil_setproctitle_init(int argc, const char* argv[])
{
  (void) argc;
  (void) argv;
}

void
vsf_sysutil_setproctitle_internal(const char* p_buf)
{
  setproctitle("%s", p_buf);
}
#elif defined(VSF_SYSDEP_HAVE_HPUX_SETPROCTITLE)
void
vsf_sysutil_setproctitle_init(int argc, const char* argv[])
{
  (void) argc;
  (void) argv;
}

void
vsf_sysutil_setproctitle_internal(const char* p_buf)
{
  struct mystr proctitle_str = INIT_MYSTR;
  union pstun p;
  str_alloc_text(&proctitle_str, "vsftpd: ");
  str_append_text(&proctitle_str, p_buf);
  p.pst_command = str_getbuf(&proctitle_str);
  pstat(PSTAT_SETCMD, p, 0, 0, 0);
  str_free(&proctitle_str);
}
#elif defined(VSF_SYSDEP_TRY_LINUX_SETPROCTITLE_HACK)
void
vsf_sysutil_setproctitle_init(int argc, const char* argv[])
{
  int i;
  char** p_env = environ;
  if (s_proctitle_inited)
  {
    bug("vsf_sysutil_setproctitle_init called twice");
  }
  s_proctitle_inited = 1;
  if (argv[0] == 0)
  {
    die("no argv[0] in vsf_sysutil_setproctitle_init");
  }
  for (i=0; i<argc; i++)
  {
    s_proctitle_space += vsf_sysutil_strlen(argv[i]) + 1;
    if (i > 0)
    {
      argv[i] = 0;
    }
  }
  while (*p_env != 0)
  {
    s_proctitle_space += vsf_sysutil_strlen(*p_env) + 1;
    p_env++;
  }
  /* Oops :-) */
  environ = 0;
  s_p_proctitle = (char*) argv[0];
  vsf_sysutil_memclr(s_p_proctitle, s_proctitle_space);
}

void
vsf_sysutil_setproctitle_internal(const char* p_buf)
{
  struct mystr proctitle_str = INIT_MYSTR;
  unsigned int to_copy;
  if (!s_proctitle_inited)
  {
    bug("vsf_sysutil_setproctitle: not initialized");
  }
  vsf_sysutil_memclr(s_p_proctitle, s_proctitle_space);
  if (s_proctitle_space < 32)
  {
    return;
  }
  str_alloc_text(&proctitle_str, "vsftpd: ");
  str_append_text(&proctitle_str, p_buf);
  to_copy = str_getlen(&proctitle_str);
  if (to_copy > s_proctitle_space - 1)
  {
    to_copy = s_proctitle_space - 1;
  }
  vsf_sysutil_memcpy(s_p_proctitle, str_getbuf(&proctitle_str), to_copy);
  str_free(&proctitle_str);
  s_p_proctitle[to_copy] = '\0';
}
#else /* VSF_SYSDEP_HAVE_SETPROCTITLE */
void
vsf_sysutil_setproctitle_init(int argc, const char* argv[])
{
  (void) argc;
  (void) argv;
}

void
vsf_sysutil_setproctitle_internal(const char* p_buf)
{
  (void) p_buf;
}
#endif /* VSF_SYSDEP_HAVE_SETPROCTITLE */

#ifdef VSF_SYSDEP_HAVE_MAP_ANON
void
vsf_sysutil_map_anon_pages_init(void)
{
}

void*
vsf_sysutil_map_anon_pages(unsigned int length)
{
  char* retval = mmap(0, length, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
  if (retval == MAP_FAILED)
  {
    die("mmap");
  }
  return retval;
}
#else /* VSF_SYSDEP_HAVE_MAP_ANON */
void
vsf_sysutil_map_anon_pages_init(void)
{
  if (s_zero_fd != -1)
  {
    bug("vsf_sysutil_map_anon_pages_init called twice");
  }
  s_zero_fd = open("/dev/zero", O_RDWR);
  if (s_zero_fd < 0)
  {
    die("could not open /dev/zero");
  }
}

void*
vsf_sysutil_map_anon_pages(unsigned int length)
{
  char* retval = mmap(0, length, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE, s_zero_fd, 0);
  if (retval == MAP_FAILED)
  {
    die("mmap");
  }
  return retval;
}
#endif /* VSF_SYSDEP_HAVE_MAP_ANON */

#ifndef VSF_SYSDEP_NEED_OLD_FD_PASSING

void
vsf_sysutil_send_fd(int sock_fd, int send_fd)
{
  int retval;
  struct msghdr msg;
  struct cmsghdr* p_cmsg;
  struct iovec vec;
  char cmsgbuf[CMSG_SPACE(sizeof(send_fd))];
  int* p_fds;
  char sendchar = 0;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  p_cmsg = CMSG_FIRSTHDR(&msg);
  p_cmsg->cmsg_level = SOL_SOCKET;
  p_cmsg->cmsg_type = SCM_RIGHTS;
  p_cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));
  p_fds = (int*)CMSG_DATA(p_cmsg);
  *p_fds = send_fd;
  msg.msg_controllen = p_cmsg->cmsg_len;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  /* "To pass file descriptors or credentials you need to send/read at
   * least on byte" (man 7 unix)
   */
  vec.iov_base = &sendchar;
  vec.iov_len = sizeof(sendchar);
  retval = sendmsg(sock_fd, &msg, 0);
  if (retval != 1)
  {
    die("sendmsg");
  }
}

int
vsf_sysutil_recv_fd(const int sock_fd)
{
  int retval;
  struct msghdr msg;
  char recvchar;
  struct iovec vec;
  int recv_fd;
  char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
  struct cmsghdr* p_cmsg;
  int* p_fd;
  vec.iov_base = &recvchar;
  vec.iov_len = sizeof(recvchar);
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_flags = 0;
  /* In case something goes wrong, set the fd to -1 before the syscall */
  p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
  *p_fd = -1;  
  retval = recvmsg(sock_fd, &msg, 0);
  if (retval != 1)
  {
    die("recvmsg");
  }
  p_cmsg = CMSG_FIRSTHDR(&msg);
  if (p_cmsg == NULL)
  {
    die("no passed fd");
  }
  /* We used to verify the returned cmsg_level, cmsg_type and cmsg_len here,
   * but Linux 2.0 totally uselessly fails to fill these in.
   */
  p_fd = (int*)CMSG_DATA(p_cmsg);
  recv_fd = *p_fd;
  if (recv_fd == -1)
  {
    die("no passed fd");
  }
  return recv_fd;
}

#else /* !VSF_SYSDEP_NEED_OLD_FD_PASSING */

void
vsf_sysutil_send_fd(int sock_fd, int send_fd)
{
  int retval;
  char send_char = 0;
  struct msghdr msg;
  struct iovec vec;
  vec.iov_base = &send_char;
  vec.iov_len = 1;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_accrights = (caddr_t) &send_fd;
  msg.msg_accrightslen = sizeof(send_fd);
  retval = sendmsg(sock_fd, &msg, 0);
  if (retval != 1)
  {
    die("sendmsg");
  }
}

int
vsf_sysutil_recv_fd(int sock_fd)
{
  int retval;
  struct msghdr msg;
  struct iovec vec;
  char recv_char;
  int recv_fd = -1;
  vec.iov_base = &recv_char;
  vec.iov_len = 1;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;
  msg.msg_accrights = (caddr_t) &recv_fd;
  msg.msg_accrightslen = sizeof(recv_fd);
  retval = recvmsg(sock_fd, &msg, 0);
  if (retval != 1)
  {
    die("recvmsg");
  }
  if (recv_fd == -1)
  {
    die("no passed fd");
  }
  return recv_fd;
}

#endif /* !VSF_SYSDEP_NEED_OLD_FD_PASSING */


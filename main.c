/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * main.c
 */

#include "session.h"
#include "utility.h"
#include "tunables.h"
#include "logging.h"
#include "str.h"
#include "filestr.h"
#include "ftpcmdio.h"
#include "sysutil.h"
#include "sysdeputil.h"
#include "defs.h"
#include "parseconf.h"
#include "oneprocess.h"
#include "twoprocess.h"
#include "standalone.h"

/*
 * Forward decls of helper functions
 */
static void die_unless_privileged(void);
static void do_sanity_checks(void);
static void session_init(struct vsf_session* p_sess);
static void env_init(void);

int
main(int argc, const char* argv[])
{
  struct vsf_session the_session =
  {
    /* Control connection */
    0, 0,
    /* Data connection */
    -1, 0, -1, 0, 0, 0, 0,
    /* Login */
    1, INIT_MYSTR, INIT_MYSTR,
    /* Protocol state */
    0, 1, INIT_MYSTR, 0,
    /* Session state */
    0,
    /* Userids */
    -1, -1,
    /* Pre-chroot() cache */
    INIT_MYSTR, INIT_MYSTR, INIT_MYSTR,
    /* Logging */
    -1, INIT_MYSTR, 0, 0, 0, INIT_MYSTR, 0,
    /* Buffers */
    INIT_MYSTR, INIT_MYSTR,
    /* Parent <-> child comms */
    0, -1, -1,
    /* Number of clients */
    -1
  };
  int config_specified = 0;
  const char* p_config_name = VSFTP_DEFAULT_CONFIG;
  /* Zero or one argument supported. If one argument is passed, it is the
   * path to the config file
   */
  if (argc > 2)
  {
    die("vsftpd: too many arguments (I take an optional config file only)");
  }
  else if (argc == 0)
  {
    die("vsftpd: missing argv[0]");
  }
  if (argc == 2)
  {
    p_config_name = argv[1];
    config_specified = 1;
  }
  /* Just get out unless we start with requisite privilege */
  die_unless_privileged();
  /* This might need to open /dev/zero on systems lacking MAP_ANON. Needs
   * to be done early (i.e. before config file parse, which may use
   * anonymous pages
   */
  vsf_sysutil_map_anon_pages_init();
  /* Parse config file if it's there */
  {
    struct vsf_sysutil_statbuf* p_statbuf = 0;
    int retval = vsf_sysutil_stat(p_config_name, &p_statbuf);
    if (!vsf_sysutil_retval_is_error(retval))
    {
      vsf_parseconf_load_file(p_config_name);
    }
    else if (config_specified)
    {
      die("vsftpd: cannot open specified config file");
    }
    vsf_sysutil_free(p_statbuf);
  }
  if (tunable_setproctitle_enable)
  {
    /* Warning -- warning -- may nuke argv, environ */
    vsf_sysutil_setproctitle_init(argc, argv);
  }
  if (tunable_listen)
  {
    /* Standalone mode */
    the_session.num_clients = vsf_standalone_main();
  }
  /* Sanity checks - exit with a graceful error message if our STDIN is not
   * a socket. Also check various config options don't collide.
   */
  do_sanity_checks();
  /* Initializes session globals - e.g. IP addr's etc. */
  session_init(&the_session);
  /* Set up "environment", e.g. process group etc. */
  env_init();
  /* Set up logging - must come after global init because we need the remote
   * address to convert into text
   */
  vsf_log_init(&the_session);
  str_alloc_text(&the_session.remote_ip_str,
                 vsf_sysutil_inet_ntoa(the_session.p_remote_addr));
  /* Set up options on the command socket */
  vsf_cmdio_sock_setup();
  if (tunable_setproctitle_enable)
  {
    vsf_sysutil_set_proctitle_prefix(&the_session.remote_ip_str);
    vsf_sysutil_setproctitle("connected");
  }
  /* We might chroot() very soon (one process model), so we need to open
   * any required config files here.
   */
  if (tunable_deny_email_enable)
  {
    int retval = str_fileread(&the_session.banned_email_str,
                              tunable_banned_email_file, VSFTP_CONF_FILE_MAX);
    if (vsf_sysutil_retval_is_error(retval))
    {
      die("cannot open banned e-mail list file");
    }
  }
  if (tunable_banner_file)
  {
    int retval = str_fileread(&the_session.banner_str, tunable_banner_file,
                              VSFTP_CONF_FILE_MAX);
    if (vsf_sysutil_retval_is_error(retval))
    {
      die("cannot open banner file");
    }
  }
  /* Special case - can force one process model if we've got a setup
   * needing _no_ privs
   */
  if (!tunable_local_enable && !tunable_connect_from_port_20 &&
      !tunable_chown_uploads)
  {
    tunable_one_process_model = 1;
  }
  if (tunable_one_process_model)
  {
    vsf_one_process_start(&the_session);
  }
  else
  {
    vsf_two_process_start(&the_session);
  }
  /* NOTREACHED */
  bug("should not get here: main");
  return 1;
}

static void
die_unless_privileged(void)
{
  if (!vsf_sysutil_running_as_root())
  {
    die("vsftpd: must be started as root");
  }
}

static void
do_sanity_checks(void)
{
  {
    struct vsf_sysutil_statbuf* p_statbuf = 0;
    vsf_sysutil_fstat(VSFTP_COMMAND_FD, &p_statbuf);
    if (!vsf_sysutil_statbuf_is_socket(p_statbuf))
    {
      die("vsftpd: does not run standalone, must be started from inetd");
    }
    vsf_sysutil_free(p_statbuf);
  }
  if (tunable_one_process_model)
  {
    if (tunable_local_enable)
    {
      die("vsftpd: security: 'one_process_model' is anonymous only");
    }
    if (!vsf_sysdep_has_capabilities_as_non_root())
    {
      die("vsftpd: security: 'one_process_model' needs a better OS");
    }
  }
  if (!tunable_local_enable && !tunable_anonymous_enable)
  {
    die("vsftpd: both local and anonymous access disabled!");
  }
}

static void
env_init(void)
{
  vsf_sysutil_make_session_leader();
  /* Set up a secure umask - we'll set the proper one after login */
  vsf_sysutil_set_umask(VSFTP_SECURE_UMASK);
  /* Fire up libc's timezone initialisation, before we chroot()! */
  vsf_sysutil_tzset();
  /* Signals. We'll always take -EPIPE rather than a rude signal, thanks */
  vsf_sysutil_install_null_sighandler(kVSFSysUtilSigPIPE);
}

static void
session_init(struct vsf_session* p_sess)
{
  /* Get the addresses of the control connection */
  vsf_sysutil_getpeername(VSFTP_COMMAND_FD, &p_sess->p_remote_addr);
  vsf_sysutil_getsockname(VSFTP_COMMAND_FD, &p_sess->p_local_addr);
  /* If anonymous mode is active, fetch the uid of the anonymous user */
  if (tunable_anonymous_enable)
  {
    const struct vsf_sysutil_user* p_user =
      vsf_sysutil_getpwnam(tunable_ftp_username);
    if (p_user == 0)
    {
      die("vsftpd: cannot locate user specified in 'ftp_username'");
    }
    p_sess->anon_ftp_uid = vsf_sysutil_user_getuid(p_user);

    if (tunable_chown_uploads)
    {
      p_user = vsf_sysutil_getpwnam(tunable_chown_username);
      if (p_user == 0)
      {
        die("vsftpd: cannot locate user specified in 'chown_username'");
      }
      p_sess->anon_upload_chown_uid = vsf_sysutil_user_getuid(p_user);
    }
  }
}


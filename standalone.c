/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * standalone.c
 *
 * Code to listen on the network and launch children servants.
 */

#include "standalone.h"

#include "parseconf.h"
#include "tunables.h"
#include "sysutil.h"
#include "sysdeputil.h"
#include "utility.h"
#include "defs.h"

static int s_reload_needed;
static int s_children;

static void handle_sigchld(int duff);
static void handle_sighup(int duff);
static void do_reload(void);
static void prepare_child(int sockfd);

int
vsf_standalone_main(void)
{
  struct vsf_sysutil_sockaddr* p_sockaddr = 0;
  struct vsf_sysutil_ipv4addr listen_ipaddr;
  int listen_sock = vsf_sysutil_get_ipv4_sock();
  int retval;

  if (tunable_setproctitle_enable)
  {
    vsf_sysutil_setproctitle("LISTENER");
  }
  vsf_sysutil_install_async_sighandler(kVSFSysUtilSigCHLD, handle_sigchld);
  vsf_sysutil_install_async_sighandler(kVSFSysUtilSigHUP, handle_sighup);

  vsf_sysutil_activate_reuseaddr(listen_sock);
  vsf_sysutil_sockaddr_alloc_ipv4(&p_sockaddr);
  vsf_sysutil_sockaddr_set_port(
      p_sockaddr, vsf_sysutil_ipv4port_from_int(tunable_listen_port));
  if (!tunable_listen_address ||
      vsf_sysutil_inet_aton(tunable_listen_address, &listen_ipaddr) == 0)
  {
    listen_ipaddr = vsf_sysutil_sockaddr_get_any();
  }
  vsf_sysutil_sockaddr_set_ipaddr(p_sockaddr, listen_ipaddr);
  retval = vsf_sysutil_bind(listen_sock, p_sockaddr);
  
  vsf_sysutil_free(p_sockaddr);

  if (vsf_sysutil_retval_is_error(retval))
  {
    die("could not bind listening socket");
  }
  vsf_sysutil_listen(listen_sock, VSFTP_LISTEN_BACKLOG);

  while (1)
  {
    int new_child;
    int new_client_sock = vsf_sysutil_accept_timeout(listen_sock, 0, 0);
    if (s_reload_needed)
    {
      s_reload_needed = 0;
      do_reload();
    }
    if (vsf_sysutil_retval_is_error(new_client_sock))
    {
      if (vsf_sysutil_get_error() == kVSFSysUtilErrINTR)
      {
        continue;
      }
      die("accept");
    }
    ++s_children;
    new_child = vsf_sysutil_fork();
    if (new_child)
    {
      /* Parent context */
      vsf_sysutil_close(new_client_sock);
      /* Fall through to while() loop and accept() again */
    }
    else
    {
      /* Child context */
      vsf_sysutil_close(listen_sock);
      prepare_child(new_client_sock);
      /* By returning here we "launch" the child process with the same
       * contract as xinetd would provide.
       */
      return s_children;
    }
  }
}

static void
prepare_child(int new_client_sock)
{
  /* We must satisfy the contract: command socket on fd 0, 1, 2 */
  vsf_sysutil_dupfd2(new_client_sock, 0);
  vsf_sysutil_dupfd2(new_client_sock, 1);
  vsf_sysutil_dupfd2(new_client_sock, 2);
  if (new_client_sock > 2)
  {
    vsf_sysutil_close(new_client_sock);
  }
}
 
static void
handle_sigchld(int duff)
{
  /* WARNING - async handler. Must not call anything which might have
   * re-entrancy issues
   */
  int reap_one = 1;
  (void) duff;
  while (reap_one)
  {
    reap_one = vsf_sysutil_wait_reap_one();
    if (reap_one)
    {
      --s_children;
    }
  }
}

static void
handle_sighup(int duff)
{
  /* WARNING - async handler. Must not call anything which might have
   * re-entrancy issues
   */
  (void) duff;
  s_reload_needed = 1;
}

static void
do_reload(void)
{
  vsf_parseconf_load_file(0);
}


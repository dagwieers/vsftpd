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
#include "hash.h"

static int s_reload_needed;
static unsigned int s_children;
static struct hash* s_p_ip_count_hash;
static struct hash* s_p_pid_ip_hash;

static void handle_sigchld(void* p_private);
static void handle_sighup(int duff);
static void do_reload(void);
static void prepare_child(int sockfd);
static unsigned int handle_ip_count(
    struct vsf_sysutil_ipv4addr* p_accept_addr);
static void drop_ip_count(struct vsf_sysutil_ipv4addr* p_ip);

static unsigned int hash_ip(unsigned int buckets, void* p_key);
static unsigned int hash_pid(unsigned int buckets, void* p_key);

struct vsf_client_launch
vsf_standalone_main(void)
{
  struct vsf_sysutil_sockaddr* p_sockaddr = 0;
  struct vsf_sysutil_ipv4addr listen_ipaddr;
  int listen_sock = vsf_sysutil_get_ipv4_sock();
  int retval;
  s_p_ip_count_hash = hash_alloc(256, sizeof(struct vsf_sysutil_ipv4addr),
                                 sizeof(unsigned int), hash_ip);
  s_p_pid_ip_hash = hash_alloc(256, sizeof(int),
                               sizeof(struct vsf_sysutil_ipv4addr), hash_pid);
  if (tunable_setproctitle_enable)
  {
    vsf_sysutil_setproctitle("LISTENER");
  }
  vsf_sysutil_install_sighandler(kVSFSysUtilSigCHLD, handle_sigchld, 0);
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
    struct vsf_client_launch child_info;
    static struct vsf_sysutil_sockaddr* p_accept_addr;
    int new_child;
    struct vsf_sysutil_ipv4addr ip_addr;
    /* NOTE - wake up every 10 seconds to make sure we notice child exit
     * in a timely manner (the sync signal framework race)
     */
    int new_client_sock = vsf_sysutil_accept_timeout(
        listen_sock, &p_accept_addr, 10);
    if (s_reload_needed)
    {
      s_reload_needed = 0;
      do_reload();
    }
    if (vsf_sysutil_retval_is_error(new_client_sock))
    {
      continue;
    }
    ip_addr = vsf_sysutil_sockaddr_get_ipaddr(p_accept_addr);
    ++s_children;
    child_info.num_children = s_children;
    child_info.num_this_ip = handle_ip_count(&ip_addr);
    new_child = vsf_sysutil_fork_failok();
    if (new_child != 0)
    {
      /* Parent context */
      vsf_sysutil_close(new_client_sock);
      if (new_child > 0)
      {
        hash_add_entry(s_p_pid_ip_hash, (void*)&new_child, (void*)&ip_addr);
      }
      else
      {
        /* fork() failed, clear up! */
        --s_children;
        drop_ip_count(&ip_addr);
      }
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
      return child_info;
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
drop_ip_count(struct vsf_sysutil_ipv4addr* p_ip)
{
  unsigned int count;
  unsigned int* p_count =
    (unsigned int*)hash_lookup_entry(s_p_ip_count_hash, (void*)p_ip);
  if (!p_count)
  {
    bug("IP address missing from hash");
  }
  count = *p_count;
  if (!count)
  {
    bug("zero count for IP address");
  }
  count--;
  *p_count = count;
  if (!count)
  {
    hash_free_entry(s_p_ip_count_hash, (void*)p_ip);
  }
}

static void
handle_sigchld(void* p_private)
{
  unsigned int reap_one = 1;
  (void) p_private;
  while (reap_one)
  {
    reap_one = (unsigned int)vsf_sysutil_wait_reap_one();
    if (reap_one)
    {
      struct vsf_sysutil_ipv4addr* p_ip;
      /* Account total number of instances */
      --s_children;
      /* Account per-IP limit */
      p_ip = (struct vsf_sysutil_ipv4addr*)
        hash_lookup_entry(s_p_pid_ip_hash, (void*)&reap_one);
      drop_ip_count(p_ip);      
      hash_free_entry(s_p_pid_ip_hash, (void*)&reap_one);
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

static unsigned int
hash_ip(unsigned int buckets, void* p_key)
{
  struct vsf_sysutil_ipv4addr* p_addr = (struct vsf_sysutil_ipv4addr*)p_key;
  unsigned int val = p_addr->data[0] << 24;
  val |= p_addr->data[1] << 16;
  val |= p_addr->data[2] << 8;
  val |= p_addr->data[3];
  return val % buckets;
}

static unsigned int
hash_pid(unsigned int buckets, void* p_key)
{
  unsigned int* p_pid = (unsigned int*)p_key;
  return (*p_pid) % buckets;
}

static unsigned int
handle_ip_count(struct vsf_sysutil_ipv4addr* p_accept_addr)
{
  unsigned int* p_count =
    (unsigned int*)hash_lookup_entry(s_p_ip_count_hash, (void*)p_accept_addr);
  unsigned int count;
  if (!p_count)
  {
    count = 1;
    hash_add_entry(s_p_ip_count_hash, (void*)p_accept_addr, (void*)&count);
  }
  else
  {
    count = *p_count;
    count++;
    *p_count = count;
  }
  return count;
}


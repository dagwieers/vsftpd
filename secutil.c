/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * secutil.c
 */

#include "secutil.h"
#include "str.h"
#include "sysutil.h"
#include "sysstr.h"
#include "utility.h"
#include "sysdeputil.h"

void
vsf_secutil_change_credentials(const struct mystr* p_user_str,
                               const struct mystr* p_dir_str,
                               int do_chroot,
                               int activate_supplementary_groups,
                               unsigned int caps)
{
  struct vsf_sysutil_user* p_user;
  if (!vsf_sysutil_running_as_root())
  {
    bug("vsf_secutil_change_credentials: not running as root");
  }
  p_user = str_getpwnam(p_user_str);
  if (p_user == 0)
  {
    die("str_getpwnam");
  }
  {
    struct mystr dir_str = INIT_MYSTR;
    /* Work out where the chroot() jail is */
    if (p_dir_str == 0)
    {
      str_alloc_text(&dir_str, vsf_sysutil_user_get_homedir(p_user));
    }
    else
    {
      str_copy(&dir_str, p_dir_str);
    }
    /* Sort out supplementary groups before the chroot(). We need to access
     * /etc/groups
     */
    if (activate_supplementary_groups)
    {
      vsf_sysutil_initgroups(p_user);
    }
    else
    {
      vsf_sysutil_clear_supp_groups();
    }

    /* Always do the chdir() regardless of whether we are chroot()'ing */
    {
      int retval = str_chdir(&dir_str);
      if (retval != 0)
      {
        die("chdir");
      }
      /* Do the chroot() if required */
      if (do_chroot)
      {
        vsf_sysutil_chroot(".");
      }
    }
    str_free(&dir_str);
  }
  /* Handle capabilities */
  if (caps)
  {
    if (!vsf_sysdep_has_capabilities())
    {
      /* Need privilege but OS has no capabilities - have to keep root */
      return;
    }
    if (!vsf_sysdep_has_capabilities_as_non_root())
    {
      vsf_sysdep_adopt_capabilities(caps);
      return;
    }
    vsf_sysdep_keep_capabilities();
  }
  /* Set group id */
  vsf_sysutil_setgid(p_user);
  /* Finally set user id */
  vsf_sysutil_setuid(p_user);
  if (caps)
  {
    vsf_sysdep_adopt_capabilities(caps);
  }
}


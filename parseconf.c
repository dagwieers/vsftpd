/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * parseconf.c
 *
 * Routines and support to load in a file full of tunable variables and
 * settings, populating corresponding runtime variables.
 */

#include "parseconf.h"
#include "tunables.h"
#include "str.h"
#include "filestr.h"
#include "defs.h"
#include "sysutil.h"
#include "utility.h"

/* File local functions */
static void handle_config_setting(struct mystr* p_setting_str,
                                  struct mystr* p_value_str);

/* Tables mapping setting names to runtime variables */
/* Boolean settings */
static struct parseconf_bool_setting
{
  const char* p_setting_name;
  int* p_variable;
}
parseconf_bool_array[] =
{
  { "anonymous_enable", &tunable_anonymous_enable },
  { "local_enable", &tunable_local_enable },
  { "pasv_enable", &tunable_pasv_enable },
  { "port_enable", &tunable_port_enable },
  { "chroot_local_user", &tunable_chroot_local_user },
  { "write_enable", &tunable_write_enable },
  { "anon_upload_enable", &tunable_anon_upload_enable },
  { "anon_mkdir_write_enable", &tunable_anon_mkdir_write_enable },
  { "anon_other_write_enable", &tunable_anon_other_write_enable },
  { "chown_uploads", &tunable_chown_uploads },
  { "connect_from_port_20", &tunable_connect_from_port_20 },
  { "xferlog_enable", &tunable_xferlog_enable },
  { "dirmessage_enable", &tunable_dirmessage_enable },
  { "anon_world_readable_only", &tunable_anon_world_readable_only },
  { "async_abor_enable", &tunable_async_abor_enable },
  { "ascii_upload_enable", &tunable_ascii_upload_enable },
  { "ascii_download_enable", &tunable_ascii_download_enable },
  { "one_process_model", &tunable_one_process_model },
  { "xferlog_std_format", &tunable_xferlog_std_format },
  { "pasv_promiscuous", &tunable_pasv_promiscuous },
  { "deny_email_enable", &tunable_deny_email_enable },
  { "chroot_list_enable", &tunable_chroot_list_enable },
  { "setproctitle_enable", &tunable_setproctitle_enable },
  { "text_userdb_names", &tunable_text_userdb_names },
  { "ls_recurse_enable", &tunable_ls_recurse_enable },
  { "log_ftp_protocol", &tunable_log_ftp_protocol },
  { "guest_enable", &tunable_guest_enable },
  { "userlist_enable", &tunable_userlist_enable },
  { "userlist_deny", &tunable_userlist_deny },
  { 0, 0 }
};

static struct parseconf_uint_setting
{
  const char* p_setting_name;
  unsigned int* p_variable;
}
parseconf_uint_array[] =
{
  { "accept_timeout", &tunable_accept_timeout },
  { "connect_timeout", &tunable_connect_timeout },
  { "local_umask", &tunable_local_umask },
  { "anon_umask", &tunable_anon_umask },
  { "ftp_data_port", &tunable_ftp_data_port },
  { "idle_session_timeout", &tunable_idle_session_timeout },
  { "data_connection_timeout", &tunable_data_connection_timeout },
  { "pasv_min_port", &tunable_pasv_min_port },
  { "pasv_max_port", &tunable_pasv_max_port },
  { "anon_max_rate", &tunable_anon_max_rate },
  { "local_max_rate", &tunable_local_max_rate },
  { 0, 0 }
};

static struct parseconf_str_setting
{
  const char* p_setting_name;
  const char** p_variable;
}
parseconf_str_array[] =
{
  { "secure_chroot_dir", &tunable_secure_chroot_dir },
  { "ftp_username", &tunable_ftp_username },
  { "chown_username", &tunable_chown_username },
  { "xferlog_file", &tunable_xferlog_file },
  { "message_file", &tunable_message_file },
  { "nopriv_user", &tunable_nopriv_user },
  { "ftpd_banner", &tunable_ftpd_banner },
  { "banned_email_file", &tunable_banned_email_file },
  { "chroot_list_file", &tunable_chroot_list_file },
  { "pam_service_name", &tunable_pam_service_name },
  { "guest_username", &tunable_guest_username },
  { "userlist_file", &tunable_userlist_file },
  { 0, 0 }
};

void
vsf_parseconf_load_file(const char* p_filename)
{
  struct mystr config_file_str = INIT_MYSTR;
  struct mystr config_setting_str = INIT_MYSTR;
  struct mystr config_value_str = INIT_MYSTR;
  unsigned int str_pos = 0;
  int retval = str_fileread(&config_file_str, p_filename, VSFTP_CONF_FILE_MAX);
  if (vsf_sysutil_retval_is_error(retval))
  {
    die("cannot open config file");
  }
  while (str_getline(&config_file_str, &config_setting_str, &str_pos))
  {
    if (str_isempty(&config_setting_str) ||
        str_get_char_at(&config_setting_str, 0) == '#')
    {
      continue;
    }
    /* Split into name=value pair */
    str_split_char(&config_setting_str, &config_value_str, '=');
    handle_config_setting(&config_setting_str, &config_value_str);
  }
  str_free(&config_file_str);
  str_free(&config_setting_str);
  str_free(&config_value_str);
}

static void
handle_config_setting(struct mystr* p_setting_str, struct mystr* p_value_str)
{
  if (str_isempty(p_value_str))
  {
    die("missing value in config file");
  }
  /* Is it a boolean value? */
  {
    const struct parseconf_bool_setting* p_bool_setting = parseconf_bool_array;
    while (p_bool_setting->p_setting_name != 0)
    {
      if (str_equal_text(p_setting_str, p_bool_setting->p_setting_name))
      {
        /* Got it */
        str_upper(p_value_str);
        if (str_equal_text(p_value_str, "YES") ||
            str_equal_text(p_value_str, "TRUE") ||
            str_equal_text(p_value_str, "1"))
        {
          *(p_bool_setting->p_variable) = 1;
        }
        else if (str_equal_text(p_value_str, "NO") ||
                 str_equal_text(p_value_str, "FALSE") ||
                 str_equal_text(p_value_str, "0"))
        {
          *(p_bool_setting->p_variable) = 0;
        }
        else
        {
          die("bad bool value in config file");
        }
        return;
      }
      p_bool_setting++;
    }
  }
  /* Is it an unsigned integer setting? */
  {
    const struct parseconf_uint_setting* p_uint_setting = parseconf_uint_array;
    while (p_uint_setting->p_setting_name != 0)
    {
      if (str_equal_text(p_setting_str, p_uint_setting->p_setting_name))
      {
        /* Got it */
        /* If the value starts with 0, assume it's an octal value */
        if (!str_isempty(p_value_str) &&
            str_get_char_at(p_value_str, 0) == '0')
        {
          *(p_uint_setting->p_variable) = str_octal_to_uint(p_value_str);
        }
        else
        {
          *(p_uint_setting->p_variable) = str_atoi(p_value_str);
        }
        return;
      }
      p_uint_setting++;
    }
  }
  /* Is it a string setting? */
  {
    const struct parseconf_str_setting* p_str_setting = parseconf_str_array;
    while (p_str_setting->p_setting_name != 0)
    {
      if (str_equal_text(p_setting_str, p_str_setting->p_setting_name))
      {
        /* Got it */
        *(p_str_setting->p_variable) = str_strdup(p_value_str);
        return;
      }
      p_str_setting++;
    }
  }
  die("unrecognised variable in config file");
}


/*
 * Part of Very Secure FTPd
 * Licence: GPL
 * Author: Chris Evans
 * ls.c
 *
 * Would you believe, code to handle directory listing.
 */

#include "ls.h"
#include "str.h"
#include "strlist.h"
#include "sysstr.h"
#include "sysutil.h"
#include "tunables.h"

static int filename_passes_filter(const struct mystr* p_filename_str,
                                  const struct mystr* p_filter_str);
static void build_dir_line(struct mystr* p_str,
                           const struct mystr* p_filename_str,
                           const struct vsf_sysutil_statbuf* p_stat);

void
vsf_ls_populate_dir_list(struct mystr_list* p_list,
                         struct mystr_list* p_subdir_list,
                         struct vsf_sysutil_dir* p_dir,
                         const struct mystr* p_base_dir_str,
                         const struct mystr* p_option_str,
                         const struct mystr* p_filter_str,
                         int is_verbose)
{
  struct mystr dirline_str = INIT_MYSTR;
  struct mystr normalised_base_dir_str = INIT_MYSTR;
  struct str_locate_result loc_result;
  int a_option;
  int r_option;
  int t_option;
  int do_stat = 0;
  loc_result = str_locate_char(p_option_str, 'a');
  a_option = loc_result.found;
  loc_result = str_locate_char(p_option_str, 'r');
  r_option = loc_result.found;
  loc_result = str_locate_char(p_option_str, 't');
  t_option = loc_result.found;
  loc_result = str_locate_char(p_option_str, 'l');
  if (loc_result.found)
  {
    is_verbose = 1;
  }
  /* Invert "reverse" arg for "-t", the time sorting */
  if (t_option)
  {
    r_option = !r_option;
  }
  if (is_verbose || t_option || p_subdir_list != 0)
  {
    do_stat = 1;
  }
  /* "Normalise" the incoming base directory string by making sure it
   * ends in a '/' if it is nonempty
   */
  if (!str_equal_text(p_base_dir_str, "."))
  {
    str_copy(&normalised_base_dir_str, p_base_dir_str);
  }
  if (!str_isempty(&normalised_base_dir_str))
  {
    unsigned int len = str_getlen(&normalised_base_dir_str);
    if (str_get_char_at(&normalised_base_dir_str, len - 1) != '/')
    {
      str_append_char(&normalised_base_dir_str, '/');
    }
  }
  /* If we're going to need to do time comparisions, cache the local time */
  if (is_verbose)
  {
    vsf_sysutil_update_cached_time();
  }
  while (1)
  {
    static struct mystr s_next_filename_str;
    static struct mystr s_next_path_and_filename_str;
    static struct vsf_sysutil_statbuf* s_p_statbuf;
    str_next_dirent(&s_next_filename_str, p_dir);
    if (str_isempty(&s_next_filename_str))
    {
      break;
    }
    if (!a_option && str_getlen(&s_next_filename_str) > 0 &&
        str_get_char_at(&s_next_filename_str, 0) == '.')
    {
      continue;
    }
    /* If we have an ls option which is a filter, apply it */
    if (!str_isempty(p_filter_str))
    {
      if (!filename_passes_filter(&s_next_filename_str, p_filter_str))
      {
        continue;
      }
    }
    /* Calculate the full path (relative to CWD) for lstat() and
     * output purposes
     */
    str_copy(&s_next_path_and_filename_str, &normalised_base_dir_str);
    str_append_str(&s_next_path_and_filename_str, &s_next_filename_str);
    if (do_stat)
    {
      /* lstat() the file. Of course there's a race condition - the
       * directory entry may have gone away whilst we read it, so
       * ignore failure to stat
       */
      int retval = str_lstat(&s_next_path_and_filename_str, &s_p_statbuf);
      if (vsf_sysutil_retval_is_error(retval))
      {
        continue;
      }
    }
    if (is_verbose)
    {
      static struct mystr s_final_file_str;
      /* If it's a damn symlink, we need to append the target */
      str_copy(&s_final_file_str, &s_next_filename_str);
      if (vsf_sysutil_statbuf_is_symlink(s_p_statbuf))
      {
        static struct mystr s_temp_str;
        int retval = str_readlink(&s_temp_str, &s_next_path_and_filename_str);
        if (retval == 0 && !str_isempty(&s_temp_str))
        {
          str_append_text(&s_final_file_str, " -> ");
          str_append_str(&s_final_file_str, &s_temp_str);
        }
      }
      build_dir_line(&dirline_str, &s_final_file_str, s_p_statbuf);
    }
    else
    {
      /* Just emit the filenames - note, we prepend the directory for NLST
       * but not for LIST
       */
      str_copy(&dirline_str, &s_next_path_and_filename_str);
      str_append_text(&dirline_str, "\r\n");
    }
    /* Add filename into our sorted list - sorting by filename or time. Also,
     * if we are required to, maintain a distinct list of direct
     * subdirectories.
     */
    {
      static struct mystr s_temp_str;
      const struct mystr* p_sort_str = 0;
      const struct mystr* p_sort_subdir_str = 0;
      if (!t_option)
      {
        p_sort_str = &s_next_filename_str;
      }
      else
      {
        str_alloc_text(&s_temp_str,
                       vsf_sysutil_statbuf_get_sortkey_mtime(s_p_statbuf));
        p_sort_str = &s_temp_str;
        p_sort_subdir_str = &s_temp_str;
      }
      str_list_add(p_list, &dirline_str, p_sort_str);
      if (p_subdir_list != 0 && vsf_sysutil_statbuf_is_dir(s_p_statbuf))
      {
        str_list_add(p_subdir_list, &s_next_filename_str, p_sort_subdir_str);
      }
    }
  } /* END: while(1) */
  str_list_sort(p_list, r_option);
  if (p_subdir_list != 0)
  {
    str_list_sort(p_subdir_list, r_option);
  }
  str_free(&dirline_str);
  str_free(&normalised_base_dir_str);
}

static int
filename_passes_filter(const struct mystr* p_filename_str,
                       const struct mystr* p_filter_str)
{
  /* A simple routine to match a filename against a pattern.
   * This routine is used instead of e.g. fnmatch(3), because we should be
   * reluctant to trust the latter. fnmatch(3) involves _lots_ of string
   * parsing and handling. There is broad potential for any given fnmatch(3)
   * implementation to be buggy.
   *
   * Currently supported pattern(s):
   * - any number of wildcards, "*"
   */
  static struct mystr s_filter_remain_str;
  static struct mystr s_name_remain_str;
  static struct mystr s_temp_str;
  int last_was_wildcard = 1;
  int must_match_at_current_pos = 1;
  str_copy(&s_filter_remain_str, p_filter_str);
  str_copy(&s_name_remain_str, p_filename_str);

  while (!str_isempty(&s_filter_remain_str))
  {
    static struct mystr s_match_needed_str;
    /* Locate next wildcard */
    struct str_locate_result locate_result =
      str_locate_char(&s_filter_remain_str, '*');
    /* Isolate text leading up to wildcard (if any) - needs to be matched */
    if (locate_result.found)
    {
      unsigned int indexx = locate_result.index;
      str_left(&s_filter_remain_str, &s_match_needed_str, indexx);
      str_mid_to_end(&s_filter_remain_str, &s_temp_str, indexx + 1);
      str_copy(&s_filter_remain_str, &s_temp_str);
    }
    else
    {
      /* No more wildcards. Must match remaining filter string exactly. */
      str_copy(&s_match_needed_str, &s_filter_remain_str);
      str_empty(&s_filter_remain_str);
      last_was_wildcard = 0;
    }
    if (!str_isempty(&s_match_needed_str))
    {
      /* Need to match something.. could be a match which has to start at
       * current position, or we could allow it to start anywhere
       */
      unsigned int indexx;
      locate_result = str_locate_str(&s_name_remain_str, &s_match_needed_str);
      if (!locate_result.found)
      {
        /* Fail */
        return 0;
      }
      indexx = locate_result.index;
      if (must_match_at_current_pos && indexx > 0)
      {
        /* Fail */
        return 0;
      }
      /* Chop matched string out of remainder */
      str_mid_to_end(&s_name_remain_str, &s_temp_str,
                     indexx + str_getlen(&s_match_needed_str));
      str_copy(&s_name_remain_str, &s_temp_str);
    }
    /* Only the first iteration can require a match at current position -
     * subsequent iterations will have seen a '*'
     */
    must_match_at_current_pos = 0;
  }
  /* Any incoming string left means no match unless we ended on a wildcard */
  if (!last_was_wildcard && str_getlen(&s_name_remain_str) > 0)
  {
    return 0;
  }
  /* OK, a match */
  return 1;
}

static void
build_dir_line(struct mystr* p_str, const struct mystr* p_filename_str,
               const struct vsf_sysutil_statbuf* p_stat)
{
  static struct mystr s_tmp_str;
  filesize_t size = vsf_sysutil_statbuf_get_size(p_stat);
  /* Permissions */
  str_alloc_text(p_str, vsf_sysutil_statbuf_get_perms(p_stat));
  str_append_char(p_str, ' ');
  /* Hard link count */
  str_alloc_ulong(&s_tmp_str, vsf_sysutil_statbuf_get_links(p_stat));
  str_lpad(&s_tmp_str, 4);
  str_append_str(p_str, &s_tmp_str);
  str_append_char(p_str, ' ');
  /* User */
  if (tunable_hide_ids)
  {
    str_alloc_text(&s_tmp_str, "ftp");
  }
  else
  {
    int uid = vsf_sysutil_statbuf_get_uid(p_stat);
    struct vsf_sysutil_user* p_user = 0;
    if (tunable_text_userdb_names)
    {
      p_user = vsf_sysutil_getpwuid(uid);
    }
    if (p_user == 0)
    {
      str_alloc_ulong(&s_tmp_str, (unsigned long) uid);
    }
    else
    {
      str_alloc_text(&s_tmp_str, vsf_sysutil_user_getname(p_user));
    }
  }
  str_rpad(&s_tmp_str, 8);
  str_append_str(p_str, &s_tmp_str);
  str_append_char(p_str, ' ');
  /* Group */
  if (tunable_hide_ids)
  {
    str_alloc_text(&s_tmp_str, "ftp");
  }
  else
  {
    int gid = vsf_sysutil_statbuf_get_gid(p_stat);
    struct vsf_sysutil_group* p_group = 0;
    if (tunable_text_userdb_names)
    {
      p_group = vsf_sysutil_getgrgid(gid);
    }
    if (p_group == 0)
    {
      str_alloc_ulong(&s_tmp_str, (unsigned long) gid);
    }
    else
    {
      str_alloc_text(&s_tmp_str, vsf_sysutil_group_getname(p_group));
    }
  }
  str_rpad(&s_tmp_str, 8);
  str_append_str(p_str, &s_tmp_str);
  str_append_char(p_str, ' ');
  /* Size in bytes */
  str_alloc_filesize_t(&s_tmp_str, size);
  str_lpad(&s_tmp_str, 8);
  str_append_str(p_str, &s_tmp_str);
  str_append_char(p_str, ' ');
  /* Date stamp */
  str_append_text(p_str, vsf_sysutil_statbuf_get_date(p_stat,
                                                      tunable_use_localtime));
  str_append_char(p_str, ' ');
  /* Filename */
  str_append_str(p_str, p_filename_str);
  str_append_text(p_str, "\r\n");
}


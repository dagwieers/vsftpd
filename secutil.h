#ifndef VSF_SECUTIL_H
#define VSF_SECUTIL_H

struct mystr;

/* vsf_secutil_change_credentials()
 * PURPOSE
 * This function securely switches process credentials to the user specified.
 * There are options to enter a chroot() jail, and supplementary groups may
 * or may not be activated.
 * PARAMETERS
 * p_user_str     - the name of the user to become
 * p_dir_str      - the directory to chdir() and possibly chroot() to.
 *                  (if NULL, the user's home directory is used)
 * do_chroot      - if non-zero, chroot() the new user into the directory
 * activate_supplementary_groups -
 *                  if non-zero, activate any supplementary groups
 * caps           - bitmap of capabilities to adopt. NOTE, if the underlying
 *                  OS does not support capabilities as a non-root user, and
 *                  the capability bitset is non-empty, then root privileges
 *                  will have to be retained.
 */
void vsf_secutil_change_credentials(const struct mystr* p_user_str,
                                    const struct mystr* p_dir_str,
                                    int do_chroot,
                                    int activate_supplementary_groups,
                                    unsigned int caps);
#endif /* VSF_SECUTIL_H */


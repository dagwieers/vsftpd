#ifndef VSF_PARSECONF_H
#define VSF_PARSECONF_H

/* vsf_parseconf_load_file()
 * PURPOSE
 * Parse the given file as a vsftpd config file. If the file cannot be
 * opened for whatever reason, a fatal error is raised. If the file contains
 * any syntax errors, a fatal error is raised.
 * If the call returns (no fatal error raised), then the config file was
 * parsed and the global config settings will have been updated.
 * PARAMETERS
 * p_filename     - the name of the config file to parse
 */
void vsf_parseconf_load_file(const char* p_filename);

#endif /* VSF_PARSECONF_H */


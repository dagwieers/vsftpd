#ifndef VSF_TUNABLES_H
#define VSF_TUNABLES_H

/* Configurable preferences */
/* Booleans */
extern int tunable_anonymous_enable;          /* Allow anon logins */
extern int tunable_local_enable;              /* Allow local logins */
extern int tunable_pasv_enable;               /* Allow PASV */
extern int tunable_port_enable;               /* Allow PORT */
extern int tunable_chroot_local_user;         /* Restrict local to home dir */
extern int tunable_write_enable;              /* Global enable writes */
extern int tunable_anon_upload_enable;        /* Enable STOR for anon users */
extern int tunable_anon_mkdir_write_enable;   /* MKD for anon */
extern int tunable_anon_other_write_enable;   /* DELE RMD RNFR RNTO for anon */
extern int tunable_chown_uploads;             /* chown() anon uploaded files */
extern int tunable_connect_from_port_20;      /* PORT connects from port 20 */
extern int tunable_xferlog_enable;            /* Log transfers to a file */
extern int tunable_dirmessage_enable;         /* Look for + output .message */
extern int tunable_anon_world_readable_only;  /* Only serve world readable */
extern int tunable_async_abor_enable;         /* Enable async ABOR requests */
extern int tunable_ascii_upload_enable;       /* Permit ASCII upload */
extern int tunable_ascii_download_enable;     /* Permit ASCII download */
extern int tunable_one_process_model;         /* Go faster stripes ;-) */
extern int tunable_xferlog_std_format;        /* Log details like wu-ftpd */
extern int tunable_pasv_promiscuous;          /* Allow any PASV connect IP */
extern int tunable_deny_email_enable;         /* Ban a list of anon e-mails */
extern int tunable_chroot_list_enable;        /* chroot() based on list file */
extern int tunable_setproctitle_enable;       /* Try to use setproctitle() */
extern int tunable_text_userdb_names;         /* For "ls", lookup text names */
extern int tunable_ls_recurse_enable;         /* Allow ls -R */
extern int tunable_log_ftp_protocol;          /* Log FTP requests/responses */
extern int tunable_guest_enable;              /* Remap guest users */
extern int tunable_userlist_enable;           /* Explicit user allow or deny */
extern int tunable_userlist_deny;             /* Is user list allow or deny? */
extern int tunable_use_localtime;             /* Use local time or GMT? */
extern int tunable_check_shell;               /* Use /etc/shells for non-PAM */
extern int tunable_hide_ids;                  /* Show "ftp" in ls listings */
extern int tunable_listen;                    /* Standalone (no inetd) mode? */
extern int tunable_port_promiscuous;          /* Any any PORT connect IP */
extern int tunable_passwd_chroot_enable;      /* chroot() based on passwd */

/* Integer/numeric defines */
extern unsigned int tunable_accept_timeout;
extern unsigned int tunable_connect_timeout;
extern unsigned int tunable_local_umask;
extern unsigned int tunable_anon_umask;
extern unsigned int tunable_ftp_data_port;
extern unsigned int tunable_idle_session_timeout;
extern unsigned int tunable_data_connection_timeout;
extern unsigned int tunable_pasv_min_port;
extern unsigned int tunable_pasv_max_port;
extern unsigned int tunable_anon_max_rate;
extern unsigned int tunable_local_max_rate;
extern unsigned int tunable_listen_port;
extern unsigned int tunable_max_clients;

/* String defines */
extern const char* tunable_secure_chroot_dir;
extern const char* tunable_ftp_username;
extern const char* tunable_chown_username;
extern const char* tunable_xferlog_file;
extern const char* tunable_message_file;
extern const char* tunable_nopriv_user;
extern const char* tunable_ftpd_banner;
extern const char* tunable_banned_email_file;
extern const char* tunable_chroot_list_file;
extern const char* tunable_pam_service_name;
extern const char* tunable_guest_username;
extern const char* tunable_userlist_file;
extern const char* tunable_anon_root;
extern const char* tunable_local_root;
extern const char* tunable_banner_file;
extern const char* tunable_pasv_address;
extern const char* tunable_listen_address;
extern const char* tunable_user_config_dir;

#endif /* VSF_TUNABLES_H */


Summary: vsftpd - Very Secure Ftp Daemon
Name: vsftpd
Version: 0.9.2
Release: rh6_1
Copyright: GPL
Group: System Environment/Daemons
URL: ftp://ferret.lmh.ox.ac.uk/pub/linux/
Source: %{name}-%{version}.tar.gz
Packager: Seth Vidal <skvidal@phy.duke.edu>
BuildRoot: /var/tmp/%{name}-%{version}-root
Requires: inetd, logrotate
Provides: ftpserver

%description
A Very Secure FTP Daemon - written from scratch - by Chris "One Man Security
Audit Team" Evans


%prep
%setup -q -n %{name}-%{version}

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/share/empty
mkdir -p $RPM_BUILD_ROOT/etc
mkdir -p $RPM_BUILD_ROOT/etc/pam.d
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man5
mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man8
install -m 755 vsftpd  $RPM_BUILD_ROOT/usr/sbin/vsftpd
install -m 600 vsftpd.conf $RPM_BUILD_ROOT/etc/vsftpd.conf
install -m 644 RedHat/vsftpd.pam $RPM_BUILD_ROOT/etc/pam.d/ftp
install -m 644 vsftpd.conf.5 $RPM_BUILD_ROOT/%{_mandir}/man5/
install -m 644 vsftpd.8 $RPM_BUILD_ROOT/%{_mandir}/man8/
install -m 644 RedHat/vsftpd.log $RPM_BUILD_ROOT/etc/logrotate.d/vsftpd.log

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/sbin/vsftpd
%dir /usr/share/empty
%config /etc/vsftpd.conf
%config /etc/pam.d/ftp
%config /etc/logrotate.d/vsftpd.log
%doc INSTALL BUGS AUDIT Changelog LICENSE README README.security REWARD SPEED TODO SECURITY/ TUNING SIZE
%{_mandir}/man5/vsftpd.conf.*
%{_mandir}/man8/vsftpd.*

%changelog
* Thu Mar 22 2001 Seth Vidal <skvidal@phy.duke.edu>
- updated to 0.0.15
- added entry for vsftpd.8 man page
- added entry for vsftpd.log logrotate file
- added TUNING file to docs list
* Wed Mar 7 2001 Seth Vidal <skvidal@phy.duke.edu>
- Updated to 0.0.14
- made %files entry for man page
* Wed Feb 21 2001 Seth Vidal <skvidal@phy.duke.edu>
- Updated to 0.0.13
* Mon Feb 12 2001 Seth Vidal <skvidal@phy.duke.edu>
- Updated to 0.0.12
* Wed Feb 7 2001 Seth Vidal <skvidal@phy.duke.edu>
- updated to 0.0.11
* Fri Feb 1 2001 Seth Vidal <skvidal@phy.duke.edu>
- Update to 0.0.10
* Fri Feb 1 2001 Seth Vidal <skvidal@phy.duke.edu>
- First RPM packaging
- Stolen items from wu-ftpd's pam setup
- Separated rh 7 and rh 6.X's packages
- Built for Rh6

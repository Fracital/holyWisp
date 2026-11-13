## holyWisp RPM spec for Fedora/RHEL. Builds the server and client into two packages: `holywisp`
## installs the hardened systemd unit and creates the isolated `wisp` system user via
## systemd-sysusers; `holywisp-client` is the command-line client alone. Release artifacts are
## built by deploy/package.sh (which defines hw_version, hw_release and hw_client_split) and the
## Release CI workflow.
%global debug_package %{nil}

Name:           holywisp
Version:        %{?hw_version}%{!?hw_version:0.5.3}
Release:        %{?hw_release}%{!?hw_release:2}%{?dist}
Summary:        A Wisp v1/v2 server in C with no runtime dependencies

License:        MIT
URL:            https://github.com/Fracital/holyWisp
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  cmake
BuildRequires:  ninja-build
BuildRequires:  libxcrypt-devel
BuildRequires:  systemd-rpm-macros

Requires(pre):  shadow-utils
%{?systemd_requires}
Suggests:       %{name}-client

%description
holyWisp is a Wisp (https://github.com/MercuryWorkshop/wisp-protocol) server written in C11 with
no dependencies beyond libc and pthreads. It speaks Wisp v1 and v2 over WebSocket, relays TCP and
UDP streams, and ships flood protection, per-IP rate and bandwidth limits, IP reputation scoring,
a default-deny egress policy, host and port filters, an optional upstream proxy and optional PTY
terminal streams. This package runs it as a dedicated, unprivileged, heavily sandboxed systemd
service. The command-line client is in holywisp-client.

%package client
Summary:        Command-line client for Wisp v1/v2 servers
# Until this release the client's binary was in the server package: the two cannot both own it.
Conflicts:      %{name} < %{?hw_client_split}%{!?hw_client_split:0.5.3-2}

%description client
holywisp-client is netcat through a Wisp server: it opens a TCP or UDP stream through any Wisp v1
or v2 server and relays it to standard input and output, with password login and an echo
benchmark. This package installs the client only: no service, no user, no configuration. The
server is in the holywisp package.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake -G Ninja -DHW_BUILD_TESTS=OFF -DHW_VERSION_SUFFIX="" -DCMAKE_BUILD_TYPE=Release
%cmake_build

%install
%cmake_install
# Config, systemd unit, sysusers and tmpfiles.
install -D -m 0640 deploy/holywisp.conf \
    %{buildroot}%{_sysconfdir}/holywisp/holywisp.conf
install -D -m 0644 deploy/systemd/holywisp.service \
    %{buildroot}%{_unitdir}/holywisp.service
install -D -m 0644 deploy/systemd/holywisp.sysusers \
    %{buildroot}%{_sysusersdir}/holywisp.conf
install -D -m 0644 deploy/systemd/holywisp.tmpfiles \
    %{buildroot}%{_tmpfilesdir}/holywisp.conf
install -d -m 0750 %{buildroot}%{_sharedstatedir}/holywisp

%pre
# Create the wisp user/group before the files land (sysusers handles it on modern systemd; this is
# the belt-and-braces fallback for a locked, shell-less system account).
getent group wisp >/dev/null || groupadd -r wisp
getent passwd wisp >/dev/null || \
    useradd -r -g wisp -d %{_sharedstatedir}/holywisp -s /sbin/nologin \
        -c "holyWisp Wisp server" wisp
exit 0

%post
# The account exists by now: %%pre made it (and rpm 4.19 and newer make it themselves from the
# packaged sysusers.d file). The tmpfiles.d entry is applied here rather than at the next boot.
%tmpfiles_create holywisp.conf
# Config may hold password hashes: root-owned, group-readable by wisp, not world-readable.
# Nothing here follows a symbolic link (an earlier tmpfiles.d entry left the directory writable by
# the service user): chown -h changes a link itself, and chmod only runs on a real directory or a
# regular file. The directory comes first, so that what is inside it can no longer be swapped.
chown -h root:wisp %{_sysconfdir}/holywisp 2>/dev/null || :
if [ -d %{_sysconfdir}/holywisp ] && [ ! -L %{_sysconfdir}/holywisp ]; then
    chmod 0750 %{_sysconfdir}/holywisp 2>/dev/null || :
fi
chown -h root:wisp %{_sysconfdir}/holywisp/holywisp.conf 2>/dev/null || :
if [ -f %{_sysconfdir}/holywisp/holywisp.conf ] && [ ! -L %{_sysconfdir}/holywisp/holywisp.conf ]; then
    chmod 0640 %{_sysconfdir}/holywisp/holywisp.conf 2>/dev/null || :
fi
chown -h wisp:wisp %{_sharedstatedir}/holywisp 2>/dev/null || :
%systemd_post holywisp.service

%preun
%systemd_preun holywisp.service

%postun
%systemd_postun_with_restart holywisp.service

%files
%license LICENSE
%doc README.md
%{_bindir}/holywisp
%{_unitdir}/holywisp.service
%{_sysusersdir}/holywisp.conf
%{_tmpfilesdir}/holywisp.conf
%config(noreplace) %attr(0640,root,wisp) %{_sysconfdir}/holywisp/holywisp.conf
%dir %attr(0750,root,wisp) %{_sysconfdir}/holywisp
%dir %attr(0750,wisp,wisp) %{_sharedstatedir}/holywisp

%files client
%license LICENSE
%doc README.md
%{_bindir}/holywisp-client

%changelog
* Thu Nov 12 2026 holyWisp maintainers <noreply@example.com> - 0.5.3-2
- The client is its own package, holywisp-client; the server package no longer carries it.

* Wed Nov 05 2025 holyWisp maintainers <noreply@example.com> - 0.1.0-1
- Initial package: hardened systemd service running as the dedicated wisp user.

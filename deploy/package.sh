#!/usr/bin/env bash
# Build holyWisp distribution packages, two of each kind: `holywisp`, the server as a hardened
# systemd service with its dedicated `wisp` user, and `holywisp-client`, the command-line client
# alone (no service, no user, no config), as .debs (dpkg-deb) and/or .rpms (rpmbuild). Run from
# anywhere; paths are resolved from the repo root.
#
#   deploy/package.sh [deb|rpm|all]   (default: all that this host can build)
#
# Output goes to build/packages/. VERSION defaults to the project version; override with HW_VERSION.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="$root/build/packages"
# Version: an explicit HW_VERSION wins, but only if it looks like a version (starts with a digit);
# otherwise, and by default, read it from CMakeLists. This keeps an untagged "master" build from
# producing an invalid package version.
default_version="$(grep -oE 'project\(holyWisp VERSION [0-9.]+' "$root/CMakeLists.txt" | grep -oE '[0-9.]+' || echo 0.5.3)"
version="${HW_VERSION:-}"
case "$version" in
	[0-9]*) ;;
	*) version="$default_version" ;;
esac
# The packaging's own revision (the deb's -N, the rpm's Release), for a change to the packages
# that is not a change to the version. 2 is the first without holywisp-client inside `holywisp`:
# `client_split` below is where the client's file changed hands, and stays that forever. Raise
# pkg_release when the packaging changes again; it need not go back to 1 for a new version.
pkg_release="${HW_PKG_RELEASE:-2}"
client_split="0.5.3-2"
arch_deb="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
want="${1:-all}"

mkdir -p "$out"

# The binaries that go into the .deb. The RPM compiles its own from the source tarball, under
# %cmake, which hands the build the distribution's flags; a .deb made by debhelper would get
# Debian's the same way. This one is made by hand (dpkg-deb, below), so the flags are asked for
# here: where dpkg-buildflags exists (dpkg-dev: Debian, Ubuntu) its CPPFLAGS, CFLAGS and LDFLAGS
# go to CMake, with every hardening feature it knows unless DEB_BUILD_MAINT_OPTIONS says
# otherwise. They are passed as cache entries, not through the environment, which CMake reads
# only the first time it configures a tree. Where it does not exist, the build has the project's
# own mitigations (CMakeLists.txt, "Exploit mitigations") and nothing else, as before.
deb_flags=0
build_binaries() {
	echo "==> building release binaries"
	local flags=()
	if [ "$want" != rpm ] && command -v dpkg-buildflags >/dev/null; then
		export DEB_BUILD_MAINT_OPTIONS="${DEB_BUILD_MAINT_OPTIONS:-hardening=+all}"
		local cflags ldflags
		# CMake has no CPPFLAGS of its own; the preprocessor flags ride with the compiler's.
		cflags="$(dpkg-buildflags --get CPPFLAGS) $(dpkg-buildflags --get CFLAGS)"
		ldflags="$(dpkg-buildflags --get LDFLAGS)"
		flags+=("-DCMAKE_C_FLAGS=$cflags" "-DCMAKE_EXE_LINKER_FLAGS=$ldflags")
		deb_flags=1
		echo "    dpkg-buildflags: $cflags"
		echo "    dpkg-buildflags: $ldflags"
	fi
	cmake -S "$root" -B "$root/build/pkg" -G "${GENERATOR:-Ninja}" \
		-DCMAKE_BUILD_TYPE=Release -DHW_BUILD_TESTS=OFF -DHW_VERSION_SUFFIX="" \
		${flags[@]+"${flags[@]}"} >/dev/null
	cmake --build "$root/build/pkg" >/dev/null
	"$root/build/pkg/holywisp" --version
}

# Debian's CFLAGS carry -g, which debhelper would strip into a -dbgsym package. There is no such
# package here, so the debug sections go; the symbol table stays, as it always has.
strip_debug() {
	if [ "$deb_flags" = 1 ] && command -v strip >/dev/null; then
		strip --strip-debug "$@"
	fi
}

# md5sums for everything outside DEBIAN/, then the package itself.
deb_finish() {
	local stage="$1" deb="$2"
	(cd "$stage" && find . -type f -not -path './DEBIAN/*' -printf '%P\n' | sort |
		while read -r f; do md5sum "$f"; done > DEBIAN/md5sums)
	fakeroot dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null
	echo "    $deb"
	dpkg-deb --info "$deb" | sed 's/^/    /'
}

build_deb() {
	build_deb_server
	build_deb_client
}

build_deb_server() {
	echo "==> building .deb: holywisp"
	local stage="$out/deb"
	rm -rf "$stage"
	install -D -m 0755 "$root/build/pkg/holywisp" "$stage/usr/bin/holywisp"
	strip_debug "$stage/usr/bin/holywisp"
	install -D -m 0640 "$root/deploy/holywisp.conf" "$stage/etc/holywisp/holywisp.conf"
	install -D -m 0644 "$root/deploy/systemd/holywisp.service" "$stage/lib/systemd/system/holywisp.service"
	install -D -m 0644 "$root/deploy/systemd/holywisp.sysusers" "$stage/usr/lib/sysusers.d/holywisp.conf"
	install -D -m 0644 "$root/deploy/systemd/holywisp.tmpfiles" "$stage/usr/lib/tmpfiles.d/holywisp.conf"
	install -D -m 0644 "$root/README.md" "$stage/usr/share/doc/holywisp/README.md"
	install -D -m 0644 "$root/LICENSE" "$stage/usr/share/doc/holywisp/copyright"

	local isize
	isize="$(du -k -s "$stage" | cut -f1)"
	install -d "$stage/DEBIAN"
	cat > "$stage/DEBIAN/control" <<CTL
Package: holywisp
Version: $version-$pkg_release
Architecture: $arch_deb
Maintainer: holyWisp maintainers <noreply@example.com>
Installed-Size: $isize
Depends: libc6, libcrypt1, adduser
Suggests: holywisp-client
Section: net
Priority: optional
Homepage: https://github.com/Fracital/holyWisp
Description: A Wisp v1/v2 server in C with no runtime dependencies
 holyWisp speaks Wisp v1 and v2 over WebSocket and relays TCP and UDP streams.
 It ships flood protection, per-IP rate and bandwidth limits, IP reputation
 scoring, a default-deny egress policy, host and port filters, an optional
 upstream proxy and optional PTY terminal streams. This package runs it as a
 dedicated, unprivileged, heavily sandboxed systemd service.
CTL
	# Mark the config as a conffile so upgrades do not clobber local edits.
	echo "/etc/holywisp/holywisp.conf" > "$stage/DEBIAN/conffiles"
	install -m 0755 "$root/deploy/debian/postinst" "$stage/DEBIAN/postinst"
	install -m 0755 "$root/deploy/debian/prerm" "$stage/DEBIAN/prerm"
	install -m 0755 "$root/deploy/debian/postrm" "$stage/DEBIAN/postrm"
	deb_finish "$stage" "$out/holywisp_${version}-${pkg_release}_${arch_deb}.deb"
}

# The client alone: one binary and its documentation, no maintainer scripts. Until client_split
# the binary was in `holywisp`, so this package takes the file over from one of those (Replaces).
# There is deliberately no Breaks beside it, as policy would have for a moved file: with an older
# server installed and no newer one to hand, apt satisfies a Breaks by removing the server, and
# installing a client must never take a running server away. The older server keeps working
# without the client's file, and stops claiming it once dpkg has handed it over.
build_deb_client() {
	echo "==> building .deb: holywisp-client"
	local stage="$out/deb-client"
	rm -rf "$stage"
	install -D -m 0755 "$root/build/pkg/holywisp-client" "$stage/usr/bin/holywisp-client"
	strip_debug "$stage/usr/bin/holywisp-client"
	install -D -m 0644 "$root/README.md" "$stage/usr/share/doc/holywisp-client/README.md"
	install -D -m 0644 "$root/LICENSE" "$stage/usr/share/doc/holywisp-client/copyright"

	local isize
	isize="$(du -k -s "$stage" | cut -f1)"
	install -d "$stage/DEBIAN"
	cat > "$stage/DEBIAN/control" <<CTL
Package: holywisp-client
Version: $version-$pkg_release
Architecture: $arch_deb
Maintainer: holyWisp maintainers <noreply@example.com>
Installed-Size: $isize
Depends: libc6, libcrypt1
Replaces: holywisp (<< $client_split)
Section: net
Priority: optional
Homepage: https://github.com/Fracital/holyWisp
Description: Command-line client for Wisp v1/v2 servers
 holywisp-client is netcat through a Wisp server: it opens a TCP or UDP
 stream through any Wisp v1 or v2 server and relays it to standard input and
 output, with password login and an echo benchmark. This package installs the
 client only; the server and its service are in the holywisp package.
CTL
	deb_finish "$stage" "$out/holywisp-client_${version}-${pkg_release}_${arch_deb}.deb"
}

build_rpm() {
	echo "==> building .rpm"
	local top="$out/rpmbuild"
	rm -rf "$top"
	mkdir -p "$top"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
	# Source tarball: a clean export of the tree under holywisp-<version>/.
	local tardir="$out/holywisp-$version"
	rm -rf "$tardir"
	mkdir -p "$tardir"
	# From the working tree (not a git commit), so the package reflects exactly what is built.
	cp -a "$root"/{CMakeLists.txt,CMakePresets.json,cmake,include,src,examples,deploy,README.md,LICENSE} "$tardir/"
	rm -rf "$tardir/deploy/out"
	(cd "$out" && tar -czf "$top/SOURCES/holywisp-$version.tar.gz" "holywisp-$version")
	rm -rf "$tardir"
	cp "$root/deploy/rpm/holywisp.spec" "$top/SPECS/"
	rpmbuild --define "_topdir $top" --define "hw_version $version" --define "hw_release $pkg_release" \
		--define "hw_client_split $client_split" -bb "$top/SPECS/holywisp.spec"
	find "$top/RPMS" -name '*.rpm' -exec cp {} "$out/" \; -exec echo "    {}" \;
}

build_binaries
case "$want" in
deb) build_deb ;;
rpm) build_rpm ;;
all)
	command -v dpkg-deb >/dev/null && build_deb || echo "==> skipping .deb (no dpkg-deb)"
	command -v rpmbuild >/dev/null && build_rpm || echo "==> skipping .rpm (no rpmbuild)"
	;;
*)
	echo "usage: $0 [deb|rpm|all]" >&2
	exit 2
	;;
esac
echo "==> done; artifacts in $out"

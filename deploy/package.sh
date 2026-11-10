#!/usr/bin/env bash
# Build holyWisp distribution packages: a .deb (dpkg-deb) and/or an .rpm (rpmbuild). Both install
# the hardened systemd unit and the dedicated `wisp` user. Run from anywhere; paths are resolved
# from the repo root.
#
#   deploy/package.sh [deb|rpm|all]   (default: all that this host can build)
#
# Output goes to deploy/out/. VERSION defaults to the project version; override with HW_VERSION.
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
arch_deb="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
want="${1:-all}"

mkdir -p "$out"

build_binaries() {
	echo "==> building release binaries"
	cmake -S "$root" -B "$root/build/pkg" -G "${GENERATOR:-Ninja}" \
		-DCMAKE_BUILD_TYPE=Release -DHW_BUILD_TESTS=OFF -DHW_VERSION_SUFFIX="" >/dev/null
	cmake --build "$root/build/pkg" >/dev/null
	"$root/build/pkg/holywisp" --version
}

build_deb() {
	echo "==> building .deb"
	local stage="$out/deb"
	rm -rf "$stage"
	install -D -m 0755 "$root/build/pkg/holywisp" "$stage/usr/bin/holywisp"
	install -D -m 0755 "$root/build/pkg/holywisp-client" "$stage/usr/bin/holywisp-client"
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
Version: $version
Architecture: $arch_deb
Maintainer: holyWisp maintainers <noreply@example.com>
Installed-Size: $isize
Depends: libc6, libcrypt1, adduser
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
	# md5sums for everything outside DEBIAN/.
	(cd "$stage" && find . -type f -not -path './DEBIAN/*' -printf '%P\n' | sort |
		while read -r f; do md5sum "$f"; done > DEBIAN/md5sums)

	local deb="$out/holywisp_${version}_${arch_deb}.deb"
	fakeroot dpkg-deb --build --root-owner-group "$stage" "$deb" >/dev/null
	echo "    $deb"
	dpkg-deb --info "$deb" | sed 's/^/    /'
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
	rpmbuild --define "_topdir $top" --define "hw_version $version" -bb "$top/SPECS/holywisp.spec"
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

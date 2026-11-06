#!/bin/bash
# Forced command for the CI deploy key on terp (/usr/local/sbin/holywisp-deploy-gate).
# The only command it accepts is `deploy <40-hex sha>`: fetch that commit from GitHub, build it in
# $STAGE, swap $REPO and the binaries to it, restart the holywisp systemd service and health-check
# it, rolling back on failure. Installed by hand; CI never updates it. /etc/holywisp is not touched.
#
# One-time terp setup (by hand, as root), serving https://holywisp.fracit.al/:
#   useradd -r -g wisp -d /var/lib/holywisp -s /usr/sbin/nologin wisp   # (groupadd wisp first)
#   mkdir -p /opt/holywisp /etc/holywisp /var/lib/holywisp
#   git clone https://github.com/Fracital/holyWisp.git /opt/holywisp/repo
#   install -Dm0640 /opt/holywisp/repo/deploy/holywisp.conf /etc/holywisp/holywisp.conf
#   # edit the conf: host = 127.0.0.1, port = 8082, serve-webclient = on
#   install -m0755 /opt/holywisp/repo/deploy/systemd/holywisp.service /etc/systemd/system/
#   # point ExecStart at /opt/holywisp/bin/holywisp, then: systemctl enable --now holywisp
#   install -m0755 /opt/holywisp/repo/deploy/terp-deploy-gate.sh /usr/local/sbin/holywisp-deploy-gate
#   # pin the CI public key to it in root's authorized_keys:
#   #   command="/usr/local/sbin/holywisp-deploy-gate",no-port-forwarding,no-pty ssh-ed25519 AAAA...
# Then set the TERP_DEPLOY_KEY repo secret to the matching private key.
set -euo pipefail
umask 022

REPO=/opt/holywisp/repo
STAGE=/opt/holywisp/stage
BIN=/opt/holywisp/bin
UPSTREAM=https://github.com/Fracital/holyWisp.git
APP=holywisp
PORT=8082
LOG=/var/log/holywisp-deploy.log

read -r -a cmd <<<"${SSH_ORIGINAL_COMMAND:-}"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG" >&2; }

exec 9>/run/lock/holywisp-deploy.lock
flock -w 900 9

healthcheck() {
	for _ in $(seq 1 30); do
		curl -fsS -o /dev/null -m 5 "http://127.0.0.1:$PORT/health" && return 0
		sleep 1
	done
	return 1
}

restart_app() {
	systemctl restart "$APP"
	if ! healthcheck; then
		log "health check failed after restart"
		journalctl -u "$APP" -n 40 --no-pager >&2 || true
		return 1
	fi
}

# Build $1 in the stage checkout, then move the live checkout and binaries to it.
build_and_sync() {
	local sha=$1
	[[ -d $STAGE/.git ]] || git clone -q "$UPSTREAM" "$STAGE"
	git -C "$STAGE" fetch -q "$UPSTREAM" "$sha" || git -C "$STAGE" fetch -q "$REPO" "$sha"
	git -C "$STAGE" checkout -q --force --detach "$sha"
	git -C "$STAGE" clean -qfdx
	make -C "$STAGE" release >&2
	install -d "$BIN"
	install -m0755 "$STAGE/build/release/holywisp" "$BIN/holywisp.new"
	install -m0755 "$STAGE/build/release/holywisp-client" "$BIN/holywisp-client.new"
	mv -f "$BIN/holywisp.new" "$BIN/holywisp"
	mv -f "$BIN/holywisp-client.new" "$BIN/holywisp-client"
	git -C "$REPO" fetch -q "$STAGE" "$sha"
	git -C "$REPO" reset -q --keep "$sha"
}

deploy_app() {
	local sha=${1:-}
	[[ $sha =~ ^[0-9a-f]{40}$ ]] || {
		echo "usage: deploy <40-hex sha>" >&2
		exit 64
	}
	local live
	live=$(git -C "$REPO" rev-parse HEAD)
	# Never overwrite work done directly on terp that is not on GitHub.
	if [[ -n $(git -C "$REPO" status --porcelain --untracked-files=no) ]]; then
		log "refusing $sha: $REPO has uncommitted changes to tracked files"
		exit 1
	fi
	git -C "$REPO" fetch -q "$UPSTREAM" "$sha"
	if ! git -C "$REPO" merge-base --is-ancestor "$live" "$sha"; then
		log "refusing $sha: live HEAD $live has commits that are not on GitHub; push them first"
		exit 1
	fi
	log "deploying $sha (live $live)"
	build_and_sync "$sha"
	if ! restart_app; then
		log "rolling back to $live"
		build_and_sync "$live"
		restart_app || log "rollback to $live is unhealthy too"
		exit 1
	fi
	log "deployed $sha"
}

case "${cmd[0]:-}" in
deploy) deploy_app "${cmd[1]:-}" ;;
*)
	echo "denied: '${SSH_ORIGINAL_COMMAND:-}'" >&2
	exit 126
	;;
esac

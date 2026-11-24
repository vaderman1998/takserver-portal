#!/usr/bin/env bash
# pki-snapshot.sh - file-level snapshots of everything the portal's certificate jobs touch, for
# boxes without VM snapshots.
#
#   sudo ./pki-snapshot.sh save [name]      # default name: the current date and time
#   sudo ./pki-snapshot.sh list
#   sudo ./pki-snapshot.sh restore <name>   # stops TAK Server, puts the files back, starts it
#   sudo ./pki-snapshot.sh diff <name>      # what changed since that snapshot (names only)
#
# What is saved: /opt/tak/certs (every CA, keystore, config.cfg, cert-metadata.sh, the backup
# folders a root rotation leaves), CoreConfig.xml and CoreConfig.example.xml.
# What is NOT saved: TAK's database. Admin grants made with `certmod -A` are additive and
# survive a restore; certificates enrolled by devices stay in the certificate table either way.

set -euo pipefail
TAK_DIR="${TAK_DIR:-/opt/tak}"
SNAP_DIR="${PKI_SNAPSHOT_DIR:-/root/tak-pki-snapshots}"
UNIT="takserver"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -d "$TAK_DIR/certs" ]] || { echo "$TAK_DIR/certs not found" >&2; exit 1; }
mkdir -p "$SNAP_DIR"; chmod 700 "$SNAP_DIR"

cmd="${1:-}"
name="${2:-}"
members=(certs CoreConfig.xml)
[[ -f "$TAK_DIR/CoreConfig.example.xml" ]] && members+=(CoreConfig.example.xml)

case "$cmd" in
  save)
    name="${name:-$(date +%Y%m%d-%H%M%S)}"
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "name: letters, numbers, . _ - only" >&2; exit 1; }
    out="$SNAP_DIR/$name.tgz"
    [[ -e "$out" ]] && { echo "$out exists; pick another name" >&2; exit 1; }
    tar czf "$out" -C "$TAK_DIR" "${members[@]}"
    chmod 600 "$out"
    echo "saved $out ($(du -h "$out" | cut -f1))"
    ;;
  list)
    ls -la "$SNAP_DIR"/*.tgz 2>/dev/null || echo "no snapshots in $SNAP_DIR"
    ;;
  diff)
    [[ -n "$name" && -f "$SNAP_DIR/$name.tgz" ]] || { echo "snapshot not found" >&2; exit 1; }
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    tar xzf "$SNAP_DIR/$name.tgz" -C "$tmp"
    echo "== changes since $name, within what it holds (certs/ and CoreConfig*.xml) =="
    changed=0
    for m in "$tmp"/*; do
      n="$(basename "$m")"
      out="$(diff -rq "$m" "$TAK_DIR/$n" 2>&1)" || changed=1
      if [[ -n "$out" ]]; then
        printf '%s\n' "$out" | sed \
          -e "s#^Files $tmp/\(.*\) and $TAK_DIR/.* differ\$#changed   \1#" \
          -e "s#^Only in $tmp/\([^:]*\): \(.*\)#removed   \1/\2#" \
          -e "s#^Only in $TAK_DIR/\([^:]*\): \(.*\)#added     \1/\2#"
      fi
    done
    if [[ $changed -eq 0 ]]; then echo "no differences"; fi
    ;;
  restore)
    [[ -n "$name" && -f "$SNAP_DIR/$name.tgz" ]] || { echo "snapshot not found; see: $0 list" >&2; exit 1; }
    echo "Restoring $name over $TAK_DIR/certs and CoreConfig*.xml. TAK Server will restart."
    read -rp "Type RESTORE to continue: " ok; [[ "$ok" == "RESTORE" ]] || { echo "aborted"; exit 1; }
    pre="$SNAP_DIR/before-restore-$(date +%Y%m%d-%H%M%S).tgz"
    tar czf "$pre" -C "$TAK_DIR" "${members[@]}" && chmod 600 "$pre"
    echo "current state kept as $pre"
    systemctl stop "$UNIT"
    rm -rf "$TAK_DIR/certs"
    tar xzf "$SNAP_DIR/$name.tgz" -C "$TAK_DIR"
    chown -R tak:tak "$TAK_DIR/certs" "$TAK_DIR/CoreConfig.xml" "$TAK_DIR/CoreConfig.example.xml" 2>/dev/null || true
    systemctl start "$UNIT"
    echo "restored; TAK Server starting. Watch: journalctl -u $UNIT -f"
    ;;
  *)
    sed -n '2,15p' "$0"
    exit 1
    ;;
esac

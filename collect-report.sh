#!/usr/bin/env bash
# collect-report.sh - print a plain-text picture of this TAK Server's certificate state and the
# portal's recent jobs, with every password redacted, so it can be pasted into a report.
#
#   sudo ./collect-report.sh > report.txt
#
# Reads only. Never prints keystore passwords, private keys or the DB password.

set -u
TAK_DIR="${TAK_DIR:-/opt/tak}"
FILES="$TAK_DIR/certs/files"
CC="$TAK_DIR/CoreConfig.xml"
PORTAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

redact() { sed -E 's/(Pass|password|PASS)=("[^"]*"|[^ ]*)/\1="***"/g'; }
hr() { printf '\n==== %s ====\n' "$1"; }

hr "host"
date -u +"%Y-%m-%dT%H:%M:%SZ"; hostname -f 2>/dev/null || hostname
grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null
[[ -f "$TAK_DIR/version.txt" ]] && { printf 'TAK Server: '; cat "$TAK_DIR/version.txt"; }
printf 'takserver package: '; dpkg-query -W -f='${Version} ${db:Status-Status} (dpkg)\n' takserver 2>/dev/null \
  || rpm -q --qf '%{VERSION}-%{RELEASE} (rpm)\n' takserver 2>/dev/null || echo "not known to dpkg / rpm"
printf 'takserver.war: '; python3 -c 'import sys, zipfile
z = zipfile.ZipFile(sys.argv[1]); n = [x for x in z.namelist() if x.endswith("shortver.txt")]
print(z.read(n[0]).decode().strip() if n else "no shortver.txt inside")' "$TAK_DIR/takserver.war" 2>/dev/null || echo "not readable"
printf 'portal unit: '; systemctl is-active tak-portal 2>/dev/null || echo "not installed"
printf 'takserver unit: '; systemctl is-active takserver 2>/dev/null || echo "?"
printf 'java: '; java -version 2>&1 | head -1
printf 'keytool: '; command -v keytool || ls /usr/lib/jvm/*/bin/keytool 2>/dev/null | head -1 || echo "not found"
printf 'openssl: '; openssl version 2>/dev/null
printf 'tak user: '; id tak 2>/dev/null || echo "none"

hr "CoreConfig (certificate-related lines, passwords redacted)"
if [[ -r "$CC" ]]; then
  grep -nE 'keystoreFile|truststoreFile|<crl|certificateSigning|TAKServerCAConfig|validityDays|<auth|connector port|<input ' "$CC" | redact
else
  echo "$CC not readable"
fi

hr "certs/files listing"
ls -la "$FILES" 2>/dev/null || echo "$FILES missing"

hr "CA certificates"
for f in root-ca.pem ca.pem; do
  if [[ -r "$FILES/$f" ]]; then
    printf '%s: ' "$f"
    openssl x509 -in "$FILES/$f" -noout -subject -issuer -enddate -nameopt RFC2253 2>/dev/null | tr '\n' ' '; echo
  fi
done

hr "server certificate on disk"
# the main <security><tls> only: a connector (installTAK's 8446 Let's Encrypt) and federation carry keystores of their own
SEC="$(sed -n '/<security[[:space:]>]/,/<\/security>/p' "$CC" 2>/dev/null)"
KS="$(printf '%s\n' "$SEC" | grep -oE 'keystoreFile="[^"]*"' | head -1 | sed -E 's/keystoreFile="([^"]*)"/\1/; s#.*/##; s/\.jks$//')"
SRV="${KS:-takserver}"
echo "name from CoreConfig: $SRV"
if [[ -r "$FILES/$SRV.pem" ]]; then
  openssl x509 -in "$FILES/$SRV.pem" -noout -subject -issuer -enddate -nameopt RFC2253 2>/dev/null
  printf 'SANs: '; openssl x509 -in "$FILES/$SRV.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' '
fi

hr "what 8443 presents right now"
openssl s_client -connect 127.0.0.1:8443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -enddate -nameopt RFC2253 2>/dev/null || echo "no answer on 8443"
printf '8089 listening: '; (exec 3<>/dev/tcp/127.0.0.1/8089) 2>/dev/null && echo yes || echo no

hr "live truststore entries"
TS="$(printf '%s\n' "$SEC" | grep -oE 'truststoreFile="[^"]*"' | head -1 | sed -E 's/truststoreFile="([^"]*)"/\1/')"
TP="$(printf '%s\n' "$SEC" | grep -oE 'truststorePass="[^"]*"' | head -1 | sed -E 's/truststorePass="([^"]*)"/\1/')"
if [[ -n "$TS" && -r "$TAK_DIR/$TS" ]]; then
  echo "file: $TS"
  KT_STOREPASS="$TP" keytool -list -v -keystore "$TAK_DIR/$TS" -storepass:env KT_STOREPASS 2>/dev/null \
    | grep -E '^(Alias name|Entry type|Owner|Issuer|Valid)' | sed -E 's/^Valid.*until: /  until: /'
else
  echo "truststore not found or unreadable ($TS)"
fi

hr "client certificates on disk (issuer, expiry)"
for p in "$FILES"/*.p12; do
  [[ -e "$p" ]] || continue
  n="$(basename "$p" .p12)"
  case "$n" in truststore-*|*-signing|*-le|"$SRV") continue;; esac
  if [[ -r "$FILES/$n.pem" ]]; then
    printf '%-24s ' "$n"; openssl x509 -in "$FILES/$n.pem" -noout -issuer -enddate -nameopt RFC2253 2>/dev/null | tr '\n' ' '; echo
  fi
done

hr "certificate table by issuer (newest cert per client UID)"
if command -v psql >/dev/null 2>&1; then
  SQL="SELECT DISTINCT ON (client_uid) client_uid, coalesce(nullif(user_dn,''), creator_dn, ''), replace(replace(certificate, chr(13), ''), chr(10), '') FROM certificate WHERE coalesce(client_uid,'')<>'' AND revocation_date IS NULL AND (expiration_date IS NULL OR expiration_date > now()) ORDER BY client_uid, issuance_date DESC"
  runuser -u postgres -- psql -d cot -tAF $'\t' -c "$SQL" 2>/dev/null | while IFS=$'\t' read -r uid user cert; do
    body="$(echo "$cert" | sed -E 's/-----(BEGIN|END) CERTIFICATE-----//g' | tr -d ' ')"
    iss="$(printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$(echo "$body" | fold -w 64)" | openssl x509 -noout -issuer -nameopt RFC2253 2>/dev/null | sed -E 's/.*CN=([^,]+).*/\1/')"
    printf '%-40s %-24s %s\n' "$uid" "$user" "${iss:-?}"
  done | sort -k3 | awk '{print} {c[$3]++} END {if (NR == 0) print "(no live certificates in the table)"; else {print "--"; for (k in c) print c[k], "on", k}}'
else
  echo "psql not installed"
fi

hr "portal job logs (newest 3)"
for f in $(ls -t "$PORTAL_DIR"/logs/*.log 2>/dev/null | head -3); do
  echo "--- $f ---"; redact < "$f"; echo
done
[[ -d "$PORTAL_DIR/logs" ]] || echo "no logs directory yet"

hr "takserver-messaging.log: certificate / TLS lines (last 40)"
grep -iE 'certificate|truststore|keystore|ssl|tls|handshake' "$TAK_DIR/logs/takserver-messaging.log" 2>/dev/null | tail -40 | redact

hr "tak-portal journal (last 40)"
journalctl -u tak-portal -n 40 --no-pager 2>/dev/null | redact

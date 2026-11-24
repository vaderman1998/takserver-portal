# TAK Server Portal

A zero-dependency admin panel for a native TAK Server (.deb / .rpm) install: upload and install
upgrade packages, restart the server, watch its log, and manage the certificate authority
(rotate the intermediate CA without dropping every phone, revoke old CAs, hand out truststores
and connection packages).

Built on the TAK Server Upgrade Portal. One Python file for HTTP (`app.py`), one for the PKI
work (`takcerts.py`), one for file-level snapshots (`snapshots.py`), one for updating the portal from its repository
(`selfupdate.py`), one for running TerraTAK as a container (`terratak.py`), a login page and a
dashboard. Standard library only.

## Install

```bash
git clone https://github.com/vaderman1998/takserver-portal.git && cd takserver-portal
sudo ./install.sh
```

The installer asks for a port, admin credentials and the server's public name, writes a systemd
unit (`tak-portal`), opens the port in ufw / firewalld and starts the service. It picks up a
Let's Encrypt certificate from `/etc/letsencrypt/live/` when there is one.

The portal runs as root. It needs `openssl`, `runuser` and Java's `keytool` on the box, all of
which a TAK Server install already brings; `psql` is used for the live certificate table.
Python 3.6 or newer: RHEL / Rocky 8's stock 3.6 works, and the installer uses the newest
`python3.x` it finds (on Rocky 8, `dnf install -y python3.11` before installing is worth it).

The top bar shows the installed TAK Server version: the `takserver` package as dpkg or rpm
records it, in TAK's own form (`5.4-RELEASE-106`), with `shortver.txt` inside `takserver.war` as
the fallback and a cross-check (the two are shown side by side, in amber, when they disagree).

## Updating the portal

The **Portal** card shows the commit this install runs (or that it is a plain copy of the files)
and updates it from the repository:

- **Check for updates** fetches and lists the commits and files that would change. Nothing moves.
- **Update portal** (portal password) backs the current files up to `backups/` (newest 5 kept),
  fast-forwards the checkout, runs the unit tests with the portal's own Python and, if they pass,
  restarts the `tak-portal` unit through a transient systemd timer. The page waits for the portal
  to come back and sends you to the login page. If the tests fail, the files go back to the
  previous commit and nothing is restarted. Untick *restart* to switch the files without a
  restart, or tick *skip the self-tests* when the suite cannot run on that box.
- An install that was copied over by hand (no `.git`) is adopted on its first update: the folder
  becomes a checkout of the repository; `uploads/`, `logs/`, `backups/` and `portal-state.json`
  are kept. Local edits to tracked files make the update refuse until they are stashed.

The repository URL and branch live in `portal-state.json`. A private repository needs either a
read-only token saved in the card (GitHub: fine-grained token, *Contents: read-only*, kept in
`portal-state.json` mode 600 and handed to git through `GIT_ASKPASS`, never on a command line) or
an SSH deploy key for root with a `git@github.com:` URL. `git` must be installed on the server.

From a shell the same thing is:

```bash
cd /root/takserver-portal && git pull --ff-only && systemctl restart tak-portal
```

## TerraTAK

TAK Product Center ships TerraTAK, its tile generator and streaming server, as a container image
per CPU architecture (`terratak-<version>-amd64.tar`, `-arm64.tar` from tak.gov). The **TerraTAK**
card under *Apps* runs it the way the image's own documentation says to:

- Drop the tarball on the card. It streams to `uploads/terratak/` (never held in memory) and is
  checked: a real image, tagged `terratak:<version>`, built for this server's architecture.
- **Install** loads the image, creates the container `terratak` with the data volume
  `terratak-data` mounted at `/opt/terratak`, publishes the port, opens it in ufw / firewalld and
  waits for the health endpoint. Installing a newer tarball later **upgrades**: the container is
  replaced, the volume with every tileset is kept.
- Settings (portal password): port, JVM heap for the server and for the tiling pipelines, the
  map center at start, and an optional login. TerraTAK has no login of its own; with a name and
  password set, the portal writes a Helidon basic-auth file to `/opt/terratak-config/` and
  mounts it read-only, so everyone must sign in and only that user may change data. Devices
  streaming tiles need the same login. Traffic is plain HTTP; a TLS reverse proxy is yours to add.
- Start / Stop / Restart / Logs, Remove container (keeps the data), Delete data volume.
- No container engine on the box? **Install Docker** puts the distribution's docker.io
  (Debian / Ubuntu) or Docker CE from download.docker.com (RHEL / Rocky) on and enables it.
  podman is used when it is what the box has.

## What the certificate side does

TAK's PKI, as its own scripts lay it out:

| Thing | Where |
|---|---|
| Root CA | `files/root-ca.pem`, `root-ca-do-not-share.key` |
| Working CA slot (signs the next makeCert run) | `files/ca.pem`, `ca-do-not-share.key`, `ca-trusted.pem` |
| One set per intermediate | `files/<INT>.pem`, `<INT>-signing.jks`, `truststore-<INT>.jks` / `.p12` |
| What TAK trusts on 8089 / 8443 | `CoreConfig.xml` `<security><tls truststoreFile>` |
| What signs certificates enrolled on 8446 | `CoreConfig.xml` `<TAKServerCAConfig keystoreFile>` |

ATAK, iTAK and WinTAK trust the CA they enrolled with and ignore the chain the server sends. A
server certificate signed by the **intermediate** therefore disconnects every device the moment
that intermediate is rotated. One signed by the **root** keeps them connected while users move to
the new intermediate. The portal shows which you have and lets you switch (reversible, with the
old certificate backed up and restored on any failure).

**Rotate Intermediate CA** (all through TAK's `makeCert.sh`, run as the `tak` user):

1. Puts the root CA in the working slot so the new intermediate is signed by the root.
2. `makeCert.sh ca <NEW>` with the validity you chose (makeCert hard-codes 730 days; the portal
   runs a temporary copy with that number replaced, TAK's script is never edited).
3. Reissues the server certificate with the same signer as before, carrying this server's real
   names (FQDN, host name, addresses) as SANs.
4. Reissues every client certificate on the new CA (keystores are moved aside first, because
   keytool's overwrite prompt otherwise leaves the `.p12` on the old CA).
5. Builds the new trust list: every CA the live truststore trusts is carried forward (expired ones
   dropped and logged with their live certificate counts), the old intermediate is kept, and
   self-signed roots are removed from TAK's own list. Java treats every truststore entry as a trust
   anchor, so a root in it would accept any intermediate that root ever signed, including a
   revoked one. The `.p12` handed to devices keeps the root.
6. Points `CoreConfig.xml` at the new truststore and signing keystore (attribute-targeted, no
   blind text replace) and caps enrolled-certificate validity to the intermediate's remaining life.
7. Restarts TAK Server and waits until 8443 presents a certificate.

**Revoke** removes an old intermediate and every root from TAK's trust list, reissues the server
certificate only if it chained through the revoked CA, rebuilds the device truststore and
restarts. It refuses the current intermediate, a root, an unknown alias, and anything while a
client certificate signed directly by the root still exists.

**Live certificates by CA** reads TAK's `certificate` table (newest certificate per client UID)
and groups it by issuer, so you can see who still has to move before you revoke.

**Rotate Root CA** is the full rebuild (every device re-enrolls). The old `files/` directory is
moved to a backup beside it first. `makeRootCa.sh` writes a fresh `fed-truststore.jks` holding
only the new root, which would drop every federation partner's CA, so the previous file is put
back with its own password, our old root and anything it signed are removed from it, and the new
root is added. Partners that federate with this server must import the new `root-ca.pem`.

A new certificate password also follows into the federation `<tls>` when it serves the same
server keystore as `<security><tls>` (installTAK's default), since that keystore is reissued with
the new password.

Every job streams into the terminal panel. Rotate, Revoke, Root rotate, the signer switch and the
names reissue ask for the portal password again. Only one certificate job runs at a time.

## Servers built with myTeckNet's installTAK

The portal reads the layout from the box rather than assuming the TAK docs' names, so an
installTAK server works as is:

- The server certificate is named after the host (`certs/files/<hostname>.jks`), taken from
  CoreConfig's `keystoreFile`. It is never treated as a client certificate and never handed out.
- CoreConfig's `<crl>` entry inside `<security><tls>` gets a sibling for each new intermediate;
  Revoke removes the revoked CA's entry. `CAkey` / `CAcertificate` on `TAKServerCAConfig` follow
  the new intermediate. `CoreConfig.example.xml` is kept in step, as installTAK treats it as the
  source of truth.
- `webadmin` is granted the admin role by certificate fingerprint, so after it is reissued the
  portal runs `UserManager.jar certmod -A` again. Import the new `webadmin.p12` into your
  browser before you revoke the old CA; the old one keeps working until then.
- A `<hostname>-le.jks` Let's Encrypt keystore on 8446 and its `renew-tak-le` cron job are left
  alone, including across a root rotation. If installTAK's Let's Encrypt step failed (no public
  DNS or port 80), CoreConfig still points 8446 at that missing keystore and the renew cron
  restarts TAK Server twice a day; the Certificate Authority card flags it and **Reset 8446 to
  TAK's certificate** puts the connector back and removes the cron entries.
- The password default installTAK leaves in `cert-metadata.sh` (`${CAPASS:-...}`) is read and,
  on a password change, rewritten in place.
- The enrollment endpoint installTAK recorded in `/opt/tak/takdatapackagedesc` is the default
  server name for connection packages.

The Docker variant of installTAK (the `takserver-docker-*.zip` path) is not supported: there is
no `tak` user or `takserver` unit on the host.

Compared with the myTeckNet intermediate-CA guide, Rotate does the same steps (root back into the
working slot, `makeCert.sh ca`, reissue the server certificate, import the old intermediate into
the new truststore, rename in both CoreConfig files, restart) and adds: every CA the live
truststore trusts is carried forward, roots leave TAK's own trust list, the CRL list is kept
complete, and, if the box is ticked, the client certificates on disk are reissued on the new CA.

## Files handed out

`/api/certs/download/<name>` serves `.p12`, `.pem` and `.jks` files from `/opt/tak/certs/files`.
Private keys, CSRs, CRLs, signing keystores and anything named `root-ca*` or `fed-*` are never
served. `/api/certs/package` builds an ATAK / iTAK connection data package (manifest, `config.pref`
with certificate enrollment on, the live truststore); `?client=<name>` adds that client's `.p12`
instead of enrollment.

## Configuration

Environment (set in the systemd unit by `install.sh`): `TAK_PORTAL_PORT`, `TAK_PORTAL_USER`,
`TAK_PORTAL_PASS`, `TAK_PORTAL_CERT_DIR`, `TAK_DIR` (default `/opt/tak`).

`portal-state.json` (mode 600) holds the server name used for packages and SANs, and the last
rotation (old CA, new CA, when) so the dashboard can show the window until the old CA is revoked.

The certificate password is read from `CoreConfig.xml` (`truststorePass`, what TAK actually opens
the truststore with), then from a literal `CAPASS` in `cert-metadata.sh`, then TAK's default.
A new password entered during a rotation is written to `cert-metadata.sh` when its lines are
literal and into CoreConfig's `<security><tls>` and `<TAKServerCAConfig>`; the federation
truststore keeps its own.

## Rolling back without VM snapshots

Everything the certificate jobs change is under `/opt/tak/certs` plus the two CoreConfig
files, so a file-level snapshot is a complete undo. The **Snapshots** card on the dashboard
saves one (optionally named), lists them with the intermediate CA each one was taken under,
shows a diff against the live files in the terminal panel, restores one (stops TAK Server,
puts the files back, starts it) and deletes old ones. Restore and delete ask for the portal
password.

Every certificate job (rotate, revoke, root rotate, signer switch, names reissue, 8446 reset)
saves `auto-before-<job>-<time>` first and refuses to run if it cannot; the newest 10 automatic
snapshots are kept, named ones are never pruned. A restore keeps the state it replaced as
`before-restore-<time>`. Admin grants made with `certmod -A` live in the database and are
additive, so they survive either way.

The same snapshots are usable from a shell, which matters when the portal itself is the
problem; both tools write the same tarballs to `/root/tak-pki-snapshots`:

```bash
sudo ./pki-snapshot.sh save before-rotate
sudo ./pki-snapshot.sh list
sudo ./pki-snapshot.sh diff before-rotate     # which files a job touched
sudo ./pki-snapshot.sh restore before-rotate  # stops TAK, puts the files back, starts TAK
```

## Reporting what happened, as text

Every job's output is also written to `logs/<time>-<job>.log` (mode 600, newest 60 kept), and
the terminal panel has a **Copy** button. For a full picture of the server's certificate state
with every password redacted:

```bash
sudo ./collect-report.sh > report.txt
```

It prints the OS, the TAK Server package version and what `takserver.war` says, the certificate lines of `CoreConfig.xml`, the `certs/files`
listing, every CA and client certificate's issuer and expiry, what 8443 presents right now, the
live truststore's entries, the certificate table grouped by issuer, the newest portal job logs,
and the TLS-related lines of `takserver-messaging.log`. Paste that instead of a screenshot.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests build a throwaway PKI with `openssl` and exercise the parsing, CoreConfig patching,
trust-list decisions and the connection package without touching a TAK Server.

Every job (create client, signer switch, intermediate rotation with a device attached, revoke
with and without live devices on the CA, root rotation) has been run against a throwaway
installTAK server on Ubuntu 24.04 with Let's Encrypt on 8446. An ATAK device
enrolled by username and password stayed connected across an intermediate rotation with a
root-signed server certificate, was refused after its CA was revoked, and re-enrolled.

## Not covered

Containerised TAK Server (no `tak` user on the host), Federation Hub certificates, Let's Encrypt
on 8446 (a keystore named `*-le.*` is kept across a root rotation but not managed), LDAP, TLS or
an external database for TerraTAK (Helidon config files in `/opt/terratak-config/` are the place
for those).

# Security Policy

## Why this file exists

zeek-otx sits in two places that make a bug here worse than a bug in an
ordinary script.

It **runs as root, hourly, on a sensor.** The Security Onion installer clones a
pinned revision to `/opt/zeek/share/zeek-otx` and drives it from `/etc/cron.d`.
Anything that gets code or a path into that tree runs with the sensor's full
privileges, on a box whose whole job is watching a network it is trusted to see.

It **ingests third-party content.** The OTX pulses it fetches are written by
other people. A pulse name, reference URL or indicator is attacker-influenced
input, and it is transformed into a tab-separated file that Zeek then loads as
its Intel feed. `clean_field()` in `scripts/zeek-otx.py` exists precisely
because an unescaped tab or newline in a pulse field would otherwise let a
pulse author add, alter or suppress rows in that feed.

A researcher who finds either class of problem needs somewhere to send it that
is not a public issue.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | Yes |
| The revision pinned by `OTX_REV` in `install-so2.sh` | Yes |
| Anything older | No — please reproduce against `main` first |

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**:
**Security → Report a vulnerability** on
<https://github.com/SackOfHacks/zeek-otx/security/advisories/new>.

Do not open a public issue for a suspected vulnerability.

Please include, as far as you have it:

- what zeek-otx does that it should not, and what you expected instead;
- how you invoked it, and the relevant parts of `zeek-otx.conf` **with the API
  key removed**;
- a minimal pulse or API response that reproduces it — synthetic, please, not a
  dump of your subscriptions;
- the commit you tested, the Python version and the platform.

Expect an acknowledgement within 7 days and an assessment within 30. If the
report is confirmed, the fix and the advisory are published together, and you
are credited unless you would rather not be.

### Never send your API key

An OTX API key is a credential for your account and your subscriptions. It does
not belong in an issue, an advisory, a log excerpt or a config file attached to
either. If you think you have leaked one, rotate it at
<https://otx.alienvault.com/api> first and report second.

## Scope

In scope:

- **Intel-feed injection.** Any pulse field that can add, modify or remove a row
  in the generated Intel file, break out of a column, or forge `meta.source`,
  `meta.url` or `meta.do_notice`. A pulse author steering what the sensor
  alerts on — or silencing it — is the headline threat here.
- **Anything running as root that should not.** Command injection through a
  config value, a pulse field or a filename; a path written outside the
  configured `outfile`; a symlink or TOCTOU race on the temporary file or the
  atomic replace.
- **The installer.** `install-so2.sh` runs as root and fetches code: an
  unverified or substitutable revision, a writable path in the deployed tree, a
  cron or logrotate file that can be edited by a non-root account.
- **Credential exposure.** The API key reaching a log, the process table, a
  world-readable file, or any host other than the OTX API.
- **Denial of the feed.** A malformed API response that leaves the Intel file
  truncated, empty or stale without that being obvious — a sensor that has
  quietly stopped matching indicators is a security problem, not an outage.
- Crashes, hangs or unbounded memory growth while parsing an API response.

Out of scope:

- The contents of the pulses themselves. Bad, wrong or malicious *indicators*
  are an OTX data-quality matter — report those to AlienVault. The concern here
  is only what a pulse can do to the file format and to the host.
- Findings that need an attacker to already be root on the sensor, or to already
  hold the API key.
- Vulnerabilities in `requests`, Zeek or Security Onion — please report those
  upstream. Tell us anyway if zeek-otx's usage makes one exploitable when it
  otherwise would not be.
- Automated scanner output with no demonstrated impact.

## Notes for operators

- The generated Intel file defaults to mode `0640`. It is the list of what your
  sensor is watching for; do not widen it without a reason.
- Keep `zeek-otx.conf` at `0600`. The installer sets this; a hand-rolled
  install should too.
- The `OTX_REV` pin is a review control, not a formality. It exists so that you
  can read exactly what will run as root every hour before it does. CI enforces
  that the pin covers the deployed tree — see `.github/check-pin.sh`.

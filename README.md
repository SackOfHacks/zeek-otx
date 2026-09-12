# zeek-otx

Scripts to add AlienVault's OTX intel feed to Zeek.

`zeek-otx.py` pulls the pulses you are subscribed to from the OTX API and
rewrites them as a [Zeek Intel framework](https://docs.zeek.org/en/master/frameworks/intel.html)
file, so that Zeek alerts on the indicators they contain. An installer is
included for Security Onion 2; the script also runs standalone on any Zeek host.

## Requirements

- A free AlienVault OTX API key. Sign up at <https://otx.alienvault.com/> and
  take the key from <https://otx.alienvault.com/api>, then subscribe to the
  pulses you want — the script fetches *your subscriptions*, so a fresh account
  with none produces an empty feed.
- Python 3.
- The Python `requests` module — the only third-party dependency. On
  Debian/Ubuntu (including Security Onion) `apt-get install python3-requests`;
  otherwise `python3 -m pip install -r requirements.txt`.

## Install on Security Onion 2

```
git clone https://github.com/SackOfHacks/zeek-otx.git
cd zeek-otx
chmod +x install-so2.sh
sudo ./install-so2.sh
```

The installer clones a **pinned revision** of this repository to
`/opt/zeek/share/zeek-otx`, prompts for your API key, writes the feed to
Security Onion's Salt-managed intel directory
(`/opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat`), installs an
hourly cron job and a logrotate config, and restarts Zeek.

It pins rather than tracking `main` because the cloned tree runs as root every
hour: you should be able to review exactly what will run. The pin is
`OTX_REV` at the top of `install-so2.sh`.

After the initial install it can take a few minutes for Zeek to start using the
feed. See [Verifying](#verifying) below.

### Updating

Re-run the installer. It resets the checkout to the current pin on every run,
so an upgrade is just:

```
cd zeek-otx
git pull
sudo ./install-so2.sh
```

You will be asked for your API key again — the checkout is reset, so the
previously configured copy of the config is replaced.

To install a revision other than the pinned default (after reviewing the diff —
this is root-executed code), export it:

```
sudo OTX_REV=<40-character commit sha> ./install-so2.sh
```

### Uninstalling

```
sudo rm -f /etc/cron.d/zeek-otx /etc/logrotate.d/zeek-otx
sudo rm -rf /opt/zeek/share/zeek-otx
sudo rm -f /opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat
```

Then restart Zeek.

## Standalone use

`scripts/zeek-otx.py` has no Security Onion dependencies. Copy `scripts/` where
you like, fill in `zeek-otx.conf`, and run it:

```
python3 zeek-otx.py --config /path/to/zeek-otx.conf
```

`--config` defaults to `zeek-otx.conf` **in the current working directory**, so
under cron either pass the path explicitly or set a working directory. The
installer rewrites that default to an absolute path for exactly this reason.

Keep the config mode `0600` and owned by the account that runs the script; it
holds your API key.

To have a plain (non-Security-Onion) Zeek load the generated feed, add the
package directory to `local.zeek`:

```
@load /opt/zeek/share/zeek-otx/scripts
```

and set `ZeekOTX::intel_file` if your `outfile` is not the default path. That
loader also enables **hashing of every file Zeek reassembles**, because the
feed's `FileHash-*` indicators cannot match otherwise. It is not free on a busy
sensor — see `scripts/file-hashing.zeek`, and comment out the `@load
./file-hashing` line in `scripts/__load__.zeek` if you would rather not pay it.

Security Onion 2 does **not** need this; its own intel pipeline picks up the
file the installer writes.

## Configuration

`scripts/zeek-otx.conf`, section `[otx]`:

| Field | Required | Meaning |
| --- | --- | --- |
| `api_key` | yes | Your OTX API key. |
| `days_of_history` | yes | How far back to ask for modified pulses, in whole days. Each run rewrites the whole feed, so this is the feed's size, not an increment. Default `90`. |
| `outfile` | yes | Where the generated Zeek Intel file is written. The directory must already exist. |
| `do_notice` | yes | `T` or `F` — the `meta.do_notice` column, i.e. whether an Intel match also raises a notice. |
| `outfile_mode` | no | Octal mode for the generated feed. Defaults to `0640`, so the list of indicators the sensor watches for is not readable by every local account. Widen it only if the process consuming the feed cannot otherwise open it. |

## Verifying

```
tail -f /nsm/zeek/logs/current/intel.log
```

Example output, from an `nslookup` of `w0x.host`:

```json
{"ts":"2020-11-25T21:55:18.492845Z","uid":"CAQ5L829XWjptOiFF4","id.orig_h":"172.16.25.123","id.orig_p":58219,"id.resp_h":"9.9.9.9","id.resp_p":53,"seen.indicator":"w0x.host","seen.indicator_type":"Intel::DOMAIN","seen.where":"DNS::IN_REQUEST","seen.node":"zeek","matched":["Intel::DOMAIN"],"sources":["AlienVault OTXv2 - Luhansk Ukraine Gov. Phishing Campaign ID: 5fb83d70906bd27194456779 Author: AlienVault"]}
```

If nothing appears, in order:

```
# Did the fetch run, and did it say anything?
tail /var/log/zeek-otx.log

# Was a feed produced, and can Zeek read it?
ls -l /opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat

# Did Zeek's Intel framework complain at startup?
grep -i intel /nsm/zeek/logs/current/reporter.log
```

A feed the Zeek process cannot open simply does not load — set `outfile_mode`
if that is what `reporter.log` shows.

## Platform support

Security Onion 2 and plain Zeek. The Security Onion **16.04** installer was
removed: that platform is end-of-life, it shipped Bro 2.x, and the script had
drifted into a mix of Bro-era and Zeek-era paths that could no longer work as
written. It remains in the git history if you need it as a starting point.

## License

BSD 3-Clause — see [LICENSE](LICENSE).

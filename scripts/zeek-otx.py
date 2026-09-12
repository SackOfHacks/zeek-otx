#!/usr/bin/env python3

import os
import re
import sys
from argparse import ArgumentParser
from configparser import ConfigParser
from configparser import Error as ConfigError
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    # This runs unattended from cron, so an import failure would otherwise land
    # in the log as a bare traceback. See requirements.txt.
    sys.stderr.write(
        "ERROR: the 'requests' module is not installed.\n"
        "       Install it with 'apt-get install python3-requests' or\n"
        "       'python3 -m pip install -r requirements.txt'.\n")
    sys.exit(1)

# The AlienVault OTX Pulse URL is hard coded.
# If it is ever to change, update the URL below:
#
# HTTPS is mandatory: the API key travels in the X-OTX-API-KEY request header,
# so a plaintext http:// scheme would disclose it to anyone on the network path
# on every (hourly, by default) run.
_URL = 'https://otx.alienvault.com/api/v1/pulses/subscribed'

# Network timeout, in seconds, applied to every OTX API request. Without it a
# stalled connection would hang the hourly cron job indefinitely.
_TIMEOUT = 30

# Default mode applied to the generated Intel file. The feed enumerates exactly
# which indicators the sensor watches for, which is precisely the list an
# attacker with an unprivileged shell on the sensor wants in order to pick
# infrastructure that is not covered. It is created non-world-readable rather
# than at whatever umask the root cron job happens to run with.
#
# Override with 'outfile_mode' in the config when the consuming process does not
# run as the file's owner or group -- for example a Zeek that runs unprivileged
# and reads the feed path directly. A feed Zeek cannot open does not load, and
# nothing in this project surfaces that beyond Zeek's own reporter.log.
_DEFAULT_OUTFILE_MODE = 0o640

# Zeek Intel file header format
_HEADER = b"#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in\n"

# The Zeek Intel framework reads a tab-separated, newline-delimited file, so any
# tab, newline or other control character inside a field would let a Pulse author
# terminate the record early and append arbitrary indicators to the feed. Every
# field is scrubbed with this before it is written.
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f]')

# Mapping of OTXv2 Indicator types to Zeek Intel types, additionally,
# identifies unsupported intel types to prevent errors in Zeek.
_MAP = {
    "IPv4": "Intel::ADDR",
    "IPv6": "Intel::ADDR",
    "domain": "Intel::DOMAIN",
    "hostname": "Intel::DOMAIN",
    "email": "Intel::EMAIL",
    "URL": "Intel::URL",
    "URI": "Intel::URL",
    "FileHash-MD5": "Intel::FILE_HASH",
    "FileHash-SHA1": "Intel::FILE_HASH",
    "FileHash-SHA256": "Intel::FILE_HASH",
}


def fatal(message):
    '''
    Reports an operator-actionable error and exits.

    This script's normal home is an hourly cron job whose output goes to a log
    file nobody reads until something is wrong, so every foreseeable failure
    says what to fix rather than surfacing as a traceback.
    '''

    sys.stderr.write("ERROR: {0}\n".format(message))
    sys.exit(1)


def clean_field(value):
    '''
    Neutralises Zeek Intel field/record delimiters in a single field value.

    Pulse content is authored by third parties, so it is untrusted input: an
    unescaped tab or newline in a Pulse name, reference URL or indicator would
    otherwise inject additional, fully attacker-chosen rows into the intel feed.
    '''

    if value is None:
        return '-'
    cleaned = _CONTROL_CHARS_RE.sub(' ', str(value))
    return cleaned.strip() or '-'


def strip_scheme(url):
    '''
    Removes a leading scheme from a URL indicator.

    Zeek's Intel::URL type stores the URL without its scheme. The strip is
    anchored to the start of the string and applied once, because the previous
    str.replace() was unanchored and global:

      - a scheme repeated inside the URL was also removed, so
        "http://a.test/r?u=http://b.test" became "a.test/r?u=b.test";
      - an indicator with no scheme at all makes urlparse() report an empty
        scheme, which reduced the search pattern to "://" and stripped that
        separator wherever it appeared, so "a.test/r?u=http://b.test" became
        "a.test/r?u=httpb.test".

    Either rewrite silently corrupts the indicator, and a corrupted indicator
    never matches, so the pulse is quietly not detected on.
    '''

    scheme = urlparse(url).scheme
    if not scheme:
        return url
    # urlparse() lower-cases the scheme it reports, the indicator need not be.
    prefix = '{0}://'.format(scheme)
    if url[:len(prefix)].lower() == prefix:
        return url[len(prefix):]
    return url


def read_config(path):
    '''
    Loads and validates the configuration file.

    ConfigParser.read() returns silently when the file does not exist, so the
    absence of a config previously surfaced one step later as a NoSectionError
    traceback that named the section rather than the missing file. Every value
    is validated here so that a bad config is reported once, in terms of the
    field the operator has to correct.
    '''

    if not os.path.isfile(path):
        fatal("configuration file not found: {0}\n"
              "       Pass one with --config, or copy zeek-otx.conf from the\n"
              "       repository and fill in your OTX API key.".format(path))

    config = ConfigParser()
    try:
        config.read(path)
    except (ConfigError, OSError, UnicodeDecodeError) as exc:
        fatal("configuration file {0} could not be parsed: {1}".format(
            path, exc))

    if not config.has_section('otx'):
        fatal("configuration file {0} has no [otx] section.".format(path))

    def required(field):
        value = config.get('otx', field, fallback='').strip()
        if not value:
            fatal("'{0}' is not set in the [otx] section of {1}.".format(
                field, path))
        return value

    key = required('api_key')

    raw_days = required('days_of_history')
    try:
        days = int(raw_days)
    except ValueError:
        fatal("'days_of_history' in {0} must be a whole number of days, "
              "not {1!r}.".format(path, raw_days))
    if days < 1:
        fatal("'days_of_history' in {0} must be at least 1, not {1}.".format(
            path, days))

    outfile = required('outfile')

    # do_notice is written verbatim into the feed's meta.do_notice column, where
    # Zeek parses it as a bool. Anything else makes the Intel framework reject
    # every line of the feed, so it is checked here rather than at load time.
    do_notice = required('do_notice')
    if do_notice not in ('T', 'F'):
        fatal("'do_notice' in {0} must be 'T' or 'F', not {1!r}.".format(
            path, do_notice))

    raw_mode = config.get('otx', 'outfile_mode', fallback='').strip()
    if raw_mode:
        try:
            mode = int(raw_mode, 8)
        except ValueError:
            fatal("'outfile_mode' in {0} must be an octal mode such as 0640, "
                  "not {1!r}.".format(path, raw_mode))
        if not 0 <= mode <= 0o777:
            fatal("'outfile_mode' in {0} must be between 0000 and 0777.".format(
                path))
    else:
        mode = _DEFAULT_OUTFILE_MODE

    return key, days, outfile, do_notice, mode


def _get(key, mtime, limit=20, next_request=''):
    '''
    Retrieves a result set from the OTXv2 API using the restrictions of
    mtime as a date restriction.
    '''

    headers = {'X-OTX-API-KEY': key}
    params = {'limit': limit, 'modified_since': mtime}
    try:
        if next_request == '':
            r = requests.get(_URL, headers=headers, params=params,
                             timeout=_TIMEOUT)
        else:
            r = requests.get(next_request, headers=headers, timeout=_TIMEOUT)
    except requests.RequestException as exc:
        fatal("the OTX request failed: {0}".format(exc))

    # Depending on the response code, return the valid response.
    if r.status_code == 200:
        try:
            return r.json()
        except ValueError:
            fatal("the OTX API returned a malformed (non-JSON) response.")
    if r.status_code == 403:
        fatal("an invalid API key was specified.")
    if r.status_code == 400:
        fatal("an invalid request was made.")
    # Any other status (429 rate limit, 5xx outage, ...) previously fell through
    # and returned None, which surfaced as an opaque TypeError in the caller.
    fatal("the OTX API returned an unexpected status: HTTP {0}.".format(
        r.status_code))


def iter_pulses(key, mtime, limit=20):
    '''
    Creates an iterator that steps through Pulses since mtime using key.
    '''

    # Populate an initial result set, after this the API will generate the next
    # request in the loop for every iteration.
    initial_results = _get(key, mtime, limit)
    for result in initial_results.get('results') or []:
        yield result

    next_request = initial_results.get('next')
    while next_request:
        json_data = _get(key, mtime, next_request=next_request)
        for result in json_data.get('results') or []:
            yield result
        next_request = json_data.get('next')


def map_indicator_type(indicator_type):
    '''
    Maps an OTXv2 indicator type to a Zeek Intel Framework type.
    '''

    return _MAP.get(indicator_type)


def main():
    '''Retrieve intel from OTXv2 API.'''

    parser = ArgumentParser(description='AlienVault OTXv2 Zeek Client')
    parser.add_argument('-c', '--config',
                        help='configuration file path',
                        default='zeek-otx.conf')
    args = parser.parse_args()

    key, days, outfile, do_notice, outfile_mode = read_config(args.config)
    if_in = "-"

    # datetime.now() is naive *local* time, and .isoformat() on a naive value
    # emits no UTC offset, so the API received a bare timestamp and read it as
    # UTC. That shifted the requested window by the host's offset: east of UTC
    # the window started late and pulses modified in the gap were never fetched,
    # silently. An offset-aware value is unambiguous whatever the API assumes.
    mtime = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    outdir = os.path.dirname(os.path.abspath(outfile))
    if not os.path.isdir(outdir):
        fatal("the directory for 'outfile' does not exist: {0}\n"
              "       Create it, or point 'outfile' somewhere that "
              "exists.".format(outdir))

    tmpfile = outfile + '.tmp'
    # The mode argument to os.open() is masked by the umask, so it is also set
    # explicitly. Both happen before any indicator is written, so the feed is
    # never briefly world-readable.
    try:
        fd = os.open(tmpfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                     outfile_mode)
    except OSError as exc:
        fatal("cannot write the intel feed to {0}: {1}".format(tmpfile, exc))
    os.chmod(tmpfile, outfile_mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(_HEADER)
        for pulse in iter_pulses(key, mtime):
            # Intel description for notices. Every interpolated value is Pulse
            # author controlled, so the assembled description is scrubbed of
            # delimiters before use.
            description = clean_field(
                'AlienVault OTXv2 - %s ID: %s Author: %s' % (
                    pulse.get(u'name'),
                    pulse.get(u'id'),
                    pulse.get(u'author_name')))
            for indicator in pulse.get(u'indicators') or []:
                zeek_type = map_indicator_type(indicator.get(u'type'))
                if zeek_type is None:
                    continue
                try:
                    url = pulse[u'references'][0]
                except (IndexError, KeyError, TypeError):
                    url = 'https://otx.alienvault.com'
                fields = [clean_field(indicator.get(u'indicator')),
                          (zeek_type),
                          (description),
                          clean_field(url),
                          clean_field(do_notice),
                          clean_field(if_in)]
                if fields[1] == "Intel::URL":
                    fields[0] = strip_scheme(fields[0])
                f.write(('\t'.join(fields) + '\n').encode('utf-8'))

    os.replace(tmpfile, outfile)


if __name__ == '__main__':
    main()

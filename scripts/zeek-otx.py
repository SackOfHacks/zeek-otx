#!/usr/bin/env python3

import re
import requests
import sys
import os

from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime, timedelta
from urllib.parse import urlparse

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
        print("The OTX request failed: {0}".format(exc))
        sys.exit(1)

    # Depending on the response code, return the valid response.
    if r.status_code == 200:
        try:
            return r.json()
        except ValueError:
            print("The OTX API returned a malformed (non-JSON) response.")
            sys.exit(1)
    if r.status_code == 403:
        print("An invalid API key was specified.")
        sys.exit(1)
    if r.status_code == 400:
        print("An invalid request was made.")
        sys.exit(1)
    # Any other status (429 rate limit, 5xx outage, ...) previously fell through
    # and returned None, which surfaced as an opaque TypeError in the caller.
    print("The OTX API returned an unexpected status: HTTP {0}.".format(
        r.status_code))
    sys.exit(1)

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

    config = ConfigParser()
    config.read(args.config)
    key = config.get('otx', 'api_key')
    days = int(config.get('otx', 'days_of_history'))
    outfile = config.get('otx', 'outfile')
    do_notice = config.get('otx', 'do_notice')
    if_in = "-"

    mtime = (datetime.now() - timedelta(days=days)).isoformat()

    with open(outfile + '.tmp', 'wb') as f:
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
                    parsed = urlparse(fields[0])
                    fields[0] = parsed.geturl().replace(
                        '{0}://'.format(parsed.scheme), '')
                f.write(('\t'.join(fields) + '\n').encode('utf-8'))

    os.rename(outfile + '.tmp', outfile)

if __name__ == '__main__':
    main()

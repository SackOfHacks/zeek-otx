#!/bin/bash
set -euo pipefail

# The tree cloned below is executed as root, once immediately and then hourly
# from cron, so it is pinned to a reviewed revision instead of whatever main
# happens to point at when the installer is run.
#
# To move to a newer revision, either edit the default here or export OTX_REV
# before running -- both take effect, because the checkout is reset to this
# value on every run rather than only on a fresh clone. Review the diff first;
# this is code that runs as root on a sensor.
#
# .github/workflows/ci.yml fails the build if anything under scripts/ or this
# installer changes without the pin being bumped, which is how the pin went
# stale the first time.
OTX_REV="${OTX_REV:-37bd2a74b001e6c7f9b975b59f9b1fb297596cd4}"

OTX_URL="https://github.com/SackOfHacks/zeek-otx.git"

# Define the zeek-otx install folder variable
OTX_PATH="/opt/zeek/share/zeek-otx"
OTX_OUTFILE="/opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat"

OTX_SCRIPT="$OTX_PATH/scripts/zeek-otx.py"
OTX_CONF="$OTX_PATH/scripts/zeek-otx.conf"
OTX_LOG="/var/log/zeek-otx.log"


# This installer writes to /opt and /etc/cron.d and installs a root cron job.
if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: this installer must be run as root." >&2
	exit 1
fi


# Everything this installer needs, checked before anything is written. The
# fetch below used to be the first thing to notice a missing 'requests', and it
# runs after the API key has been written but before the cron job is installed
# -- so a missing dependency left a half-install that could never retry itself.
echo
echo "Checking prerequisites ..."
missing=0
for cmd in git python3; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "ERROR: '$cmd' is not installed." >&2
		missing=1
	fi
done
if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import requests' >/dev/null 2>&1; then
	echo "ERROR: the Python 'requests' module is not installed." >&2
	echo "       Install it with 'apt-get install python3-requests' (preferred" >&2
	echo "       on Security Onion) or 'python3 -m pip install requests'." >&2
	missing=1
fi
if [ "$missing" -ne 0 ]; then
	echo "Install the above and re-run this script; nothing has been changed." >&2
	exit 1
fi


# Download OTX download and parse script files
echo
echo "Downloading zeek-otx script files ..."
echo
if [ ! -d "$OTX_PATH/.git" ]; then
	if [ -e "$OTX_PATH" ]; then
		echo "ERROR: $OTX_PATH exists but is not a git checkout." >&2
		echo "       Move it aside and re-run." >&2
		exit 1
	fi
	git clone --quiet "$OTX_URL" "$OTX_PATH"
fi

# Bring the checkout to the pin on every run, which is what makes bumping
# OTX_REV an upgrade path rather than advice that cannot be followed: the old
# code checked the existing checkout against the new pin, failed, and told the
# user to bump the constant they had just bumped.
#
# Only fetch when the pin is not already in the local object store, so that
# re-running on a sensor with no egress still works.
if ! git -C "$OTX_PATH" cat-file -e "${OTX_REV}^{commit}" 2>/dev/null; then
	git -C "$OTX_PATH" fetch --quiet origin
fi
if ! git -C "$OTX_PATH" cat-file -e "${OTX_REV}^{commit}" 2>/dev/null; then
	echo "ERROR: revision $OTX_REV does not exist in $OTX_URL." >&2
	echo "       Check the value of OTX_REV." >&2
	exit 1
fi

# reset --hard, not checkout: the configuration step below rewrites tracked
# files in place, so the tree is dirty from the second run onwards and a plain
# checkout would refuse. Nothing of value lives here -- the API key is
# re-prompted and re-written further down.
git -C "$OTX_PATH" reset --hard --quiet "$OTX_REV"

if [ "$(git -C "$OTX_PATH" rev-parse HEAD)" != "$(git -C "$OTX_PATH" rev-parse "${OTX_REV}^{commit}")" ]; then
	echo "ERROR: $OTX_PATH is not at the pinned revision $OTX_REV." >&2
	echo "       Remove $OTX_PATH and re-run." >&2
	exit 1
fi

if [ ! -f "$OTX_SCRIPT" ] || [ ! -f "$OTX_CONF" ]; then
	echo "ERROR: $OTX_PATH does not contain the expected scripts/ files." >&2
	exit 1
fi

# The hourly cron job below runs zeek-otx.py as root, so nothing in the install
# path may be writable by a non-root user.
chown -R root:root "$OTX_PATH"
chmod -R go-w "$OTX_PATH"

# zeek-otx.py refuses to write into a directory that does not exist rather than
# creating one, so make sure the Salt-managed intel directory is there.
mkdir -p "$(dirname "$OTX_OUTFILE")"


# Get the OTX API key from user
echo
echo "Please provide your Alienvault OTX API key! [ENTER]:"
echo "(Input field is hidden)"
echo
read -r -s APIKEY
if [ -z "$APIKEY" ]; then
	echo "ERROR: no API key was entered." >&2
	exit 1
fi


# Configure script files
echo "Configuring ZEEK OTX script files..."
echo
# Restrict the config before the key is written into it.
chmod 600 "$OTX_CONF"
# The key is passed through the environment rather than as an argument: a
# command line is world-readable via ps, which would defeat the hidden prompt
# above. It is also never interpolated into a sed replacement, where a |, & or
# \ in the key would corrupt (or escape) the substitution.
APIKEY="$APIKEY" OTX_CONF="$OTX_CONF" OTX_OUTFILE="$OTX_OUTFILE" \
	python3 - <<'PY'
import os
import re

conf = os.environ['OTX_CONF']
api_key = os.environ['APIKEY']
outfile = os.environ['OTX_OUTFILE']

with open(conf) as handle:
    text = handle.read()

# A callable replacement is used so that the value is substituted literally;
# a plain string would have backslash escapes expanded by re.sub().
text = re.sub(r'(?m)^api_key.*$', lambda _: 'api_key = ' + api_key, text)
text = re.sub(r'(?m)^outfile.*$', lambda _: 'outfile = ' + outfile, text)

with open(conf, 'w') as handle:
    handle.write(text)
PY
chmod 600 "$OTX_CONF"
unset APIKEY
sed -i "s|default='zeek-otx.conf'|default='$OTX_CONF'|" "$OTX_SCRIPT"


# The cron job and log rotation go in before the first fetch, not after. The
# first fetch talks to a third-party API over the network, so it is the step
# most likely to fail on an otherwise fine install -- and if it takes the rest
# of the installer down with it, there is no scheduled run to recover on.
echo "Adding cron job...will run hourly to pull new pulses"
echo
cat << EOF > /etc/cron.d/zeek-otx
# /etc/cron.d/zeek-otx
#
# crontab entry to manage Zeek OTX pulse updates

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 * * * * root python3 $OTX_SCRIPT >> $OTX_LOG 2>&1
EOF
chown root:root /etc/cron.d/zeek-otx
chmod 644 /etc/cron.d/zeek-otx

if [ -d /etc/logrotate.d ]; then
	echo "Adding logrotate config for $OTX_LOG"
	echo
	install -o root -g root -m 644 \
		"$OTX_PATH/scripts/zeek-otx.logrotate" /etc/logrotate.d/zeek-otx
fi


# Run the OTX Pulse retrieval script for first time
echo "Pulling OTX Pulses for the first time..."
echo
if python3 "$OTX_SCRIPT"; then
	first_run_ok=1
else
	first_run_ok=0
	echo
	echo "WARNING: the first OTX fetch failed (see the error above)." >&2
	echo "         The cron job is installed, so the next hourly run will" >&2
	echo "         retry. Check $OTX_LOG, or run it by hand:" >&2
	echo "           sudo python3 $OTX_SCRIPT" >&2
	echo
fi


# Restart Zeek
echo "Restarting Zeek..."
echo
if command -v so-zeek-restart >/dev/null 2>&1; then
	so-zeek-restart
else
	echo "WARNING: so-zeek-restart not found; restart Zeek yourself to pick" >&2
	echo "         up the new intel feed." >&2
fi

if [ "$first_run_ok" -eq 1 ]; then
	echo "Done!"
else
	echo "Done, with warnings -- see above."
fi
echo

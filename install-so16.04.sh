#!/bin/bash
set -euo pipefail

# Define the zeek-otx install folder variable
OTX_PATH="/opt/bro/share/bro/site/otx"
OTX_OUTFILE="/opt/bro/share/zeek/intel/otx.dat"
LOCAL_BRO="/opt/bro/share/zeek/site/local.bro"


# This installer writes to /opt and /etc/cron.d and installs a root cron job.
if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: this installer must be run as root." >&2
	exit 1
fi


# Download OTX download and parse script files
echo
echo "Downloading zeek-otx script files ..."
echo
if [ ! -d "$OTX_PATH" ]; then
	git clone https://github.com/SackOfHacks/zeek-otx.git "$OTX_PATH"
else
	echo "ZEEK-OTX files directory already exists!"
fi

# Fail closed rather than continuing in the caller's working directory: the
# steps below copy and delete files relative to the install path.
cd "$OTX_PATH" || { echo "ERROR: cannot enter $OTX_PATH" >&2; exit 1; }
if [ -d scripts ]; then
	cp -av scripts/* .
	rm -rf scripts
fi

# The hourly cron job below runs zeek-otx.py as root, so nothing in the install
# path may be writable by a non-root user.
chown -R root:root "$OTX_PATH"
chmod -R go-w "$OTX_PATH"


# Get the OTX API key from user
echo
echo "Please provide your Alienvault OTX API key! [ENTER]:"
echo "(Input field is hidden)"
echo
read -r -s APIKEY


# Configure script files
echo "Configuring ZEEK OTX script files..."
echo
if [ -f "$OTX_PATH/zeek-otx.conf" ]; then
	# Restrict the config before the key is written into it.
	chmod 600 "$OTX_PATH/zeek-otx.conf"
	# The key is passed through the environment rather than as an argument: a
	# command line is world-readable via ps, which would defeat the hidden
	# prompt above. It is also never interpolated into a sed replacement, where
	# a |, & or \ in the key would corrupt (or escape) the substitution.
	APIKEY="$APIKEY" OTX_CONF="$OTX_PATH/zeek-otx.conf" OTX_OUTFILE="$OTX_OUTFILE" \
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
	chmod 600 "$OTX_PATH/zeek-otx.conf"
fi
unset APIKEY
if [ -f "$OTX_PATH/zeek-otx.py" ]; then
	sed -i "s|default='zeek-otx.conf'|default='$OTX_PATH/zeek-otx.conf'|" "$OTX_PATH/zeek-otx.py"
fi


# Add to local.bro
echo "Adding @load to local.bro"
if ! grep -q otx "$LOCAL_BRO"; then
        echo '@load site/otx' >> "$LOCAL_BRO"
else
        echo "@load site/otx already exists in $LOCAL_BRO!"
fi



# Run the OTX Pulse retrieval script for first time
echo "Pulling OTX Pulses for the first time..."
echo
if [ -f "$OTX_PATH/zeek-otx.py" ]; then
	/usr/bin/python3 "$OTX_PATH/zeek-otx.py"
fi


# Add a cron job to fetch hourly pulse updates
echo "Adding cron job...will run hourly to pull new pulses"
echo
cat << EOF > /etc/cron.d/zeek-otx
# /etc/cron.d/zeek-otx
#
# crontab entry to manage Zeek OTX pulse updates
 
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
 
0 * * * * root python3 $OTX_PATH/zeek-otx.py >> /var/log/zeek-otx.log 2>&1
EOF
chown root:root /etc/cron.d/zeek-otx
chmod 644 /etc/cron.d/zeek-otx


# Restart Zeek 
echo "Restarting Zeek..."
echo
so-zeek-restart
echo "Done!"
echo

#!/bin/bash

# Define the zeek-otx install folder variable
OTX_PATH="/opt/zeek/share/zeek-otx"


# Download OTX download and parse script files
echo
echo "Downloading zeek-otx script files ..."
echo
if [ ! -d $OTX_PATH ]; then
	git clone https://github.com/SackOfHacks/zeek-otx.git $OTX_PATH
else
	echo "ZEEK-OTX files directory already exists!"
fi
cd $OTX_PATH
if [ -d scripts ]; then
	cp -av scripts/* .
	rm -rf scripts
fi 


# Get the OTX API key from user
echo
echo "Please provide your Alienvault OTX API key! [ENTER]:"
echo "(Input field is hidden)"
echo
read -s APIKEY


# Configure script files
echo "Configuring ZEEK OTX script files..."
echo
if [ -f $OTX_PATH/zeek-otx.conf ]; then
	sed -i "s|api_key.*|api_key = $APIKEY|" $OTX_PATH/zeek-otx.conf
	sed -i "s|outfile.*|outfile = /opt/so/saltstack/local/salt/zeek/policy/intel/intel.dat|" $OTX_PATH/zeek-otx.conf
fi 
if [ -f $OTX_PATH/zeek-otx.py ];then
	sed -i "s|default='zeek-otx.conf'|default='$OTX_PATH/zeek-otx.conf'|" $OTX_PATH/zeek-otx.py
fi 


# Run the OTX Pulse retrieval script for first time
echo "Pulling OTX Pulses for the first time..."
echo
if [ -f $OTX_PATH/zeek-otx.py ]; then
	/usr/bin/python3 $OTX_PATH/zeek-otx.py
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


# Restart Zeek 
echo "Restarting Zeek..."
echo
so-zeek-restart
echo "Done!"
echo

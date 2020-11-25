# zeek-otx
Repository of scrips to add AlienVault's OTX intel feed to zeek

The scripts works with a (free) API key from AlienVault's OTX feed. Obtain a key by signing up for the OTX service here:
https://otx.alienvault.com/


The zeek-otx.py script can be run independently, or to install on a SecurityOnion 2 machine: 

  git clone https://github.com/SackOfHacks/zeek-otx.git

  cd zeek-otx

  chmod +x install-so2.sh

  sudo ./install-so2.sh


After initial install it might take a few minutes for Zeek to start using the intel feed. You can monitor results with the following command:

  tail -f /nsm/zeek/logs/current/intel.log

(example output for running a nslookup on "w0x.host"):
...
{"ts":"2020-11-25T21:55:18.492845Z","uid":"CAQ5L829XWjptOiFF4","id.orig_h":"172.16.25.123","id.orig_p":58219,"id.resp_h":"9.9.9.9","id.resp_p":53,"seen.indicator":"w0x.host","seen.indicator_type":"Intel::DOMAIN","seen.where":"DNS::IN_REQUEST","seen.node":"zeek","matched":["Intel::DOMAIN"],"sources":["AlienVault OTXv2 - Luhansk Ukraine Gov. Phishing Campaign ID: 5fb83d70906bd27194456779 Author: AlienVault"]}
...

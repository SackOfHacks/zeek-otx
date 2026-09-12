##! Loads the generated AlienVault OTX feed into Zeek's Intel framework.
##!
##! This package is for a plain Zeek install, where you add
##!
##!     @load /opt/zeek/share/zeek-otx/scripts
##!
##! to local.zeek. Security Onion 2 does not need it: install-so2.sh writes the
##! feed into Security Onion's own Salt-managed intel directory, and Security
##! Onion loads it for you.
##!
##! If your feed is not at the default path below, redef it from local.zeek
##! *before* loading this script:
##!
##!     redef ZeekOTX::intel_file = "/path/to/otx.dat";

@load frameworks/intel/seen
@load frameworks/intel/do_notice

# FileHash-MD5/SHA1/SHA256 indicators only ever match if Zeek is hashing the
# files it sees, which it does not do by default. That hashing is not free --
# see scripts/file-hashing.zeek for the cost. Comment this line out if you do
# not want it; the other indicator types are unaffected.
@load ./file-hashing

module ZeekOTX;

export {
	## Path to the Intel file written by zeek-otx.py. Must match the
	## 'outfile' setting in zeek-otx.conf.
	const intel_file = "/opt/zeek/share/zeek-otx/otx.dat" &redef;
}

redef Intel::read_files += {
	ZeekOTX::intel_file
};

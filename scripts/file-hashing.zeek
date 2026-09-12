##! Enables MD5/SHA1/SHA256 hashing of every file Zeek reassembles.
##!
##! Roughly a third of the indicator types this feed carries are FileHash-MD5,
##! FileHash-SHA1 and FileHash-SHA256, and Zeek cannot match any of them unless
##! it is hashing files. It does not do that by default, which is why this is
##! loaded from __load__.zeek.
##!
##! The cost is real and is paid on every file, not only on files that match:
##! Zeek has to reassemble each one and run three digests over it, which on a
##! high-throughput sensor shows up as worker CPU and as memory held for
##! in-flight file reassembly. On a sensor that is already dropping packets,
##! this will make that worse.
##!
##! To turn it off, comment out the `@load ./file-hashing` line in
##! __load__.zeek. The ADDR, DOMAIN, EMAIL and URL indicators in the feed keep
##! working; only the file-hash ones go quiet.

@load frameworks/files/hash-all-files

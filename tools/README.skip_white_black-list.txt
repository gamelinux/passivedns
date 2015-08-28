# PassiveDNS (https://github.com/gamelinux/passivedns)
# Example file for skiplist, whitelist and blacklist to be read from pdns2db.pl 
# Lines starting with # are not processed.

# Example 1: STATIC DOMAINS/IPs
# work with: --skiplist, --whitelist or --blacklist
# One domain on each line. The match has to be exact.
www.google.com
www.facebook.com
www.twitter.com
8.8.8.8
8.8.4.4
current.cvd.clamav.net

# Example 2: PCRE formated DOMAINS/IPs
# work with: --skiplist-pcre, --whitelist-pcre or --blacklist-pcre
# One domain on each line.
\.google\.com$
\.facebook\.com$
\.twitter\.com$
antivirus
\.3322\.org$
# blacklist type of services
\.mailserveren\.com$
\.sorbs\.net$
\.spamcop\.net$
\.list\.dnswl\.org$
\.(zen|sbl|dbl)\.spamhaus\.org$
\.bb\.barracudacentral\.org$
\.mailspike\.net$
\.score\.senderscore\.com$
\.bondedsender\.org$
\.surbl\.org$
\.uribl\.com$
\.habeas\.com$
\.support-intelligence\.net$
\.in-addr\.arpa$

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

## Stuff that you might wan to skip:
\.ping\.clamav\.net$
\.current\.cvd\.clamav\.net$
-adfe2ko9\.senderbase\.org$
\.hashserver\.cs\.trendmicro\.com$
\.sbl-xbl\.spamhaus\.org$
\.mail-abuse\.com$
\.zen\.spamhaus\.org$
\.r\.mail-abuse\.com$
\.avqs\.mcafee\.com$
\.channel\.facebook\.com$
.channel\.facebook\.com$
.channel\d{2}\.facebook\.com$



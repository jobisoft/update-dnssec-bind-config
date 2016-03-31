# update-dnssec-bind-config #

I wanted to enable DNSSEC for my domains, so the first step was to setup two public DNS servers managing my domains. But I did not want to have my DNSSEC keys out in the open, so I decided that the signing should be done at a save place on a computer which is not accessible from the internet (behind a router/firewall).

I decided to not use any database but just plain text files and thus choose the standard BIND zone file format. I also do not use the NOTIFY method, because that would require my signing computer to be seen by my public DNS servers. Instead, there is no need at all to have a DNS server running on the signing computer: The signed zone files are pushed via SCP to the actual DNS servers, which monitor their local files with incron and reload the DNS server on changes. Both my public DNS servers are running as masters. Alternatively, one could setup them up as master and slave and only push the signed zone files to the master.

As a second objective, I wanted to reduce redundancy in my zone files, so I implemented a simple template system, which allows me to reuse SOA records, use IP-variables in the records and auto-generated the named.conf.local file (all options are defined in the zone files).

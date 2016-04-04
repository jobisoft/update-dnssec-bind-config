# update-dnssec-bind-config #

I wanted to enable DNSSEC for my domains, so the first step was to setup two public DNS servers managing my domains. But I did not want to have my DNSSEC keys out in the open, so I decided that the signing should be done at a save place on a computer which is not accessible from the internet (behind a router/firewall).

I decided to not use any database but just plain text files and thus choose the standard BIND zone file format. I also do not use the NOTIFY method, because that would require my signing computer to be seen by my public DNS servers. Instead, there is no need at all to have a DNS server running on the signing computer: The signed zone files are pushed via SCP to the actual DNS servers, which monitor their local files with incron and reload the DNS server on changes. Both my public DNS servers are running as masters. Alternatively, one could set them up as master and slave and only push the signed zone files to the master.

As a second objective, I wanted to reduce redundancy in my zone files, so I implemented a simple template system, which allows me to reuse SOA records, use IP-variables in the records and auto-generated the named.conf.local file (all options are defined in the zone files).

As a third objective, update-dnssec-bind-config should support my [letsencrypt certificate rollovers](https://github.com/jobisoft/rollover-letsencrypt-certs) and automatically publish the TLSA/DANE records. So this script is run daily by cron and grabs the current TLSA records from my webserver. It also grabs all the public S/MIME keys from my mailserver (which needs them for the [auto-encryption](https://github.com/jobisoft/encrypt-smime) of all incoming non-encrypted mails) and generates/publishes the corresponding SMIMEA records.

## update-dnssec-bind.config.ini #

The script is searching for the ini file in the current working directory. All path defined in the config are relative to the current working directory as well:

```
[GlobalConfig]
TemplateFolder: example/templates
GeneratedZoneFolder: example/generated
named.conf.local: example/named.conf.local

[RemoteUpdates]
; Everytime the generated config changed, it can be pushed
; to remote servers. Add the required update command for
; each server.
ns1: scp -r example/named.conf.local example/generated ns1.domain.net:~/bind/
ns2: scp -r example/named.conf.local example/generated ns2.domain.net:~/bind/
	
[DNSSEC]
; All zones which have a subfolder inside the KeyFolder
; get signed. 
KeyFolder: example/dnssec
; This script is using the zonesigner tool to generate
; the DNSSEC keys (ZSK & KSK) and to actually sign the
; zones. The ZonesignerOptions string is extended by
; " -zone <ZoneName> <ZoneFile>"
; When calling zonesigner, the working directory is set to
; the zone's keyFolder
ZonesignerPath: /usr/sbin/zonesigner
ZonesignerOptions: -algorithm ECDSAP384SHA384 -random /dev/hwrng -endtime 64d --usensec3

[SMIMEA]
; For each SMIME certificate, which should be added as an
; SMIMEA record, add a file to this folder, named as the
; corresponding email adress.
CertsFolder: example/import/smime
; If the content of the CertsFolder must be updated from a
; remote location, set the required update command. 
; Leave it empty, if not needed.
UpdateCmd: scp -p mails.domain.net:~/smime/* example/import/smime

[TLSA]
; For each domain which should get one or more TLSA records,
; add a file (named as its FQDN) which includes pre-generated
; TLSA records (usefull project: rollover-letsencrypt-certs). 
RecordsFolder: example/import/tlsa
; If the content of the RecordsFolder must be updated from a
; remote location, set the required update command. 
; Leave it empty, if not needed.
UpdateCmd: scp -p www.domain.net:~/tlsa/* example/import/tlsa

```
## Remote server config ##

To setup users on the remote servers, who can only connect via scp, the tool `rssh` might be usefull. Adding user:

```
useradd -m -d /home/<user> -s /usr/bin/rssh <user>
```

and edit `/etc/rssh.conf` to enable SCP for all or just the new user. Furthermore a new incrontab is needed:

```
/home/<user>/bind/named.conf.local IN_MODIFY /usr/sbin/service bind9 restart
```

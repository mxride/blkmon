**Monitors a set of target BGP Autonomous Systems for Hostile IPs listed in publicly available Blocklists.**


---

## Obtaining results ##

The consolidated list of Hostile IPs is sent via xmpp chat to a specified group of users.

A simple user web GUI interface is also provided for user "ad hoc" querying.

## What it does in brief ##

The contents of Public blocklists (containing lists of Hostile IPs) are downloaded and parsed. Hostnames are resolved using an efficient bulk Dns lookup.

A public routeserver is used to list the subnets for the target ASNs. This data is loaded into a Balanced Binary Tree for quick searching to determine whether a given Hostile IP is in the target ASNs.

The resulting (hopefully short) list of potential Hostile IPs is then run through a bulk whois lookup. This is used to cross-validate IP-ASN mapping.

## Under the covers ##

Contains Twisted code for telnet, simple TCP, web gui, and dns lookups. Twisted Wokkel is used for xmpp.

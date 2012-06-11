"""cfg module: Configure the application."""

from twisted.words.protocols.jabber.jid import JID

######
#   Constants for output
######

# separate individual values in a particular field
SEP = " | "

# separate individual IP records in a grouped message
DELIM = "\r\n"


######
#   Debug variables and constants
######

DEBUG_OFF = 0
DEBUG_ON = 1
DEBUG_ON_LIST = 2
DEBUG_VERBOSE = 3

#   Turn debugging on / off

debug = DEBUG_OFF

######
#   Blocklists
######

# read / process blocklists every nn hr

DEFER_SECS_BLK = 60 * 60 * 24

"""Define the Blocklists

Each individual Blocklist contains a list of some sort that defines a set of
hostile IPs.

The lists can have various formats:
    * IP V4 address
    * hostnames
    * URLs
    * Cisco ACLs

The application tries to recognize the format and parse the individual elements.

The Blocklists have different functions and purposes:
    * List Cmd & Ctl centers for botnets (eg abuse.ch)
    * List IPs that are actively attacking other IPs (eg SANS Dshield)
    * List IPs that have attacked a probe of some sort

--- Blocklist definitions ---

Each blocklist definition contains:
        a descriptive tag
        the URL pointing to the blocklist to download

--- Acceptable Use ---

Notes about "Acceptable Use"

See Lenny Zeltser's list of malware blocklists for more information (or see
the individual sites' for their "acceptable use" policy)

http://zeltser.com/combating-malicious-software/malicious-ip-blocklists.html
"""

#   2012-5-30 LG Initialize this list using a piecemeal approach in order to
#   work around an unidentified python problem in parsing the syntax of a
#   complex list

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $ Check individual site's "acceptable use" policy before using   $
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

blklist_urls = [['dshield',
        'http://feeds.dshield.org/top10-2.txt']]
                # sans high activity IPs

#blklist_urls.append(['spyeye-ip',
#        'https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist'])
                # IPs including A records for domain names
                                
#blklist_urls.append(['zeus-domain',
#                'http://www.abuse.ch/zeustracker/blocklist.php?download=domainblocklist'])
                # domain names
                
#blklist_urls.append(['zeus-ips',
#        'http://www.abuse.ch/zeustracker/blocklist.php?download=ipblocklist'])
                # ips
                
#blklist_urls.append(['malc0de.com-ips',
#        'http://malc0de.com/bl/IP_Blacklist.txt'])
                # ips
                                
#blklist_urls.append(['malwaredomainlist',
#        'http://www.malwaredomainlist.com/hostslist/ip.txt'])
                # ips
                
#blklist_urls.append(['em-threat-compromised-ips',
#        'http://rules.emergingthreats.net/blockrules/compromised-ips.txt'])
                # ips
                
#blklist_urls.append(['em-threat-block-ips',
#        'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'])
                # ips
                                
#blklist_urls.append(['openbl',
#        'http://www.openbl.org/lists/base.txt'])
                # ips


######
#   Routeserver access
######
"""Telnet to a public Routeserver to list the subnets for specific ASNs.

To reduce loading on the bulk Whois lookup service, the application telnets
to a public routeserver once a week.

All the subnets for the ASNs that interest us are listed. The output is
processed and built into a binary tree for lookups.

If a IP read from a blocklist is in a subnet in the binary tree, then the IP
probably belongs to one of the ASNs being monitored.

Only Cisco public Routeservers are supported.

--- Acceptable Use ---
Some of the public routeservers specify that permission should be asked before
using a scripted or other automated access.

The application takes care not to overload the Routeserver.

Please check the Routeserver's Acceptable Use policy before using.
"""


# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $ Check individual rte server's "acceptable use" policy before using   $
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


# List of public routeservers to access
rteserv_list = [
    "route-views.on.bb.telus.com",
    "route-views.optus.net.au",
    "route-server.ip.tiscali.net",    
    ]


# Download IP subnet data from routeservers / rebuild binary tree every nn days

DEFER_SECS_IP = 60 * 60 * 24 * 7

# Port for telnet access to public routeservers

PORT = 23

# Cisco cmd to list all the subnets for a given BGP ASN

RTESRV_CMD = "show ip bgp regexp _nnnn$"


# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $ Specify the list of target ASNs to be monitored.  $
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$


# Target ASNs: These are the ASNs that are being monitored for hostile IP
# activity. Replace "nnn1" by "1234" (your first tgt ASN), "nnn2" by "4567"
# (your second tgt ASN), and so forth

as_search_list = ['nnn1', 'nnn2', 'nnn3', 'nnn4',
                'nnn5']

# Hit "Enter" every n sec to flush data out of buffers when accessing the
# routeserver using Twisted's telnet 

rs_enter_throttle = 2

# Reduce the load on the Routeserver by looking for nn cmd prompts before
# submitting the next "list" cmd to the Routeserver

rs_as_cmd_throttle = 2

######
#   Sanity check of IP verification
######
"""Check the sanity of the binary tree used for IP lookups

Once the binary tree of IP subnets has been built, the application will look up
an IP (known to be in a target ASN) in the binary tree. This checks that the
routeserver is giving correct information, and that the binary tree has been
properly built.
"""

#   The following IP should be a stable, well-known IP in one of the target
#   ASNs.

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $ Specify some stable well-known IP in one of the target ASNs to be $
# $ monitored. This IP will be used for sanity checking of the        $  
# $ subnet downloads from the public routeserver.                     $
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

# In the following, "xxx.yyy.zzz.www" would be replaced by something like
# "192.168.0.53". AS "nnnn" would be the corresponding ASN eg "1234"

sanity_ip = "xxx.yyy.zzz.www"
sanity_as = "nnnn"

#   If hit we this limit during IP tree sanity checking, then the application
#   will schedule a rebuild of the IP binary tree using the next routeserver in
#   the list.

ip_prob_max = 3

#   The first sanity check at startup will always fail since the binary tree
#   hasn't been built yet.
#   Wait for nn secs after a failure before retrying the sanity check.

#   Retry interval
ip_prob_retry = 60 * 4

######
#   xmpp
######
"""Send a status msg using XMPP

The application sends a consolidated status message listing hostile IPs found to
a set of XMPP userids.

Testing was done using Google Gtalk.
"""

# Leave nn sec between individual xmpp msgs in over not to overload their
# chat server
xmpp_throttle = 3

# This specifies the number of individual IP records to group together in one
# xmpp msg 
numgrp = 9

# This is the max number of xmpp msgs. The application won't send more than this
# number of msgs in one burst.
maxmsgs = 8


# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $$$ Specify the list of Gtalk userids that will receive status msgs. $
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

# This is the list of xmpp userids which will receive the status msg.
xmpp_uids = ["myuid1@gmail.com"]
   
# These are the credentials that the application uses to logon to the xmpp
# server (eg Gtalk, Jabber, or other)

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $$$ You must add your own Gtalk userid and credentials here $$$
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

myjid = JID("myuid2@gmail.com")
mypasswd = 'mypasswd2'

# After all the status messages have been sent, the application logs off until
# the next download cycle starts. This logoff occurs nn sec after last status
# xmpp msg has been sent.
# By logging off each time, the application simplifies the xmpp handling. There
# is no need to process rosters, provide extended presence support and so forth
# in order to convince the chat server that we are still there.

logoff_delay = 120

######
#   Bulk whois lookups to cymru
######
"""Validate ASN information by doing a bulk "whois" lookup

As mentioned above, the application uses a binary lookup to determine which
hostile IPs are probably in the target ASNs being monitored.

To ensure accuracy of the information provided, the application submits the
hostile IP addresses found to a bulk whois lookup server. The responses from
this server are used to update the information in the Hostile IP dictionary.

After this final step, the application produces the consolidated status message
containing the hostile IPs found in the target ASNs.

*** Acceptable use ***

Note that cymru.org severely restricts bulk downloads. Be sure to check their
acceptable use policy before using this application.
"""

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $ Check cymru.org's bulk whois "acceptable use" policy before using   $
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

# server for bulk whois lookups

CYMRU_PORT = 43
CYMRU_IP = "whois.cymru.com"


# To limit load on the cymru whois server, this is the maximum number of IPs
# that the application will submit during one download / lookup process cycle.

cyrmu_max = 20

# After all the blocklists have been read, dns lookups usually occur.
# There can be a lot of these, and they can take some time.
#
# The code to do bulk whois lookups keeps checking
# every so often to see the dns lookups have finally finished.  
# This variable specifies the delay between checks.

cymru_delay = 60 * 5


# All queries to the bulk whois server must start with the "first" cmd, then
# contain a list of IP V4 addresses, then end with the "last" cmd

CYMRU_CMD_FIRST = "begin \n" "countrycode \n"
CYMRU_CMD_LAST = "end \n"


######
#   web interface
######
"""Provide a web interface for user interaction

A rudimentary web interface is provided to allow a user to:
    - Obtain the global status msg listing hostile IPs in the target ASNs.
    - Do a lookup in the Hostile IP dictionary for a specific IP V4 address.
    
The Hostile IP being queried can be any arbitrary IP V4 address (ie does not
have to be in the target ASNs. If the IP address is in the dictionary, the web
server will list what is known about the  IP in question.
"""

# specify the port for web UI access

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
# $ You must replace "nnnnn" by some tcp port. Be sure that firewall policy $
# $ both on the host and on the network perimeter defenses allows this port.$ 
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

web_port = nnnnn



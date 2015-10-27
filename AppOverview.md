# Introduction #

This page gives a brief overview of the application's structure and processing.


# Structure #

Blkmon is a typical twistd application. The main structure can be see in the "blk.tac" file.

Status alerting is handled by the "worker service" object.

There is a global data container object which contains:

  * Hostile IP dictionary: Information on hostile IPs
  * Binary Tree containing all subnets for all target ASNs being monitored
  * Ptr to worker service object
  * Other global counters and variables.

Execution is structured as 2 independent timer loops:

  * Routeserver subnet download
  * Hostile IP blocklist downloads

# Processing #

## Routeserver subnet download ##


Blkmon interacts with a public routeserver to determine all the subnets for all the target ASNs being monitored.

This is done by initiating a telnet session to the rteserver. Currently only Cisco rte servers are supported. The specific cmd used is:

> show ip bgp regexp _nnn$_

where "nnn" is some ASN such as 1234.

Once the list of subnets for the AS has been extracted, Google's ipaddr class is used to compress the AS' address space to the least # of supernets.

Each ASN is listed in turn. The resulting list of subnets is read and processed.

This subnet information is used to build a balanced binary tree structure containing all the subnets for all the BGP Autonomous Systems (AS) that are to be monitored.

Subsequently, when the application wishes to check quickly if a given hostile IP is in one of the target ASNs, a lookup is done using the binary tree.

This approach avoids overloading some whois server with literally thousands of queries in a short time.

### Detailed processing ###

The application code cycles through a list of public routeservers on a timer loop (usually about 1 week / cycle). A single cycle reads in all the subnets for all the target ASNs, and then uses this information to build the binary subnet lookup tree.

When the telnet connection is established with the public routeserver, a
Cisco rtr cmd is built to list the subnets for the 1st tgt BGP ASN.

At the same time a loop is initiated to hit "Enter" from time to time. This helps keep the session alive with some traffic, and also helps flush out the buffers.

As each line of output is rec'd, it is parsed to extract the subnet information. Different formats are possible depending on the version of
Cisco IOS used in the rteserver.

The IP subnet address information is extracted and converted to a Google
Ipaddr object. The Google code does validation of the input data. Finally the Ipaddr subnet object is stored in a list containing all the results.

If a "---More---" is rec'd on the telnet session, then this is the end of a page of output. So the code "hits spacebar" to prompt the delivery of the next page of output.

When finally a cmd prompt is rec'd, this means that all the subnets have
been listed. At this point, the list of subnet objects is sent to Google's "collapse\_address\_list" method to condense the list to the smallest number of supernets. Finally the condensed list of subnets are inserted one by one into the binary tree.

A throttling fn kicks in to count the number of "Enter" rec'd. This slows things down, ensures that all output has been rec'd for the current AS, and generally reduces load on the public routeserver.

Next, a new Cisco cmd is built for the next ASN in the target list.
Everything starts again for this new ASN.

When all the ASNs have been processed, an "exit" cmd is sent to the public rteserver to tear down the telnet session.

## Hostile IP blocklist downloads ##

Blkmon reads all the Hostile IP blocklists on a daily basis.

The contents of the various blocklists are read and parsed to extract known hostile IPs.

This information is consolidated into the Hostile IP dictionary.

As the input lines from the various blocklists are parsed, asynchronous Dns lookups are done to resolve IP addresses. Once the IP V4 address is available, the Hostile IP dictionary is updated with the additional information.

Once all the dns lookups are completed, the entire Hostile
IPs dictionary is enumerated. Each Hostile IP in the dictionary is looked up in the Binary Tree to see if this IP is in one of the target ASN's that are being monitored.

The resulting small group of hostile IPs is submitted to a bulk whois lookup in order to ensure that the IP - ASN mapping is correct. The results from the bulk whois lookup are used to update the Hostile IPs dictionary.

Finally, the Hostile IP dictionary is enumerated once again to produce the final list of hostile IPs in the target ASNs. The worker service object is invoked to send out the new xmpp status message to all authorized xmpp users.

## Worker service utility functions ##

The wrkserv object provides two basic utility services:

  * Does bulk dns lookups
  * Produces and sends xmpp status msgs

### Status msg processing ###

The "worker service" object is used to produce and then persist the Status message.

Once the Hostile IP blocklists have been downloaded and processed, the wrkserv object is invoked to produce and then store the new global Status message.

### Xmpp alerting ###

Once the msg is formatted, the wrkserv method involves a wokkel xmpp client to logon to the xmpp server, and then send out the status msg to the set of authorized xmpp uids. If the status msg is too long, it is chopped into convenient pieces. Throttling also occurs to avoid overloading the xmpp with a burst of chat msgs.

To simplify management of the xmpp session, a logon is done each time the alert msgs are to be sent. After the msgs have been sent, the code logs off the xmpp server.

### Bulk dns lookups ###

The wrkserv object also does bulk dns lookups.

The twistd code is so fast that it can easily overwhelm even a robust host if the dns lookups are allowed to run unhindered.

To overcome this a throttling mechanism was developed. Dns lookups are sent in bursts of 30 or so. The rest of the lookup requests are kept in a wait queue with a variable wait time.

The wait queue elements fire asynchronously depending on the wait time specified. If there is room in the dns request pipeline, the next request is executed. Otherwise the request is sent back to the end of the wait q.

Even on a very slow small PC, the code can execute 17K lookups in 40 min.

## The web interface ##

A simplistic web interface is provided for the user. For the details, see [WebGUI](WebGUI.md)

The Twisted web server is used to provide the web interface.

The html contents are dynamically generated.

### Root web page ###

The root page pulls up the Status msg from the wrkserv object. This message is broken into lines and then output to the user's browser.

### IP lookup form ###

A simple lookup form is also provided to allow the user to query the current contents of the Hostile IPs dictionary. This page is a form which allows the user to enter a specific IP address for lookup in the Hostile IPs dictionary. Information is kept on all the entries read from all blocklists (not just those IPs in the ASNs targeted for monitoring.)

The HTTP POST resulting from the form submit causes the IP Results page to display.

The ip address entered is verified by a regex filter. Then a lookup is
done in the Hostile IPs dictionary for the corresponding entry.

If the address is unknown, or if any exceptions occur, they are trapped,
and a generic msg is sent back to the user's browser. This limits the
information available to a potential attacker.

After the results have been displayed, the user can click on an href to
go back to the initial ip lookup form page.
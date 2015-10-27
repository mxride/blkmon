# Introduction #

This page explains how to use the simple Web GUI interface.


# Accessing the GUI #

To display the web GUI:

http://myserver-address:myTcpPort/

An example URL would be (where port 44338 is specified in the cfg.py file):

http://192.168.1.58:44338/

The root page will display the formatted status msg.

# Doing IP lookups #

An interface is also provided to do lookups of individual IPs in the Hostile IPs dictionary. Information is provided for all IPs downloaded from all the blocklists. (ie not just the IPs in the target ASNs)

To access the form, go to "/ip":

http://192.168.1.58:44338/ip

Enter an IP V4 address in the box provided. If the IP is found in the dictionary, the app will display all known information about this IP.

On the "/ipstatus" page that displays the results of the lookup, click "Continue" to go back to enter another IP.
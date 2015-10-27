# Introduction #

This page describes how to configure the Blkmon application.


# The cfg.py file #

The application is configured using the cfg.py file.

An initial version of this file will be downloaded and installed as part of the application source code.

## Quick start ##

At a bare minimum, the following must be configured in cfg.py:

| as\_search\_list | The target ASNs to monitor |
|:-----------------|:---------------------------|
| sanity\_ip, sanity\_as | A well-known IP in one of the tgt ASNs - to sanity check the rteserver subnet download. |
| xmpp\_uids       | At least one xmpp userid to receive alert msgs |
| myjid, mypasswd  | Xmpp userid / pwd to logon to the xmpp server |
| web\_port        | A tcp port to use for accessing the web GUI user interface |



The following sections describe in more detail how to configure the application.


# Detailed descriptions for configuration #

## debugging ##

Choose one of the following debug levels:

| debug | DEBUG\_OFF / DEBUG\_ON / DEBUG\_ON\_LIST / DEBUG\_VERBOSE |
|:------|:----------------------------------------------------------|

DEBUG\_ON\_LIST will list the contents of main data structures but will not activate full verbose debugging.


## Blocklist reads ##

Each individual Blocklist contains a list of some sort that defines a set of hostile IPs.

The Blocklists have different functions and purposes:
  * List Cmd & Ctl centers for botnets (eg abuse.ch)
  * List IPs that are actively attacking other IPs (eg SANS Dshield)
  * List IPs that have attacked a probe of some sort

For blkmon, each blocklist definition contains:
  * a descriptive tag
  * the URL pointing to the blocklist to download

The application can detect and parse an number of typical blocklist formats. Unit test the blocklist to be sure that this new blocklist's format is properly parsed.

Formats include:

  * IP V4 addresses
  * Dns hostnames
  * Cisco ACLs
  * Web site URLs

Here are the specific configuration variables of interest:

| DEFER\_SECS\_BLK | The delay in seconds between a full blocklist download cycle |
|:-----------------|:-------------------------------------------------------------|
| blklist\_urls.append | Append another blocklist to access. This is a python list containing an acronym for the new blocklist, plus the URL for the blocklist |

**Be sure to look at the blocklist's acceptable use policy before starting any automated downloads.**


## Routeserver access ##

Once a week or so, the application telnets to a public Routeserver to list the subnets for the target ASNs.

This information is built into a Balanced Binary Search Tree. The tree contains all the subnets for all the target ASNs.

Each Hostile IP is looked up to see if it is one of the subnets in the Binary Tree. If not, then the Hostile IP is probably not in one of the target ASNs.

Since thousands of Hostile IPs can potentially be processed, this approach reduces loading on the Whois lookup servers.

Only Cisco public Routeservers are supported.

Variables of interest:

| rteserv\_list | Specifies the list of public routeservers to access |
|:--------------|:----------------------------------------------------|
| DEFER\_SECS\_IP | The time in sec between cycles of rte server downloads. Usually this is about 1 week. |
| as\_search\_list | The list of ASNs to monitor.                        |
| sanity\_ip, sanity\_as | A well-known IP in one of the tgt ASNs - to sanity check the rteserver subnet download. |

The application checks if the routeserver subnet download actually worked by doing a lookup of a well-known, stable IP in the new Binary Tree. If the Tree lookup finds the IP and returns the correct ASN, then processing continues. Otherwise an error loop kicks in that will eventually send the application off to try another routeserver in the list.

**Check the individual routeserver's acceptable use policy before initiating automated downloads.**

## XMPP ##

The application sends status alerts to a set of XMPP userids. Credentials are supplied to the application to logon to an XMPP server in order to send out the chat messages.

Current testing was done with Gtalk.

Here are the relevant variables.

| xmpp\_uids | At least one xmpp userid to receive alert msgs |
|:-----------|:-----------------------------------------------|
| myjid, mypasswd | Xmpp userid / pwd to logon to the xmpp server  |

## Other application configuration ##

A simplistic web GUI interface is provided. This is configured on some non-standard tcp port. To avoid running as root, an unused high Tcp port
> should be used.

| web\_port | A tcp port to use for accessing the web GUI user interface |
|:----------|:-----------------------------------------------------------|

The application also does bulk whois lookups at cymru.org. This is done to cross-validate the Hostile IP - ASN mapping.

**Before doing automated bulk whois lookups using cymru's services, their acceptable use policy should be verified.**
"""blk_ipdict - Provide dictionary of Hostile IPs

*** Purpose ***

This module provides the hostileIPs object. This object contains the Hostile IPs
dictionary. It also provides methodes to build / manage the dictionary.

** Classes **

hostileIPs - Build / manage dictionary of hostile IPs

"""


#####
# imports
#####
import re

import cfg
#from blk_wk_msg import WorkerService

#from blk_state import BlkState

from twisted.python import log

from urlparse import urlparse

######
#   Patterns for parsing input
######

# These patterns determine the type of input being read

PAT_HTTP = "http"
PAT_FTP = "ftp"
PAT_ACL = "deny "


# The following patterns are used to validate input, then extract
# information

# Input line is either:
#       "nn.nn.nn.nn    some description "
#or:
#       "my.hostname.example.com       some description "

re_addr = re.compile("""
(?P<addr>\S+)\s*        # match address (either hostname or ip v4 address)
(?P<desc>.*$)           # match description if any
""",re.VERBOSE)

# Input data is:
#           "nn.nn.nn.nn"

re_ipv4 = re.compile("""
(?P<addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*  # ip v4 address
""",re.VERBOSE)

# Input data is a cisco ACL filter:
#           "deny ip host nn.nn.nn.nn any log   # some description "

re_acl = re.compile(r"""
deny\s
ip\s
host\s
(?P<addr>\S+)\s         # match address
any\s          
log\s*          
(?P<desc>.*$)           # end of string is description
""", re.VERBOSE)


######
# Object which contains the list of hostile IPs and associated information
######


class hostileIPs:
    
    """hostileIPs: Build / manage dictionary of hostile IPs
    
    *** Methods ***
    
    del_all         Delete all the elements in the dictionary
    updt_whois      Update the dictionary with a record from a whois lookup
    insert_blklst_line
                    Parse the input line read from the blocklist, then update
                    the dictionary.
    insert_ip       Insert / update the entry for an ip in the dictionary.
    list_grp        List all the dictionary entries that belong to a given grp.
    list_elt        List one element (=== 1 IP address) in the dictionary.
    list_all        List all the elements in the dictionary.
    
    
    *** Hostile IP Dictionary ***
    
    The Hostile IP dictionary is as follows:
    
    --Key--
    ip              ip address in IPV4 format
    
    --Element--
    
    A dictionary element is a list:
    
    as              Autonomous System Number (ASN) eg 1234
    cc              Country code eg CA
    org             The name of the blocklist (cf cfg.py blklist_urls)
    desc            Other information such as URL, hostname, etc
    
    *** Purpose ***

    This class builds a dictionary object which contains all the hostile IPs
    from all the blocklists that were read on input.
    
    Keeping all the information from all the blocklists allows the web interface
    query fn. Arbitrary specific IPs can be queried to see if they are known to
    be hostile (even if they are not in the ASNs being monitored.).
        
    """
    def __init__(self):
        """Constructor: Initialize the class hostileIPs"""
        self.ip_dict = {}
            
    def del_all(self):
        """Delete all the elements in the dictionary."""
        for ipAdr in self.ip_dict.keys():
            del self.ip_dict[ ipAdr ]
    
    def updt_whois(self, line):
        """ Update the dictionary with a record from the bulk whois lookup.
        
        line    Input line read from whois. Will have format: 
                "as# | n.n.n.n | cc | some description "
        """
        if cfg.debug >= cfg.DEBUG_VERBOSE:         
            log.msg("ipdict: whois: {0}".format(line.strip()))
        
        try:
            myas, myip, mycc, mydesc = line.strip().split('|', 3)
        except ValueError:
            log.err("ipdict: whois line invalid format: {0}".format(line))
            return
        
        myip = myip.strip()
        if myip in self.ip_dict:
            self.insert_ip(myip,               
                    as_ = myas.strip(),
                    cc = mycc.strip(),
                    desc = mydesc.strip()
                    )
        else:
            log.err("ipdict: unknown ip from whois - ignored: {0}".format(line))
            

    def insert_blklst_line(self, line, myorg, dns_lookup_fn):  
        """ Parse the line read from the "myorg" blocklist, then update the
            dictionary.
        
        line    Input line from the "myorg" blocklist. Line will have format:
                n.n.n.n  possibly-some-description
            
        myorg   Organization that produces the list of IPs to block
        
        dns_lookup_fn   Fn to call to schedule a dns lookup.
                This will be in blk_wrk_msg.py - do_lookup.
        
        If the parse uncovers a hostname (instead of an IP V4 address), then a
        dns lookup is scheduled by calling the fn provided.
        """
        
        line = line.strip()
                
        if cfg.debug >= cfg.DEBUG_VERBOSE:
            log.msg("ipdict: input: {0}".format(line))
            
                # ignore blank lines
        if not line:
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("ipdict:  --blank line")
            
        # ignore comments
        
        elif line[0] in r"#!":
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("ipdict: --comment")
             
        # A url of the form "http://my.hostile.ip/dir1/dir2/file.html    

        elif line.startswith((PAT_HTTP, PAT_FTP)):
            uri = urlparse(line)
            if uri.scheme in ['http', 'https', 'ftp']:
                myip = uri.netloc
                mydesc = line.strip()
                
                if cfg.debug >= cfg.DEBUG_VERBOSE:
                    log.msg("ipdict: --url: {0}".format(myip))
                    
                if re_ipv4.match(myip):
                    # update the hostile ip dictionary with this data
                    self.insert_ip(myip, desc=mydesc, org=myorg)
                else:
                    if cfg.debug >= cfg.DEBUG_VERBOSE:
                        log.msg("ipdict:   do dns lookup")
                        
                    # Send this ip to the bulk dns lookup.
                    # This is a deferred action, but in reality the
                    # actual insertion in the Hostile IPs dictionary will
                    # be handled by the dns lookup code. So no need to
                    # define callbacks here.
                    
                    d = dns_lookup_fn(myip, False, mydesc, myorg)
    
        # A cisco IP ACL
    
        elif line.startswith(PAT_ACL):
            m = re_acl.match(line)
            if m:
                if m.group('addr'):
                    myip = m.group('addr')
                    mydesc = m.group('desc')
                    if cfg.debug >= cfg.DEBUG_VERBOSE:
                        log.msg('ipdict: --acl addr:{0} desc: |{1}|'.format(
                            myip, mydesc))
                    
                    assert (re_ipv4.match(myip))

                    # update the hostile ip dictionary with this data
                    self.insert_ip(myip, desc=mydesc, org=myorg)
       
        # otherwise must be a line of the form:
        #   "my.hostile.hostname.com    some description"
        # or
        #   "nnn.nnn.nnn.nnn    some description"
        
        else:        
            m = re_addr.match(line)
            if m.group('addr'):
                myip = m.group('addr')
                mydesc = m.group('desc')
                
                if cfg.debug >= cfg.DEBUG_VERBOSE:
                    log.msg("ipdict: --addr: {0}, descr: |{1}|".format(
                        myip, mydesc))
            
                # if have a hostname then go do the dns lookup                
                if re_ipv4.match(myip):
                    if cfg.debug >= cfg.DEBUG_VERBOSE:
                        log.msg("ipdict: --ip addr: {0}".format(myip))
        
                    # update the hostile ip dictionary with this data
                    self.insert_ip(myip, desc=mydesc, org=myorg)        
                else:
                    if cfg.debug >= cfg.DEBUG_VERBOSE:
                        log.msg("ipdict:   and do dns lookup")
                    d = dns_lookup_fn(myip, False, mydesc, myorg)
            
            # final catch-all case: we don't have a clue what this input is
            else:
                if cfg.debug >= cfg.DEBUG_VERBOSE:
                    log.msg("ipdict: --line ignored, unknown format")
                    


    def insert_ip(self, __ip, desc="", as_="", org="", cc=""):
        """ Insert / update the entry for an ip in the dictionary.
        
        __ip        IP to be updated
        desc        descriptive text
        as_         BGP autonomous system number (if known)
        org         organization that produces the blocklist
                    that listed this IP as hostile
        """
        
        desc = desc.strip()
        
        # if already have an entry, then just update it
                
        if __ip in self.ip_dict:
            as_tmp, cc_tmp ,org_tmp, desc_tmp = self.ip_dict[__ip]

            if as_:
                if not as_tmp:
                    as_tmp = as_
	
        	   # believe it or not, a given IP can have 2 different AS
        	
                elif not (as_ in as_tmp):
                    as_tmp = cfg.SEP.join([as_tmp, as_])
            	
            if cc:
                if not cc_tmp:
                    cc_tmp = cc
                elif not (cc in cc_tmp):
                    cc_tmp = cfg.SEP.join([cc_tmp, cc])
            if org:                                
                if not(org in org_tmp):
                    org_tmp = cfg.SEP.join([org_tmp, org])
            if desc:
                if not(desc in desc_tmp):
                    desc_tmp = cfg.SEP.join([desc_tmp, desc])  
            
        else:
            # This is a new IP address so add it into the list.
            # Verify that this is a legitimate IP V4 ip address
            
            if not(org and re_ipv4.match(__ip)):
                log.err( "ipdict: Invalid input - ignored {0}".format(__ip))
                return              
            as_tmp = as_
            org_tmp = org
            desc_tmp = desc
            cc_tmp = cc
         
        # Update the element in the list
        self.ip_dict[__ip] = (as_tmp, cc_tmp, org_tmp, desc_tmp)
  
    def list_grp(self, as_="", org="", cc=""):
        """ List all the dictionary entries that belong to a given group.
        ___ip       IP of the dictionary entry
        as_         BGP AS # (if known)
        org         Organization producing the blocklist
        cc          Country code
        """
        for __ip in self.ip_dict:
            as_tmp, cc_tmp, org_tmp, desc_tmp = self.ip_dict[__ip]
            
            if ((not as_ or (str(as_) in str(as_tmp))) and
               (not org or (org in org_tmp)) and
               (not cc or (cc in cc_tmp))):
                yield __ip, as_tmp, cc_tmp, org_tmp, desc_tmp  

    def list_elt(self, __ip):
        """List one element (=== 1 IP address) in the dictionary."""
        if not (__ip in self.ip_dict):
            log.msg("ipdict: IP not in list of hostile IPs: {0}".format(__ip))
        else:
            return( self.ip_dict[__ip] )
        
    def list_all(self):
        """List all the elements in the dictionary."""
        for __ip in self.ip_dict:
            yield __ip


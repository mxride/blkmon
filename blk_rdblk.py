"""blk_read: Module to read / process IP blocklists, and do bulk whois lookups

*** Purpose ***

This module has the code for two basic data input functions.
    1) It downloads and processes the various Hostile IP blocklists.
    2) It submits a (small number of) IPs to a bulk whois lookup server
    
THe various Hostile IP blocklists contain lists of Hostile IPs in various
formats. The blocklist data is read by this module and submitted to the
blk_ipdict module for parsing / processing.

Initial screening / filtering produces a relatively small list of Hostile IPs in
the target ASNs being monitored. The second fn of this module is to submit these
IPs to a bulk whois server in order to cross-validate the associated ASNs.

*** Public functions ***

get_blklst      Schedule the download of the blocklist from a given url.
blklst_page_read_ok
                Callback fn that splits the page of data read into lines and
                calls the blk_ipdict module to parse / process the input
cymru_get_whois Download bulk whois information from cymru.org.

*** Public Classes ***

BulkDataProtocol
                Class to manage simple tcp socket protocol
BulkDataFactory Factory class to provide persistence for the protocol and to
                manage connection setup / teardown

"""


#####
# imports
#####
import re

from blk_state import BlkState
import cfg

import twisted.web.client

from twisted.internet import defer, reactor
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.python import log

######
# Constants
######

# matches Ip V4 
IPV4_PAT = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

######
# Download the blocklist file from the associated URL
######
       
def get_blklst(org_name, url, bstate):
    """Schedule the download of the blocklist from the specified url.
    
    org_name        A shorthand acronym to identify this blocklist 
    url             url to access the blocklist
    bstate          global data object
    """
    d = defer.Deferred()
    if cfg.debug >= cfg.DEBUG_ON:
        log.msg("rdblk: schedule dwnld from {0}, url: {1}".format(
                                        org_name, url)
                )
    d = twisted.web.client.getPage(url)
    
    d.addCallback(
            blklst_page_read_ok,
            org_name,
            url,
            bstate
            )
    d.addErrback(
            blklst_error,
            org_name,
            url
            )
    return d

def blklst_page_read_ok(data, org_name, url, bstate):
    """Callback fn fired to process a blklist page of data
    
    data        Input page of data read from the blocklisit url
    org_name    A shorthand acronym to identify this blocklist
    bstate      Ptr to global data container object
    
    This deferred callback is fired when a page of blocklist data has been read
    from the url.
    The fn splits the data into separate lines and then calls the
    insert_blklst_line() method in blk_ipdict module to parse / process the
    input data line.
    """
    
    if cfg.debug >= cfg.DEBUG_ON:
        log.msg("rdblk: Read page from {0}, url: {1}".format(org_name, url))
    
    # ptr to hostile IPs dictionary
    my_dict = bstate.get_dict()
    # ptr to worker service object    
    wrk_serv = bstate.get_wrk_serv()   
        
    for line in data.splitlines():
        my_dict.insert_blklst_line(line, org_name, wrk_serv.do_lookup)
  
def blklst_error(failure, org_name, url):
    """Callback fn: Handle an error reading the blocklist
    
    failure     twisted object representing the failure reason
    org_name    A shorthand acronym to identify this blocklist
    url         The blocklist url being accessed
    """
    log.err("Error getting blocklist for org: {0}".format(org_name))
    log.err(failure)
    # signal that "error" was handled
    return(None)


######
# Simple Tcp socket protocol to do bulk whois lookup at cymru.org
######

class BulkDataProtocol(Protocol):
    def __init__(self): 
        self.__buffer = ''
        self.MAX_LENGTH = 16384

#   vanilla twisted line reads do not function correctly with ubuntu linux
#   because twisted code looks for \r\n This is not what ubuntu linux provides!
#
    def lineReceived(self, line):
        """Process an input line of data from the bulk whois server
        
        line        The input line of data
        """
        
        if cfg.debug == cfg.DEBUG_VERBOSE:
            log.msg("BDprot: whois line read: {0}".format(line))
            
        # update hostile IP dictionary object with whois data for this IP
        self.factory.my_dict.updt_whois(line)
    
    def dataReceived(self, data):
        """Process a block of data received on input.
        
        data    The block of data rec'd as input.
        
        The input data can contain multiple lines. Also there is no guarantee
        that the data ends on a line boundary.
        
        The following code was adapted from LineOnlyReceiver protocol's
        dataReceived code.
        
        CRLF are normalized. Then individual lines of data are progressively
        pulled out of the block.        
        """
        
        # Normalize CR/LF
        data = re.sub(r"(\r\n|\n)", cfg.DELIM, data)
        
        if cfg.debug == cfg.DEBUG_VERBOSE:
            log.msg("BDprot: data rec'd: {0}".format(data))

        # strip out lines in the response data
        lines  = (self.__buffer+data).split(cfg.DELIM)
        self.__buffer = lines.pop(-1)
        for line in lines:
            if len(line) > self.MAX_LENGTH:
                log.err("BDprot: Error - line too long: {0}".format(line))
            else:
                self.lineReceived(line)
        if len(self.__buffer) > self.MAX_LENGTH:
            log.err("BDprot: Error - line too long: {0}".format(line))


    def connectionMade(self):
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("BDprot: Connected to cymru.")
        self.transport.write(self.factory.myfile)
        

class BulkDataFactory(ClientFactory):

    protocol = BulkDataProtocol

    def __init__(self, deferred, myfile, my_dict):
        """Constructor to initialize the BulkDataProtocol object.
        
        deferred    twisted deferred object fired when the session is
                    terminated
        myfile      list in memory containing the IPs to be submitted to the
                    bulk whois lookup server. Cmds are added to the input stream
                    to control the processing / output format.
        my_dict     ptr to the Hostile IP dictionary object
        """
        self.deferred = deferred
        self.myfile = myfile
        self.my_dict = my_dict

    def clientConnectionLost(self, transport, reason):
        """Handle the situation where the tcp session is lost.
        
        transport       twisted object representing transport method
        reason          twisted object representing reason for failure
        
        Fire the appropriate callback fn if the session is terminated.
        """
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("BDprot: connection closed {0}".format(
                                        reason.getErrorMessage()))
        if self.deferred is not None:
            d, self.deferred = self.deferred, None
            d.callback(reason)

    def clientConnectionFailed(self, transport, reason):
        log.err(reason)
        if self.deferred is not None:
            d, self.deferred = self.deferred, None
            d.errback(reason)

def cymru_get_whois(host, port, myfile, bstate):
    """Download bulk whois information from cymru.org.
    
    host        hostname of bulk whois server
    port        tcp port to use to establish the session
    myfile      list in memory containing the IPs to be submitted to the bulk
                whois lookup server. Cmds are added by application to this input
                stream to control the processing / output format.
    
    This function returns a Deferred which will be fired once the whois
    information has been read and processed. The Failure callback fn will be
    fired if the whois data could not be downloaded.     
    """
    my_dict = bstate.get_dict()
    
    d = defer.Deferred()
 
    factory = BulkDataFactory(d, myfile, my_dict)
    
    reactor.connectTCP(host, port, factory)
    d.addCallback(cymru_got_whois)
    d.addErrback(cymru_failed)
    return d

def cymru_failed(err):
    """Callback fn: Handle a failed bulk whois download.
    
    err     Twisted object representing reason for session failure.
    
    In fact, all telnet sessions will terminate with "error" since an "exit" cmd
    is sent to the routeserver to cause it to close the session ("unexpectedly")
    from its end.
    
    This means that the "OK" callback is never called.
    
    If the condition was a clean shutdown, then informative msgs are logged, and
    the error is ignored.
    
    Otherwise an error msg is logged, and the the error is propagated back
    through the chain of defers.
    """
    if "Connection was closed cleanly" in err.getErrorMessage():
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("BDprot: whois bulk download - connection closed cleanly")
        # signal that "error" was handled
        return(None)
    else:
        log.err("BDprot: Get whois data from cymru failed")
        log.err(err)
        # cause error to propagate back through deferred stack
        return(err)
            
# This rtn never gets called since cymru.org closes the connection
# which triggers the failure branch of the deferred chain    
def cymru_got_whois():
    log.msg("BDprot: bulk download of whois data completed successfully.")




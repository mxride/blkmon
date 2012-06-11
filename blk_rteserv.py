"""blk_rteserv: Download list of subnets in target ASNs being monitored

*** Purpose ***

This module interacts with a public routeserver to determine all the subnets for
for all the target ASNs being monitored. 

This is done by initiating a telnet session to the rteserver. Currently only the
Cisco rte servers are supported. The specific cmd used is:

    show ip bgp regexp _nnn$

where "nnn" is some ASN such as 1234.

Once the list of subnets for the AS has been extracted, Google's ipaddr class is
used to compress the AS' address space to the least # of supernets.

The code lists each ASN in turn, and processes the resulting list of subnets.

The subnet information from internet public routeserver is used to build a
balanced binary tree structure containing all the subnets for all the BGP
Autonomous Systems (AS) that are to be monitored.

Subsequently, when the application wishes to check quickly if a given hostile IP
is in one of the target ASNs, a lookup is done using the binary tree. 

This approach avoids overloading some whois server with literally thousands of
queries in a short time.

*** Public methods ***

blk_rteserv_read    Access a public rte server to download the list of subnets
                    for tgt ASNs
blk_check_ip        Check if IP x is in the binary tree of subnets for the tgt
                    ASNs 


*** Internal Classes ***

ipaddr              Manipulate IP subnets (Google code)
TelnetClient        Manage the telnet session to the public routeserver
TelnetFactory       Store persistent data for the telnet session


================================================

The telnet code is based on a sample telnet client code snippet from
http://twistedmatrix.com/pipermail/twisted-python/2007-June/015623.html
Author is JP Calderone.
The code was modified to use StatefulTelnetProtocol.
There does not appear to be any specific licensing for the code.

Information concerning Google's ipaddr code is included just below. 

Conversion to a service was based on helpful information from:
http://stackoverflow.com/questions/10522662/how-to-properly-trigger-a-python-twisted-transport
"""

######
#   Globals
######

#   ptr to next routeserver to use
rteserv_ptr = -1

######
#   Imports
######

from blk_state import BlkState
import cfg

from twisted.internet import defer, reactor, task
from twisted.internet.protocol import ClientFactory
from twisted.conch.telnet import TelnetTransport, StatefulTelnetProtocol

from twisted.python import log

######
#   Google's ipaddr module
######
"""ipaddr module: Manipulate IP subnets.

From the Google code source README file:
    ipaddr.py is a library for working with IP addresses, both IPv4 and IPv6.
    It was developed by Google for internal use, and is now open source.

    Project home page: http://code.google.com/p/ipaddr-py/

Google's code is licensed under Apache License 2.0.
cf http://www.apache.org/licenses/LICENSE-2.0
"""

from ipaddr import IPAddress, IPNetwork, collapse_address_list


class TelnetClient(StatefulTelnetProtocol):
    """TelnetClient class: Manage the telnet session to the public routeserver
    
    *** Methods ***
    processAddr         Convert input IP value to a Google ipaddr obj
                        representing a subnet 
    lineReceived        Process a line of output rec'd from the public rteserver
    enterLoop           Hit enter to help flush out the buffers.
    connectionMade      Telnet session is initiated, so initialize processing
    build_send_rteserv_cmd
                        build and send the Cisco rteserver cmd to list the
                        subnets for an AS 
    connectionLost      Telnet connection was closed so terminate the processing
                        gracefully.
                        
    *** Processing ***
    The application code cycles through a list of public routeservers on a timer
    loop (usually about 1 week / cycle). A single cycle reads in all the subnets
    for all the target ASNs, and then uses this information to build the binary
    subnet lookup tree.
    
    When the telnet connection is established with the public routeserver, a
    Cisco rtr cmd is built to list the subnets for the 1st tgt BGP ASN.
    
    At the same time a loop is initiated to hit "Enter" from time to time. This
    helps keep the session alive with some traffic, and also helps flush out the
    buffers.
    
    As each line of output is rec'd, it is parsed to extract the subnet
    information. Different formats are possible depending on the version of
    Cisco IOS used in the rteserver.
    
    The IP subnet address information is extracted and converted to a Google
    Ipaddr object. The Google code does validation of the input data. Finally
    the Ipaddr subnet object is stored in a list containing all the results.
    
    If a "---More---" is rec'd on the telnet session, then this is the end of a
    page of output. So the code "hits spacebar" to prompt the delivery of the
    next page of output.
    
    When finally a cmd prompt is rec'd, this means that all the subnets have
    been listed. At this point, the list of subnet objects is sent to Google's
    "collapse_address_list" method to condense the list to the smallest number
    of supernets. Finally the condensed list of subnets are inserted one by one
    into the binary tree.
    
    A throttling fn kicks in to count the number of "Enter" rec'd. This slows
    things down, ensures that all output has been rec'd for the current AS, and
    generally reduces load on the public routeserver.
    
    Next, a new Cisco cmd is built for the next ASN in the target list.
    Everything starts again for this new ASN.
    
    When all the ASNs have been processed, an "exit" cmd is sent to the public
    rteserver to tear down the telnet session.  
    """
    
    def __init__(self):
        """Constructor to initialize the TelnetClient object.
        """
        
        #   Have we seen at least one "--More--"?
        self.state_more = False
        
        self.prompt_cmd = ">"
        self.prompt_more = "--More--"
        self.valid_route = "*"
        self.my_addr_list = []
        self.enter_loop_task = None

    def processAddr(self, myIP):
        """Convert input IP value to a Google ipaddr obj representing a subnet.
        
        myIP        input IP V4 address string to be converted
        
        The IP subnet address information is extracted and converted to a Google
        Ipaddr object. The Google code does validation of the input data.
        Finally the Ipaddr subnet object is stored in a list containing all the
        results.    
        """
        
        try:
            # Try to convert to a network
            myaddr = IPNetwork(myIP)
            
            # Some of the route servers output blank spaces instead of the same
            # network each time if the subnet doesn't change.
            #
            # eg:    Network        Next Hop            Metric LocPrf Weight Path
            #     *> 14.140.0.0/22  202.160.242.71      0 7473 6453 4755 ?
            #     *                 203.13.132.53       0 7474 7473 6453 4755 ?
            #
            # In this case, the 2cd token I/P is really "Next Hop" rtr addr,
            # and not a subnet.
            #
            # Sometimes BGP routing tables have /24 entries. Because of the
            # foregoing, we will be ignoring these as well.
            #
            # However have already seen the subnet so can ignore the I/P line
            if myaddr.numhosts == 1:
                if cfg.debug >= cfg.DEBUG_ON:
                    log.msg("rtesrv: *** empty subnet - ignored")
                return
                
        # don't convert junk, comments, etc
        except ValueError:
            if cfg.debug >= cfg.DEBUG_ON:
                log.msg("rtesrv: *** Invalid value: {0}".format(myIP))
            return
        
        # input IP address has been converted so remember it.
        self.my_addr_list.append(myaddr)

    def lineReceived(self, line):
        """Process a line of output rec'd from the public rteserver.
        
        line        Output line rec'd from the telnet session
        
            
        As each line of output is rec'd, it is parsed to extract the subnet
        information. Different formats are possible depending on the version of
        Cisco IOS used in the rteserver.
    
        The IP subnet address information is extracted and sent to processAddr()
        for validation / processing.
    
        If a "---More---" is rec'd on the telnet session, then this is the end
        of a page of output. So the code "hits spacebar" to prompt the delivery
        of the next page of output.
        
        When finally a cmd prompt is rec'd, this means that all the subnets have
        been listed. The main driver method "build_send_rteserv_cmd" is called
        to build the cmd for the next ASN to be listed.
        
        """
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg('\nrtesrv: ---line Received:', repr(line))
        tokens = line.split()
        if cfg.debug >= cfg.DEBUG_VERBOSE:
            log.msg("\nrtesrv: ----------tokens\n", tokens, "\n------\n")
        
        if len(tokens) > 0:
            
          # If have already seen at least 1 "--More--"
          # then are looking for the cmd prompt that ends this set of
          # output
          if self.state_more:
              if tokens[-1].endswith(self.prompt_cmd):
                                  
                  # The subnets have been listed for the current AS.
                  # Insert them into the IP Binary tree.
                  # Then build and send the cmd to list the next
                  # AS.
                  # When all the AS's have been processed, this
                  # will be a simple "exit" cmd to close the session.
                  self.build_send_rteserv_cmd()
                            
          # If have "--More--", then send a space to move to next page
          #    of output
          if tokens[0] == self.prompt_more:
              if cfg.debug >= cfg.DEBUG_ON:
                  log.msg("rtesrv: ---seen more")
              self.state_more = True
              self.transport.write(" ")
              
          elif tokens[0].startswith(self.valid_route):
              # second field can be one of following formats:
              # 1) nn.nn.nn.nn/mm
              # 2) inn.nn.nn.nn/mm
              # 3) i (and subnet left blank since is a repeat)
              if len(tokens[1]) >  1:
                      myIP = tokens[1]
                      if myIP.startswith('i'):
                          myIP = myIP[1:]
                      if cfg.debug >= cfg.DEBUG_ON:
                          log.msg("rtesrv: --- IP input: {0}".format(myIP))
                      self.processAddr(myIP)
    
    def enterLoop(self):
        """Hit enter to help flush out the buffers.
        """
        # Sometimes the thing we are looking for gets stuck at the end
        # of the buffer. So send C/R every so often to flush out the
        # rest of the buffer.
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("rtesrv: ---hit enter")
        self.sendLine(" ")

    def connectionMade(self):
        """Telnet session is initiated, so initialize processing.
        
        build_send_rteserv_cmd() method is called to build the cmd to list the
        1st ASN.
        
        A loop is kicked off to hit "enter" on a regular basis so that the
        session is kept alive, and to ensure that buffers are flushed out.
        """
        log.msg('Connected to the Routeserver')
        self.clearLineBuffer()
      
        # now set Line Mode
        # and send the cmd to list all the subnets in the 1st AS
        self.setLineMode()
        
        self.build_send_rteserv_cmd()
        
        # hit ENTER from time to time
        self.enter_loop_task = task.LoopingCall(self.enterLoop)
        
        self.enter_loop_task.start(cfg.rs_enter_throttle)
      
    def build_send_rteserv_cmd(self):
        """build and send the Cisco rteserver cmd to list the subnets for the
        next ASN
        
        When finally a cmd prompt is rec'd on the telnet session output, this
        means that all the subnets have been listed for the current AS.
        
        A throttling fn now kicks in to count the number of "Enter" rec'd. This
        slows things down, ensures that all output has been rec'd for the
        current AS, and to generally reduces load on the public routeserver.
        
        When processing can continue again, the list of subnet objects is sent
        to Google's "collapse_address_list" method to condense the list to the
        smallest number of supernets.
        
        Finally the condensed list of subnets are inserted one by one into the
        binary lookup tree.
    
        Next, a new Cisco cmd is built for the next ASN in the target list.
        Everything starts again for this new ASN.
    
        When all the ASNs have been processed, an "exit" cmd is sent to the
        public rteserver to tear down the telnet session.
        """

        # Wait a bit before sending the next list cmd. This avoids
        # flooding the routeserver. More importantly, our "enter" cmd loop
        # can result in a number of cmd prompts once the current list cmd
        # has finished. This in turn will kick off a bunch of new list
        # cmds (one for each "enter" seen). So we slooowww things down a bit.
                  
        # if countdown has not finished yet,
        # then just wait for next cmd prompt
        if self.factory.cmd_prompt_cnt > 0:
            self.factory.cmd_prompt_cnt -= 1
        else:
            # have seen enough cmd prompts so build and send the next
            # list cmd
            
            # reinitialize the counter
            self.factory.cmd_prompt_cnt = cfg.rs_as_cmd_throttle
            
            # Have finished listing the subnets for the current AS
            collapsed_addr_lst = collapse_address_list(self.my_addr_list)
            self.my_addr_list = []
            
            myas = cfg.as_search_list[self.factory.as_ptr]
            
            if cfg.debug >= cfg.DEBUG_ON_LIST:
                log.msg("rtesrv: List of subnets for AS {0}: \n {1}".format(
                    myas,
                    collapsed_addr_lst
                    ))
                
            # Insert the Google subnet Ipaddr objects in the binary lookup tree
            for subnet in collapsed_addr_lst:
                self.factory.Tree.insert(subnet, myas)
        
            # point to next AS in the list
            self.factory.as_ptr += 1
            
            # If all the AS's have been listed then just end the session by
            # sending "exit"
            if self.factory.as_ptr >= len(cfg.as_search_list):
                mycmd = "exit"
            else:
                # build the cisco cmd to list the subnets in the next AS
                mycmd = cfg.RTESRV_CMD.replace(
                    'nnnn',
                    cfg.as_search_list[self.factory.as_ptr]
                    )
                if cfg.debug >= cfg.DEBUG_VERBOSE:
                    log.msg("rtesrv: rteserv cmd: {0}".format(mycmd))
                                
            # send the cmd
            self.sendLine(mycmd)
        
    def connectionLost(self,reason):
        """Telnet connection was closed so terminate the processing gracefully.
        
        reason      Twisted object to describe reason for session termination
        
        The callback fn is called to do any session cleanup.
        The "Enter" loop is shut down.
        """
        # That's it, that's all. So print out some informative msgs
        log.msg('Routeserver connection closed')
        log.msg('IP Binary tree height: {0}'.format(
            self.factory.Tree.height()))
        
        if cfg.debug >= cfg.DEBUG_ON_LIST:
            log.msg("rtesrv: Binary tree contents: \n")
            for t in self.factory.Tree.forward():
                log.msg("rtesrv: IP: {0}, AS: {1}".format(t.key, t.value))
        
        # Call the callback to clean up the session
        if not self.factory.deferred.called:
            # connection was lost unexpectedly!
            log.msg("connection closed - calling errback")
            self.factory.deferred.errback(reason)
        else:
            log.msg("connection closed - calling callback")
            self.factory.deferred.callback()
            
        # stop hitting enter - the connection has been closed
        self.enter_loop_task.stop()            
                
        
#   Telnet Factory keeps track of persistent data for the protocol

class TelnetFactory(ClientFactory):
    """TelnetFactory class: Store persistent data for the telnet session
    """
    
    def __init__(self, deferred, mytree):
        """Constructor for the TelnetFactory Class
        
        deferred    Twisted deferred fired when the session shuts down
        mytree      ptr to the binary lookup tree object
        """
        self.deferred = deferred
        self.Tree = mytree
        self.as_ptr = -1
        self.cmd_prompt_cnt = 0
        
    # pass factory attribute to the protocol so that it can refer back
    # to the persistent data stored in this factory object

    def buildProtocol(self, addr):
        p = TelnetTransport(TelnetClient)
        p.factory = self
        return p
    
    # ensure the error callback is fired if the connection fails for some reason    
    def clientConnectionFailed(self, connection, reason):
        self.deferred.errback(reason)

def read_rtesrv(bstate, myhost):
    """Download subnet information from a public routeserver and return a
    deferred which will be fired when the telnet session terminates.
    
    bstate      ptr to global data container object
    myhost      hostname of public routeserver to access
        
    This function first initializes a new binary lookup tree. Next it builds the
    factory, and then initiates the telnet session to the public routeserver.    
    """
    log.msg('Routeserver mainline rtn starting.')
    
    # Allocate / initialize a new binary lookup tree
    mytree = bstate.init_tree()
    
    # This deferred is fired when the telnet session terminates.
    d = defer.Deferred()
 
    factory = TelnetFactory(d, mytree)
    d.addCallback(rtesrv_OK)
    d.addErrback(rtesrv_failed, mytree)
    
    # Initiate the telnet session
    reactor.connectTCP(myhost, cfg.PORT, factory)
    return d

def rtesrv_failed(err, mytree):
    """Callback Fn: Handle error conditions for the rte server telnet session.
    
    mytree      ptr to binary lookup tree object
    
    In fact, all telnet sessions will terminate with "error" since an "exit" cmd
    is sent to the routeserver to cause it to close the session ("unexpectedly")
    from its end.
    
    This means that the "OK" callback is never called.
    
    If the condition was a clean shutdown, then informative msgs are loggedf, and
    the error is ignored.
    
    Otherwise an error msg is logged, and the the error is propagated back
    through the chain of defers.
    """
    
    if "Connection was closed cleanly" in err.getErrorMessage():
        log.msg("Rte server download - connection closed cleanly")
        log.msg("Binary tree height: {0}".format(mytree.height()))
        
        if cfg.debug >= cfg.DEBUG_ON_LIST:
            log.msg("\nrtesrv: *** IP tree contents ***\n")
            for t in mytree.forward():
                log.msg("rtesrv: IP tree elt: ", t.key, t.value)
                    
        # signal that "error" was handled
        return(None)
    else:
        log.err("Get subnet data from rte server failed")
        log.err(err)
        # cause error to propagate back through deferred stack
        return(err)
            
# This rtn never gets called since we have the server close the connection
# which triggers the failure branch of the deferred chain    
def rtesrv_OK():
    log.msg("rte server download of subnet data completed successfully.")


def blk_rteserv_read(bstate):
    """Access a public rte server to download the list of subnets for tgt ASNs
    
    bstate      ptr to global data container object
    
    This main driver rtn cycles through the list of public rteservers. Normally
    a new routeserver is called to rebuild the binary lookup tree about once a
    week. The read_rtesrv() method is called to initiate processing with this
    rteserver.
    """

    # Cycle through the list of public routeservers in order
    # to not overload any individual server
    my_rteserver = bstate.get_next_rte_srv()   
    log.msg("Initiating download of subnets for all AS's from {0}".format(
                                            my_rteserver))
    # Go read from the new routeserver
    read_rtesrv(bstate, my_rteserver)
    
def blk_check_ip(x, mytree):
    """ Verify if an IP address is contained in the binary lookup tree.
    
    x           the IP V4 address string to check
    mytree      a ptr to the binary subnet lookup tree
    
    The rtn checks if the IP is in the binary subnet lookup tree.
    If the IP address is not in the tree, None is returned.
    If the IP addr is found in the tree, then the return value is the ASN for
    this IP address.
    """
    try:
        t = mytree.chk_ip(x)
        
        if t != None:
            if cfg.debug >= cfg.DEBUG_VERBOSE:     
                log.msg("rtesrv: Hostile IP {0} is in AS {1}".format(
                                t.key,
                                t.value
                                ))
            return(t.value)
    except:
        log.err("Lookup failed for IP: {0}".format(x))
        
    return(None)
        


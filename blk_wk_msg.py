"""blk_wK_msg: Provide utility fn services to send status via xmpp; do dns lkups

** Classes **

The WorkerService class is a utility object used to:
    * drive messaging of xmpp alert msgs
    * contain the current set status msgs concerning known hostile IPs
    * do dns lookups of hostnames.

==============================================

Wokkel is used for xmpp support.

The Wokkel module is a publicly available set of extensions for Python Twisted.
See http://wokkel.ik.nu/

The wokkel software license follows:

Copyright (c) 2003-2012 Ralph Meijer.
	
	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the
	"Software"), to deal in the Software without restriction, including
	without limitation the rights to use, copy, modify, merge, publish,
	distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to
	the following conditions:
	
	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
	LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
	OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""


#####
# imports
#####

import cfg
from blk_state import BlkState

from twisted.internet import task, defer, reactor
from twisted.python import log

from twisted.application import service

from twisted.words.protocols.jabber.jid import JID
from twisted.words.xish import domish

from twisted.names.client import getHostByName

import wokkel.client
from wokkel import xmppim
from wokkel.xmppim import MessageProtocol, AvailablePresence
from wokkel.client import XMPPClient

from datetime import datetime

######
# Xmpp Message Handler
######

def wait(seconds, result=None):
    """Returns a deferred whose callback fn will be fired nn sec later"""
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, result)
    return d

class StatBotProtocol(MessageProtocol):
    """StatBotProtocol class: Extends MessageProtocol class to send / recv XMPP
    chat msgs.
    
    ** Methods **
    
    __init__            Constructor for the StatBotProtocol class
    sendStatMsg         Send a msg to all the authorized xmpp uids, then logoff
    
    ** Instance Variables **

    wrk_serv            ptr to worker service object
    
    This class extends the Wokkel MessageProtocol class to act as a subhandler
    protocol for xmpp msgs. It provides the interface for sending xmpp msgs.    
    """

    def __init__(self, wrk_serv):
        """Constructor for the StatBotProtocol class
        
        wrk_serv        ptr to worker service object        
        """        
        self.wrk_serv = wrk_serv
  
    def connectionMade(self):
        """Send "available" presence once the connection is made"""
    	log.msg("Xmpp client Connected!")

        # send initial presence
        self.send(AvailablePresence())
        
    def connectionLost(self, reason):
        """Clean up after the xmpp connection is closed
        
        reason      Reason why connection was closed.
        """
        
        log.msg("Xmpp client disconnected!")

    def onMessage(self, msg):
        """Reply to an incoming chat msg by sending the global status msg.
        
        msg             incoming xmpp msg
        
        The original goal here was to make this a simplistic xmpp "bot" to
        return status if prompted. However during testing it was a challenge to
        keep the xmpp active for any significant length of time. So code is
        still here but not of much use currently since the application logs on,
        sends the status msg, and then logs off immediately afterwards.
        """
    	if cfg.debug >= cfg.DEBUG_ON:
    	    log.msg("wksrv: xmpp msg rec'd")

        # If incoming msg is a "chat", then
        # check if is authorized uid
        
        if msg["type"] == 'chat' and hasattr(msg, "body"):
            my_msg = str(msg.body)
            from_uid = msg["from"]
            if cfg.debug >= cfg.DEBUG_ON:
                log.msg("wksrv: xmpp msg from {0}: |{1}|".format(from_uid, my_msg))
            
            # Check that this user is in the authorized user list
            for myuid in cfg.xmpp_uids:
                if from_uid.find(myuid) < 0:
                    continue
                
                # Get the global status msg from the worker service object
                status_msg = self.wrk_serv.get_status_msg()

                # Send it to this user
                self.sendMsgUID(
                    status_msg,
                    from_uid
                    )
                return
            # else uid is not recognized
            log.err("xmpp client: uid not authorized {0}".format(
                from_uid))
            
    def sendStatMsg(self, msg):
        """ Send a msg to all the authorized xmpp uids, then logoff xmpp.
        
        msg         msg to send
        
        This rtn will send the input msg to all authorized xmpp userids.
        Then it will schedule a logoff from xmpp once the msgs have been
        sent.
        """
        
        # Send the msg to all the xmpp userids
        for my_uid in cfg.xmpp_uids:
            self.sendMsgUID(msg, my_uid)
        
        # schedule a logoff once the status msgs have been sent
        reactor.callLater(cfg.logoff_delay,
            self.wrk_serv.xmpp_shutdown)

    # Although the following looks like an ordinary loop, it is actually
    # running as a series of Twisted "defers"

    @defer.inlineCallbacks
    
    def sendMsgUID(self, msg, my_uid):
        """ Send a (possibly very long) msg to the uid
        
        msg         Msg to send
        my_uid      Userid to send the msg to
        
        The function breaks a long msg into xmpp-sized pieces and sends each
        xmpp msg to the destination userid.
        """

        # Split the incoming msg into separate lines    
        lines = msg.splitlines()
        i = 0
        msg_cnt = 0
        while (i < len(lines)):
            # if have exceeded the max # of xmpp msgs in this burst, then
            # stop
            msg_cnt += 1
            if msg_cnt > cfg.maxmsgs:
                log.err("Too many xmpp msgs - ignoring rest")
                break
            
            # Send to the next user in the list
            reply = domish.Element((None, "message"))
            reply["type"] = 'chat'
            reply["to"] = my_uid
            
            # Next concatenate the individ lines into one xmpp-sized msg           
            j = min(i + cfg.numgrp, len(lines))
            msg_tmp = " || ".join([lines[ii] for ii in range(i,j)])
            reply.addElement("body", content= msg_tmp)
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("wksrv: send msg, i={0}, j={1}, {2}".format(i,j,msg_tmp))

            # send the xmpp msg and then wait a bit
            yield self.send(reply)
            yield wait(cfg.xmpp_throttle)
            i += cfg.numgrp


######
#   WorkerService object - Provide utility functions
######
		
class WorkerService(service.Service):
    """WorkerService: Provide utility fn to do dns lkps, manage status msgs.
    
    ** Methods **
    __init__        Constructor for the WorkerService class
    
    lkps_in_progress
                    Returns True if all the dns lookups have completed
    do_lookup       Schedule a dns lookup
    
    set_status      Set the new global status msg and send it to all the xmpp
                    userids 
        
    
    ** Instance variables **
    
    xmppclient      Ptr to Wokkel xmppclient object
    status_msg      Global status msg listing Hostile IPs found in tgt ASNs.
    
    bstate          Ptr to global container object
    
    max_x           Used to throttle dns lkups: max # simultaneous lookups
    num_x           current # active dns lookups
    num_wait        num of dns lkups in the wait queue
    
    This class provides the following service functions:
    - holds current status msg, and drives messaging
    - do bulk dns lookups
    
    """

    def __init__(self, bstate):
        """Constructor for the WorkerService class
        
        bstate      ptr to global container object
        """        
        # status msgs
        self.xmppclient = None
        self.status_msg = " ".join([str(datetime.now().ctime()),
                        "No status yet!"])
        
        self.bstate = bstate    # global container object

        # poor man's throttling of dns lookups
        # 30 simultaneous lookups at one time
        self.max_x = 30     # max # simultaneous lookups
        self.num_x = 0      # current # active dns lookups
        self.num_wait = 0   # num of dns lkups in the wait queue

######
#   Dns lookup utility fns
######

    def lookup_done(self, result, name, mydesc, myorg):
        """Callback fn for dns lkup: Update the dns throttle counters.
        
        result      Answer from the dns lookup
        name        dns hostname to lookup
        mydesc      additional description information concerning hostile ip
        myorg       blocklist identifier
        
        This callback fn is fired when the dns lookup ends. It updates the
        activity counter to show that this dns query has now finished. The
        IP information from the dns lookup is used to update the Hostile IPs
        dictionary.
        """
        
        self.num_x = max(0, self.num_x-1)
        
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("wksrv: dns_lkup: lookup done. cnt {0} {1} {2}".format(
                self.num_x,
                name,
                result))
            
        # insert dns information into the Hostile IPs dictionary
        ip_dict = self.bstate.get_dict()
        mydesc1 = cfg.SEP.join([name, mydesc])
        ip_dict.insert_ip(result, desc=mydesc1, org=myorg)
            
        if not self.lkps_in_progress():
            log.msg("All dns lookups done")

    def lookup_err(self, failure, name, mydesc, myorg):
        """Callback fn for dns lkup: Handle err condition, update counters.

        failure     Failure object describing reason for error condition
        name        dns hostname to lookup
        mydesc      additional description information concerning hostile ip
        myorg       blocklist identifier
        
        This callback fn is fired when the dns lookup ends (with an erro). It
        updates the activity counter to show that this dns query has now
        finished.
        """
        
        if cfg.debug >= cfg.DEBUG_VERBOSE:
            log.err(failure)
            
        # Update the dns lookup throttle counters
        self.num_x = max(0, self.num_x-1)
        if cfg.debug >= cfg.DEBUG_ON:
            log.err("wksrv: dns_lkup: error. cnt: {0} {1}".format(self.num_x, name))
        
        if not self.lkps_in_progress():
            log.msg("All dns lookups done")
        
        # signal that error was "handled" (ie ignore the error)
        return(None)
              
    def do_lookup(self, name, flag, mydesc, myorg):
        """Schedule a dns lookup.
        
        name        dns hostname to lookup
        flag        true if this is the 1st time thru for this dns hostname
        mydesc      additional description information concerning hostile ip
        myorg       blocklist identifier
        
        If this is not the 1st time through for this hostname, then it must have
        come from the wait queue. So decrement the cnt of requests in the wait
        queue.
        
        If there is still room in the current burst of dns lookups, then
        schedule the actual lookup and bump the activity counter of requests
        currently running.
        
        If there is no room in the current burst pipeline, then send the request
        back to the wait queue, bump the wait counter, and re-schedule this
        lookup for later on.      
        """

        if cfg.debug >= cfg.DEBUG_VERBOSE:
            log.msg("wksrv: dns_lkup: {0}, {1} org: {2}  |{3}|".format(
                name,
                flag,
                myorg,
                mydesc
                ))
                
        # if not 1st time call, then decrement wait cnt        
        if (flag):
            self.num_wait = max(0, self.num_wait-1)
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("wksrv: dns_lkup: wait cnt:", self.num_wait, name)
        
        # if not throttling then kick off next request
        if self.num_x < self.max_x:
            self.num_x = self.num_x + 1
            
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("wksrv: dns_lkup: fire another, exec cnt", self.num_x, name)
            d = getHostByName(name)
            d.addCallback(self.lookup_done, name, mydesc, myorg)
            d.addErrback(self.lookup_err, name, mydesc, myorg)
            
        else:
            # make the request wait a bit
            self.num_wait = self.num_wait + 1
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("wksrv: dns_lkup: wait another", self.num_wait, name)

            # schedule this lookup for later on
            
            d = task.deferLater(
                    reactor,
                    (self.max_x + self.num_wait)/self.max_x,
                    self.do_lookup,
                    name,
                    True,
                    mydesc,
                    myorg
                    )

    def lkps_in_progress(self):
        """Returns True if all the dns lookups have completed"""
        return (self.num_x > 0 or self.num_wait > 0)
            
######
#   Status msg functions
######


    def set_status(self, newmsg):
        """Set the new global status msg and send it to all the xmpp userids.
        
        newmsg      New global status msg to process
        """
        # timestamp the new status msg and save it
        self.status_msg = " ".join([str(datetime.now().ctime()), newmsg])
        
        # logon to xmpp
        self.xmppclient = wokkel.client.XMPPClient(cfg.myjid, cfg.mypasswd)
        if cfg.debug >= cfg.DEBUG_ON:
            self.xmppclient.logTraffic = True
        
        # start up the xmpp msg subprotocol handler which contains our
        # application-specific processing function to send out the status msg
        statbot = StatBotProtocol(self)
        statbot.setHandlerParent(self.xmppclient)
        self.xmppclient.startService()
        
        # send the status msgs using xmpp
        statbot.sendStatMsg(self.status_msg)
                     
    def get_status_msg(self):
        """Returns the current status msg."""
    	return(self.status_msg)
    	
    def xmpp_shutdown(self):
        """Schedules a logoff from xmpp."""
        if self.xmppclient:
            self.xmppclient.stopService()        


                    

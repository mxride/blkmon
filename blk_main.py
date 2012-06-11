"""blk_main: Read and process the blocklists to find hostile IPs

*** Purpose ***

This module drives the blocklist downloads. The contents of the various
blocklists are read and parsed to extract known hostile IPs.

This information is consolidated into the Hostile IP dictionary.

The dictionary is then scanned for hostile IPs in the target ASN's that are
being monitored.

The resulting small group of hostile IPs is submitted to a bulk whois lookup  in
order to ensure that the IP - ASN mapping is correct. 

Finally, the Hostile IP dictionary is scanned once again to produce the final
list of hostile IPs in the target ASNs. The worker service object is invoked to
send out the new xmpp status message to all authorized xmpp users.

*** Exported public fns ***

blklst_Main         Read and process the IP blocklists.

"""


#####
# imports
#####
from blk_rdblk import get_blklst, cymru_get_whois
from blk_rteserv import blk_check_ip
# from blk_ipdict import hostileIPs
from blk_state import BlkState
#from blk_wk_msg import StatBotProtocol
import cfg

from twisted.internet import defer, reactor
# from twisted.internet.protocol import Protocol, ClientFactory
from twisted.python import log

                   
######
#
#   Read all the blocklists
# 
######


def read_blklsts(bstate):
    """Schedule reads of the IP blocklists.
    
    bstate          Global data container object
    
    This fn loops through the list of all the IP blocklists. For each url /
    blocklist pair, schedules a download of the corresponding blocklist. 
    """

    # set up a list of deferreds to control the processing
    ds = []
    log.msg("Initiating read of blocklists")

    # Download each IP blocklist in the list
    for (org_name, url) in cfg.blklist_urls:        
        d = get_blklst(org_name, url, bstate)
        ds.append(d)

    dlist = defer.DeferredList(ds, consumeErrors=True)
    dlist.addCallback(blklsts_done, bstate)

def blklsts_done(result, bstate):
    """All the blocklist downloads have finished so schedule the whois lookups.
    
    result      List containing results of all the individual downloads. Format
                is: 
                    [(result1, err-msg), (result2, err-msg)]
                So if all downloads succeeded, result will be:
                    [(True, None), (True, None)]
    
    bstate      Global data container object
    
    This callback fn schedules the next part of the blocklist processing: the
    bulk whois lookup.
    """
    
    log.msg("\nFinished reading all blklsts. Results: {0}".format(result))
    
    reactor.callWhenRunning(cymru_chk,bstate)
    
       
def cymru_chk(bstate):
    """Submit the hostile IPs to a bulk lookup whois server in order to be sure
    we have the correct IP - ASN mapping.
    
    bstate      ptr to global data container object
    
    If there are dns lookups still being done, then this fn reschedules itself
    to check again in a while.
    
    Once all the dns lookups resutling from the blklist downloads have finished,
    then this fn enumerates the entire Hostile IP dictionary.  Each hostile IP
    is checked using the binary tree to determine if the IP is in a target ASN
    being monitored.
    
    A list is built of all these IPs for submission to the bulk whois lookup
    server. Attn is paid to ensure that the # of elts to be submitted does not
    exceed the daily maximum for this service.
    
    If there any hostile IPs found, the fn schedules the actual submission to
    the whois lookup service.
    """
    
    # if no dns lookups are in progress, then start the bulk whois lookup.
    # otherwise enter a wait loop until the dns lookups finally complete

    wk_serv = bstate.get_wrk_serv()
    
    # if dns lookups still being done
    if wk_serv.lkps_in_progress():
        
        # then wait for a bit
        reactor.callLater(cfg.cymru_delay, cymru_chk, bstate)
        return
    
    log.msg("\nbulk whois lookup is starting now")
    
    # loop thru the dictionary to find all the hostile IPs in the target ASNs
    # being monitored

    n = 0
    my_dict = bstate.get_dict()
    my_tree = bstate.get_tree()
    
    data = cfg.CYMRU_CMD_FIRST
    
    # loop through the entire Hostile IPs dictionary, IP by IP
    for myip in my_dict.list_all():
        xx1, xx2, org_tmp, desc_tmp = my_dict.list_elt(myip)
        
        # For each IP, check the binary tree to see if this IP is probably
        # in one of the ASNs being monitored.
        
        myas = blk_check_ip(myip, my_tree)

        if cfg.debug >= cfg.DEBUG_ON_LIST:
            log.msg("cymru_chk: dict: {0} {1} {2} {3}".format(
                myip,
                myas,
                org_tmp,               
                desc_tmp
                ))
        
        # if have a candidate hostile IP
        if myas != None:
            # and total # of IPs found does not exceed the daily max limit for
            # the whois server   
            if n > cfg.cyrmu_max:
                break
            else:
                n += 1
            
            if cfg.debug == cfg.DEBUG_VERBOSE:
                log.msg("cymru_chk: {0} hostile ip: {1}".format(n, myip))
                
            # Then add this IP to the list for submission to cymru bulk whois
            # lookup.
            data = "".join([data, myip, " \n"])
    
    # if have found at least one hostile IP in the target ASNs being monitored,
    # then submit the file to the bulk whois to validate the IP - ASN mapping.
    # This will purify the data by ensuring that the IP - ASN mappings are as
    # accurate as possible.
    
    if n > 0:
        data = "".join([data, cfg.CYMRU_CMD_LAST])
            
        if cfg.debug == cfg.DEBUG_VERBOSE:
            log.msg("cymru_chk: cymru cmd file: \n{0}".format(data))
            
        # Schedule the tcp socket transmission to send the data to cymru.org
        
        d = cymru_get_whois(cfg.CYMRU_IP, cfg.CYMRU_PORT, data, bstate)
        d.addBoth(cymru_done, bstate)
        
    # otherwise no hostile IPs were found this time through    
    else:
        wrk_serv = bstate.get_wrk_serv()
        wrk_serv.set_status("No hostile IPs found in ASNs of interest")
        

def cymru_done(arg, bstate):
    """The whois lookups have finished so produce the final status msg.
    
    arg         result from function call when the deferred is fired
    bstate      ptr to global data container object

    This callback fn is fired when the bulk whois lookups have finished
    successfully.
    
    As data was rec'd back from the whois lookups, it was processed and used to
    update the contents of the Hostile IPs dictionary. (Cf blk_readblk,
    BulkDataProtocol.dataReceived()
    
    Since this updating is now completed, the fn enumerates the entire Hostile
    IPs dictionary once again to produce the final status msg. The worker
    service object is called to save the msg and send it out to the xmpp
    authorized users.
    """
    log.msg("cymru_done: cymru whois download completed.")
    
    # Now check for any hostile IPs are active in our AS's

    status_msg = ""
    my_dict = bstate.get_dict()
    wrk_serv = bstate.get_wrk_serv()
    
    for as_tmp in cfg.as_search_list:
        for i, (ip__, as_str, cc_tmp, org_tmp, desc_tmp) in  \
            enumerate( my_dict.list_grp(as_=as_tmp) ):

            status_msg = " ".join([status_msg,
                        ip__,
                        as_str,
                        cc_tmp,
                        org_tmp,
                        desc_tmp,
                        cfg.DELIM])
            
    # if any found, save the new status msg and send it out using xmpp
   
    if len(status_msg) > 0:
        wrk_serv.set_status(status_msg)


def blklst_Main(bstate):
    """ Read and process the IP blocklists.
    
    bstate              ptr to global container object
    
    This is the main driver fn for the IP blocklist downloads.
    
    This fn first does a sanity check of IP lookups using the binary tree.
    
    If the sanity check doesn't work, then the fn goes into a wait loop and
    bumps a retry counter. Usually sanity check failure is due to a partially
    constructed binary lookup tree.
    
    If the retry count is exceeded, then the fn calls the routeserver object to
    reinitialize / rebuild the binary tree using another routeserver.
    
    Once the sanity check works, then this fn initializes the Hostile IP
    dictionary and starts doing the IP blocklist downloads.
    """
    
    # Do a sanity check of IP lookups. This involves doing a lookup of a known
    # stable IP address to ensure that the lookup fn says that it truly is in
    # one of the ASNs being monitored.
    chk_as = blk_check_ip(cfg.sanity_ip,
                        bstate.get_tree()
                        )
    
    # If the tree sanity check is ok, then reset the problem counter and start
    # doing the IP blocklist downloads.
    
    if chk_as == cfg.sanity_as:
        log.msg("Sanity check of IP address lookup OK")
        bstate.reset_ip_prob_cnt()
        
        # initialize the hostile IP dictionary
        my_dict = bstate.init_dict()
                
        # Now start reading the blocklists
        read_blklsts(bstate)
    else:
        # Have a sanity check error situation
        #
        # Note that at startup, this check will fail since the IP binary tree
        # hasn't been built yet. So the fn goes into a waiting loop, and bumps a
        # retry counter.
        #
        # If things are still not working after the max # retries, then we
        # will go on to another routeserver to reinitialize / rebuild the binary
        # tree. Hopefully this new attempt to build the tree will be more
        # successful. 
        
        log.err(("Sanity check of IP address lookup "
            "failed. IP: {0}, AS:{1}").format(
                       cfg.sanity_ip,
                       chk_as
                       ))
        
        # if have had too many consecutive sanity check errors for ip lookup
        if bstate.bump_ip_prob_cnt():
            
            # then go rebuild the IP binary tree using another routeserver
            blk_rteserv_read(bstate)
        else:
            # otherwise reschedule ourselves to check again in a few minutes
            reactor.callLater(
                        cfg.ip_prob_retry,
                        blklst_Main,
                        bstate
                        )

        
        
        
        
      
    
    

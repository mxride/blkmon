"""blk_state: Provide global data container object

*** Purpose ***

The blk_state module consists of one public class. This is a global utility
object used to locate and persist important data and other objects: 
    * binary tree object containing all the IP subnets for the target ASNs being
    monitored
    * Dictionary object containing hostile IP data
    * Ptr to worker service utility fn object
    * Other important global data variables

*** Public class ***

BlkState        Global container class

*** Public methods ***

init_tree       Delete and reallocate the binary search tree   
get_tree        Return a ptr to current binary search tree
init_dict       Delete and reallocate the Hostile IPs dictionary object
get_dict        Return a ptr to the current Hostile IPs dictionary object
get_wrk_serv    Return a ptr to worker utility fn object
set_wrk_serv    Set ptr to worker utility fn object
get_next_rte_srv
                Return index indicating the next public rteserver to access
bump_ip_prob_cnt
                Increment count of # times binary tree sanity chk has failed
reset_ip_prob_cnt
                Reset sanity check counter to zero
    
"""

######
#   Imports
######

from blk_tree import bbstree
from blk_ipdict import hostileIPs
# from blk_wk_msg import WorkerService
import cfg

from twisted.python import log


######
#   BlkState Class
######
	
	
class BlkState:

    def __init__(self):
        """Constructor for BlkState class
        """

        # other persistent global objects
        self.mytree = None
        self.mydict = None
        
        # ptr to next rte server in list
        self.my_rte_srv = -1
        
        # counter of problems with IP Lookups
        self.ip_prob_cnt = 0
        
        # worker service for utility fn
        self.wrk_serv = None
        
        # xmpp service object
#        self.statbot = None
        
    def init_tree(self):
        """Delete and reallocate the binary search tree
        
        Returns a ptr to the new, empty tree
        """
        try:
            del self.mytree
        except NameError:
            pass

        self.mytree = bbstree()
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("Blkstate-reinit tree {0}".format(self.mytree))
        return self.mytree
        
    def get_tree(self):
        """Return a ptr to current binary search tree
        """
        if cfg.debug >= cfg.DEBUG_VERBOSE:
            log.msg("Blkstate-tree {0}".format(self.mytree))
        return self.mytree
        
    def init_dict(self):
        """Delete and reallocate the Hostile IPs dictionary object
        
        Returns a ptr to the new empty dictionary object
        """
        try:
            del self.mydict
        except NameError:
            pass

        self.mydict = hostileIPs()
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("Blkstate-reinit dict {0}".format(self.mydict))
        return self.mydict
        
    def get_dict(self):
        """Return a ptr to the current Hostile IPs dictionary object
        """
        if cfg.debug >= cfg.DEBUG_VERBOSE:
            log.msg("Blockstate-dict {0}".format(self.mydict))
        return self.mydict
           	
    def get_wrk_serv(self):
        """Return a ptr to worker utility fn object
        """
        return self.wrk_serv
        
    def set_wrk_serv(self,wrk_serv):
        """Set ptr to worker utility fn object
        """
        self.wrk_serv = wrk_serv
   	
    def get_next_rte_srv(self):
        """Return index indicating the next public rteserver to access
        """
        # point to next rte server in the list
        self.my_rte_srv += 1
        
        # if have done them all, then start over
        if self.my_rte_srv == len(cfg.rteserv_list):
            self.my_rte_srv = 0
            
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("Blkstate- next rte server #{0} is {1}".format(
                self.my_rte_srv,
                cfg.rteserv_list[self.my_rte_srv]
                ))
            
        return cfg.rteserv_list[self.my_rte_srv]
        
    def bump_ip_prob_cnt(self):
        """Increment count of # times binary tree sanity chk has failed
        
        Returns True if counter has been exceeded, otherwise False
        """
        self.ip_prob_cnt += 1
        
        max_cnt_exceeded = (self.ip_prob_cnt >= cfg.ip_prob_max)
        if max_cnt_exceeded:
            self.ip_prob_cnt = 0
                
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("Blkstate-ip prob cnt: {0}, exceeded? {0}".format(
                self.ip_prob_cnt,
                max_cnt_exceeded
                ))

        return max_cnt_exceeded
            
    def reset_ip_prob_cnt(self):
        """Reset sanity check counter to zero
        """
        self.ip_prob_cnt = 0
        if cfg.debug >= cfg.DEBUG_ON:
            log.msg("Blkstate-ip prob cnt reset")
        

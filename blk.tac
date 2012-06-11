"""blk.tac - Define appl structure and startup sequence for the twistd daemon. 

Blk.tac is the main driver code that is executed by the twistd daemon in order
to determine application structure and startup sequence.

"""

from blk_main import blklst_Main
from blk_wk_msg import WorkerService
from blk_web import StatusPage, IPPage, IPStatusPage
from blk_rteserv import blk_rteserv_read
from blk_state import BlkState
import cfg

from twisted.application import service, internet
from twisted.python import log

from twisted.application.service import Application

from twisted.web import resource, server as webserver
from twisted.web.resource import Resource
from twisted.web.server import Site


######    
# plumbing for the twistd daemon
######

application = service.Application("HostileIPs")

######
#   Utility services
######

# Allocate the object which contains / persists the main global objects
bstate = BlkState()

# worker service

wrk_service = WorkerService(bstate)
wrk_service.setServiceParent(application)

# tell everyone where to find the worker service
bstate.set_wrk_serv(wrk_service)

######
#   Web interface
######

webroot = StatusPage(bstate)
webroot.putChild("ip", IPPage())
webroot.putChild("ipstatus", IPStatusPage(bstate))
webService = internet.TCPServer(cfg.web_port, webserver.Site(webroot))
webService.setName("Web")
webService.setServiceParent(application)

######
# timer service to drive loop which accesses routeservers for a list of IP
# subnets in the ASNs being monitored 
######

read_rtvserv_service = internet.TimerService(
                                cfg.DEFER_SECS_IP,
                                blk_rteserv_read,
                                bstate
                                )
read_rtvserv_service.setServiceParent(application)

######
# timer service to drive loop which reads / processes IP blocklists
######

blkrd_service = internet.TimerService(
                    cfg.DEFER_SECS_BLK,
                    blklst_Main,
                    bstate
                    )
blkrd_service.setServiceParent(application)




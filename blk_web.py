"""blk_web: Provide simple web user interface for status queries

The xxxPage classes form a rudimentary user web interface to:
    * allow the user to get current global status, if any
    * permit query lookups for a specific IP

*** Classes ***

StatusPage          Provide the web root page to display current status
IPPage              Provide form for query of a single IP.
IPStatusPage        Display the response to an IP query

    

This web server code was based in part on examples found in:

Twisted Network Programming Essentials
By: Abe Fettig
Publisher: O'Reilly Media, Inc.
Pub. Date: October 20, 2005
Print ISBN-13: 978-0-596-10032-2
Pages in Print Edition: 238

as well as the Twisted Labs documentation. www.twisted.com
"""

import cfg
from blk_state import BlkState

from twisted.application import service, internet
from twisted.internet import protocol, reactor, defer

from twisted.web import server as webserver
from twisted.web.resource import Resource
from twisted.web.server import Site

from twisted.python import log

from datetime import datetime
import re

######
#   Globals
######

# Pattern to match IP V4 address:
#           "nn.nn.nn.nn"

re_ipv4 = re.compile("""
(?P<addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) # ip v4 address
""",re.VERBOSE)


class StatusPage(Resource):
    """Provide the web root page "/" to display current status. This class
    extends the twisted.web class resource.Resource.
    """

    def __init__(self, bstate):
        """Constructor for the StatusPage class
        
        bstate          Ptr to global data container object
        
        Since this class extends the Twisted web class "Resource", the
        underlying constructor is also called.
        """
        self.bstate = bstate
        Resource.__init__(self)

    def getChild(self, name, request):
        """Follow the web tree to find the correct resource according to the URL
        
        name    The path specified by the URL
        request A twisted.web.server.Request specifying meta-information about
                the request
        """
        if name == '':
            return self
        return Resource.getChild(self, name, request)

    def render_GET(self, request):
        """Display the page contents if the Http method used was "GET"
        
        request A twisted.web.server.Request specifying meta-information about
                the request
                
        The html contents are dynamically generated. A call is made to the
        worker service object to get the current status msg. This msg already
        has CRLF inserted. So it is split into separate lines and displayed on
        the generated web page.
        """
        request.write("""
        <html>
        <head>
            <title>Overall Status</title
        </head>
        <body>
            <h1>Current Status</h1>
            <p>
        """)
        
        # get the current status msg
        wrk_serv = self.bstate.get_wrk_serv()
        stat_msg = wrk_serv.get_status_msg()
        
        # split it into separate lines for display on the web page
        for my_line in stat_msg.splitlines():
            request.write(' '.join([my_line,"<br>"]))
            
        request.write("""
            </p>
        </body>
        </html>
        """)
        request.finish()
        return webserver.NOT_DONE_YET


class IPPage(Resource):
    """Provide page "/ip" which is form for query of a single IP. This class
    extends the twisted.web class resource.Resource.
    """
    # Set class variable to show that this is the last elt in the URL path
    isLeaf = True

    def render_GET(self, request):
        """Display the page contents if the Http method used was "GET".
        
        request         A twisted.web.server.Request specifying meta-information
                        about the request
                        
        This page is a form which allows the user to enter a specific IP address
        for lookup in the Hostile IPs dictionary. Information is kept on all the
        entries read from all blocklists (not just those IPs in the ASNs
        targeted for monitoring.)
        
        The final result will be an HTTP POST to /ipresults.
        """
        request.write("""
        <html>
        <head>
            <title>IP query</title
        </head>
        <body>
            <form action='ipstatus' method='post'>
            Enter an IP address:
            <p>
            <input type='text' name='my_ip' maxlength=15>
            </p>

            <input type='submit' />
            </form>
        </body>
        </html>
        """)
        request.finish()
        return webserver.NOT_DONE_YET

        
class IPStatusPage(Resource):
    """Provide /ipresults page which displays the response to an IP query. This
    class extends the twisted.web class resource.Resource.
    """
    # Set class variable to show that this is the last elt in the URL path
    isLeaf = True

    def __init__(self, bstate):
        """Constructor for the StatusPage class
        
        bstate          Ptr to global data container object
        
        Since this class extends the Twisted web class "Resource", the
        underlying constructor is also called.
        """

        self.bstate = bstate
        Resource.__init__(self)

    def render_POST(self, request):
        """Display the page contents if the Http method used was "POST"
        
        request A twisted.web.server.Request specifying meta-information about
                the request
                
        The html contents are dynamically generated.

        The HTTP POST to this page results from the user submitting the /ip
        form. (see above)
        
        The ip address entered is verified by a regex filter. Then a lookup is
        done in the Hostile IPs dictionary for the corresponding entry.
        
        If the address is unknown, or if any exceptions occur, they are trapped,
        and a generic msg is sent back to the user's browser. This limits the
        information available to a potential attacker.
        
        After the results have been displayed, the user can click on an href to
        go back to the /ip form page.
        """

        request.write("""
        <html>
          <head>
            <title>IP Status</title>
          </head>
          <body>
         """)
        request.write("<p> Time: {0} </p>".format(str(datetime.now().ctime())))

        # Initialize for the lookup of an IP in the hostile IP dictionary
        
        status_msg = "Hostile IP info currently not available."
        
        ip_dict = self.bstate.get_dict()
        
        # request.args contains All of the arguments, including URL and POST
        # arguments. It is a mapping of strings (the argument names) to lists
        # of values. i.e., ?foo=bar&foo=baz&quux=spam results in
        # {'foo': ['bar', 'baz'], 'quux': ['spam']}. )
        
        try:
            # pull out the string the user entered
            value = str(request.args["my_ip"][0])
            if cfg.debug >= cfg.DEBUG_VERBOSE:
                log.msg("web: ipstatus: lookup for |{0}|".format(value))
            
            if ip_dict and value:
                # 1st 16  bytes of value should be a valid IP addr
                m = re_ipv4.search(value[:16])
                
                # if the address passes the regex filtering
                if m:
                    # then use it to do a lookup in the Hostile IPs dictionary
                    myip = m.group('addr')
                    if cfg.debug >= cfg.DEBUG_VERBOSE:
                        log.msg("web: ipstatus: lookup for |{0}|".format(myip))
                        
                    # do the lookup    
                    as_tmp, cc_tmp ,org_tmp, desc_tmp = \
                        ip_dict.list_elt(myip)
                        
                    # format the results for output on the web page    
                    status_msg = " ".join(["Hostile IP: ",
                        myip,
                        as_tmp,
                        cc_tmp,
                        org_tmp,
                        desc_tmp])
                else:
                    status_msg = "IP address - invalid format"
        except:
            status_msg = "Information not available for this IP."

        request.write('<p>' + status_msg + '</p>')
    
        request.write("""
           <p>
               <a href="ip">Continue</a> Click to enter another IP address.
           </p> 
           </body>
        </html>
        """)
        request.finish()
        return webserver.NOT_DONE_YET





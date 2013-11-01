from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import os

urls_in_scope=['testblah.com','qa.ooboob.com']
#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Third Party Referer")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    request_http_service=message.getMessageInfo().getHttpService()
    request_byte_array=message.getMessageInfo().getRequest()
    request_object=self._helpers.analyzeRequest(request_http_service, request_byte_array)

    #Extract hostname from header
    hostname=webcommon.get_host_header_from_request(self,request_object)

    #Check if the URL is NOT in scope. We want to look at referers for the requests that are made to OTHER domains.
    if (hostname) and (hostname[1] not in urls_in_scope):
      #Extract referer from header
      referer=webcommon.get_referer_header_from_request(self,request_object)
      if referer:
        t1=referer[1].split('/')
        if t1[2] in urls_in_scope:
          print referer[1]

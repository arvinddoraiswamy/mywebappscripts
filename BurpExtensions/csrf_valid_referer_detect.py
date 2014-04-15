from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import os
import re
import sys

excluded_file_extensions=['.jpg','.gif','.bmp','.png','.css','.js','.htc']
urls_in_scope=['testblah.com']

referer_header_name='Referer'
referer_header_value='https://home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules.com/'

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("CSRF Valid Referer Detector")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    request_url = BurpExtender.detect_valid_referer(self,messageIsRequest,message)

  def detect_valid_referer(self,messageIsRequest,message):
    #Only process requests as that's where the valid Referer should be 
    request_http_service=message.getMessageInfo().getHttpService()
    request_byte_array=message.getMessageInfo().getRequest()
    requestInfo=self._helpers.analyzeRequest(request_http_service, request_byte_array)
    request_url=requestInfo.getUrl()

    if messageIsRequest:
      #Extract hostname from header
      hostname=webcommon.get_host_header_from_request(self,requestInfo)

      #Check if the URL is in scope. This is to eliminate stray traffic.
      if hostname and hostname[1] in urls_in_scope:
        #Extract referer. If it's not a referer from the same site - print it out and let the engineer decide if it is unsafe.
        referer=webcommon.get_referer_header_from_request(self,requestInfo)
        if not referer[1].startswith(referer_header_value):
          print str(request_url)+'\t\t'+str(referer[1])

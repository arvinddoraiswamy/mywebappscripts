#Get server header from every response and dump it into a file
#Search response bodies for a set of common versions

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import os

unique_banners={}
list_of_platforms=['iis','apache','tomcat','weblogic','websphere','jetty','gws','ibm','oracle','nginx','bigip']
urls_in_scope=['test.blah.com']

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Platform Information Extractor")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    response_byte_array=message.getMessageInfo().getResponse()

    request_http_service=message.getMessageInfo().getHttpService()
    request_byte_array=message.getMessageInfo().getRequest()
    request_object=self._helpers.analyzeRequest(request_http_service, request_byte_array)

    #Extract hostname from header
    hostname=webcommon.get_host_header_from_request(self,request_object)
    #hostname=BurpExtender.get_host_header_from_request(self,request_object)

    #Check if the URL is in scope. This is to eliminate stray traffic.
    if hostname and hostname[1] in urls_in_scope:
       if not messageIsRequest:
         responseInfo = self._helpers.analyzeResponse(response_byte_array)

         #Extract banner from response
         banner=webcommon.get_banner_from_response(self,responseInfo)
         if banner not in unique_banners.keys():
           unique_banners[banner]=''
           print banner

         #Extract platform specific content from response
         responseBody=webcommon.get_response_body(self,response_byte_array,responseInfo)
         responseBody_string=self._helpers.bytesToString(responseBody)

         for platform_name in list_of_platforms:
           regex=re.compile('.{30}%s.{30}'%platform_name,re.IGNORECASE|re.DOTALL)
           m2=regex.search(responseBody_string)
           if m2:
             print m2.group(0)+'\n'+'-'*30+'\n'

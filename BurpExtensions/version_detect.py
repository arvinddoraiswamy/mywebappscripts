#Get server header from every response and dump it into a file
#Search response bodies for a set of common versions

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys

unique_banners={}
list_of_platforms=['iis','apache','tomcat','weblogic','websphere','jetty','gws','ibm','oracle','nginx']
urls_in_scope=['fakesite1.com']

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

    #Extract hostname from header
    hostname=BurpExtender.get_host_header_from_request(self,requestInfo)

    #Check if the URL is in scope. This is to eliminate stray traffic.
    if hostname and hostname[1] in urls_in_scope:
       if not messageIsRequest:
         responseInfo = self._helpers.analyzeResponse(response_byte_array)

         #Extract banner from response
         banner=BurpExtender.get_banner_from_response(self,responseInfo)
         if banner not in unique_banners.keys():
           unique_banners[banner]=''
           print banner

         #Extract platform specific content from response
         responseBody=BurpExtender.get_response_body(self,response_byte_array,responseInfo)
         responseBody_string=self._helpers.bytesToString(responseBody)

         for platform_name in list_of_platforms:
           regex=re.compile('.{30}%s.{30}'%platform_name,re.IGNORECASE|re.DOTALL)
           m2=regex.search(responseBody_string)
           if m2:
             print m2.group(0)+'\n'+'-'*30+'\n'

  def get_banner_from_response(self,responseInfo):
    t1 = responseInfo.getHeaders()
    header_name='Server:'
 
    for i in t1:
      #Search for the Server header
      regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
      m1=regex.match(i)
 
      #Extract and store the Server header
      if m1:
        t2=i.split(': ')
 
    return t2[1]

  def get_response_body(self,response_byte_array,responseInfo):
    responseBody=response_byte_array[responseInfo.getBodyOffset():]
    return responseBody

  def get_host_header_from_request(self,requestInfo):
    t1 = requestInfo.getHeaders()
    header_name='Host:'
 
    for i in t1:
      #Search for the Host header
      regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
      m1=regex.match(i)
 
      #Extract and store the Host header
      if m1:
        t2=i.split(': ')
 
    return t2

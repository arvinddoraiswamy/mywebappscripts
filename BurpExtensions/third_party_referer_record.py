from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys

urls_in_scope=['qa.blah.com','qa.ooboob.com']

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
    hostname=BurpExtender.get_host_header_from_request(self,request_object)

    #Check if the URL is NOT in scope. We want to look at referers for the requests that are made to OTHER domains.
    if (hostname) and (hostname[1] not in urls_in_scope):
      #Extract referer from header
      referer=BurpExtender.get_referer_header_from_request(self,request_object)
      if referer:
        t1=referer[1].split('/')
        if t1[2] in urls_in_scope:
          print referer[1]

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

  def get_referer_header_from_request(self,requestInfo):
    t1 = requestInfo.getHeaders()
    header_name='Referer:'
 
    for i in t1:
      #Search for the Referer header
      regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
      m1=regex.match(i)
 
      #Extract and store the Referer header
      if m1:
        t2=i.split(': ')
        return t2

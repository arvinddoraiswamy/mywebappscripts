from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys

excluded_file_extensions=['.jpg','.gif','.bmp','.png','.css','.js','.htc']
urls_in_scope=['securityinnovation.com']

referer_header_name='Referer'
referer_header_value='https://securityinnovation.com/'

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
      hostname=BurpExtender.get_host_header_from_request(self,requestInfo)

      #Check if the URL is in scope. This is to eliminate stray traffic.
      if hostname and hostname[1] in urls_in_scope:
        referer=BurpExtender.get_referer_header_from_request(self,requestInfo)
        if not referer[1].startswith(referer_header_value):
          print str(request_url)+'\t\t'+str(referer[1])

  def get_referer_header_from_request(self,requestInfo):
    t1 = requestInfo.getHeaders()
    header_name='Referer:'
 
    regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
    for i in t1:
      #Search for the Referer header
      m1=regex.match(i)
 
      #Extract and store the Referer header
      if m1:
        t2=i.split(': ')
 
    return t2

  def get_host_header_from_request(self,requestInfo):
    t1 = requestInfo.getHeaders()
    header_name='Host:'
 
    regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)
    for i in t1:
      #Search for the Host header
      m1=regex.match(i)
 
      #Extract and store the Host header
      if m1:
        t2=i.split(': ')
 
    return t2

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import urllib

urls_in_scope=['securityinnovation.com','qa.ooboob.com']

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Record Set Cookie Headers")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    setcookie_header=BurpExtender.record_setcookie_headers(self,messageIsRequest,message)

  def record_setcookie_headers(self,messageIsRequest,message):
    if not messageIsRequest:
      response_byte_array=message.getMessageInfo().getResponse()
      responseInfo = self._helpers.analyzeResponse(response_byte_array)
      setcookie_header=BurpExtender.get_setcookie_from_header(self,responseInfo)
      if setcookie_header:
        print setcookie_header[1]

  def get_setcookie_from_header(self,responseInfo):
    t1 = responseInfo.getHeaders()
    header_name='Set-Cookie:'
 
    #Search for the Set Cookie header
    regex=re.compile('^.*%s.*'%header_name,re.IGNORECASE)

    for i in t1:
      m1=regex.match(i)
      #Extract and store the Set Cookie header
      if m1:
        t2=i.split(': ')
        return t2

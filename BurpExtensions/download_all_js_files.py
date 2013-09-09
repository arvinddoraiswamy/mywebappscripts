from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import os
import re

urls_in_scope=['pagead2.googlesyndication.com']
download_path='/tmp'

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Download JS files")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    BurpExtender.download_all_JS_files(self,messageIsRequest,message)

  def download_all_JS_files(self,messageIsRequest,message):
    request_byte_array=message.getMessageInfo().getRequest()
    if messageIsRequest:
      request_http_service=message.getMessageInfo().getHttpService()
      request_byte_array=message.getMessageInfo().getRequest()
      request_object=self._helpers.analyzeRequest(request_http_service, request_byte_array)

      #Extract hostname from header
      hostname=BurpExtender.get_host_header_from_request(self,request_object)

      #Check if the URL is in scope. This is to eliminate stray traffic.
      if hostname and hostname[1] in urls_in_scope:
        request_url=request_object.getUrl()
        if str(request_url).endswith('.js'):
          print request_url
          os.chdir(download_path)
          os.system("wget "+str(request_url))

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

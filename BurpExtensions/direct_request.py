from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import os

session_cookie_names = ['_whetstone_session']
urls_in_scope = ['whetstone-test']
remote_listening_port = 80
protocol = 'http'
hostname = []

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers and the callbacks object. This is needed as you can't pass these as parameters to processProxymessage.
    self._helpers = callbacks.getHelpers()
    self._callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName("Direct Request")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    if messageIsRequest:
      request_byte_array,flag = BurpExtender.remove_sessioncookie_from_request(self,messageIsRequest,message)
      if flag == 1:
        BurpExtender.generate_request(self,request_byte_array)

  def remove_sessioncookie_from_request(self,messageIsRequest,message):
    request_byte_array=message.getMessageInfo().getRequest()
    requestInfo = self._helpers.analyzeRequest(request_byte_array)
    flag=0

    #Extract hostname from header
    global hostname
    hostname=webcommon.get_host_header_from_request(self,requestInfo)

    #Check if the URL is in scope. This is to eliminate stray traffic.
    if hostname and hostname[1] in urls_in_scope:
      request_string=self._helpers.bytesToString(request_byte_array)
      #Find and then remove all session cookies
      for cookie in session_cookie_names:
        regex=re.compile(r'(.*)(%s=\w+)(;*?)'%cookie,re.IGNORECASE|re.DOTALL)
        m1=regex.match(request_string)
        pritn m1.group()
        if m1:
          request_string=re.sub(m1.group(2),'',request_string)
          #Restore the manipulated string to the byte array so it can be reused.
          request_byte_array = self._helpers.stringToBytes(request_string)
          flag=1

    return request_byte_array,flag

  def generate_request(self,request_byte_array):            
    if request_byte_array:
      http_service = self._helpers.buildHttpService(hostname[1],remote_listening_port,protocol)
      req_resp = self._callbacks.makeHttpRequest(http_service, request_byte_array)
      response_byte_array = req_resp.getResponse()
      response_object=self._helpers.analyzeResponse(response_byte_array)
      response_string = self._helpers.bytesToString(response_byte_array)
      request_object=self._helpers.analyzeRequest(http_service,request_byte_array)

      '''
      Print out the URL requested, the response code and the length of the response. The reason for doing this is so you can
      compare the lengths and see if all the requests are getting redirected to a login page or custom error page.
      '''
      print str(request_object.getUrl())+'\t'+str(response_object.getStatusCode())+'\t'+str(len(response_string))

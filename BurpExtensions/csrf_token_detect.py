from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import os

#This is where you put the name of the token that is being used in the application you are testing. It searches for __VIEWSTATE by default. The 
#extension will search for this token in every request and tell you which requests do NOT have a token, so you can manually explore.
anticsrf_token_name='securityRequestParameter'

excluded_file_extensions=['.jpg','.gif','.bmp','.png','.css','.js','.htc','.jpeg','.ico','.svg']
urls_in_scope=['blah.test.com']

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("CSRF Token Detector")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    request_url = BurpExtender.detect_csrf_token(self,messageIsRequest,message)
    if request_url:
      print request_url

  def detect_csrf_token(self,messageIsRequest,message):
    #Only process requests as that's where the Token should be
    request_byte_array=message.getMessageInfo().getRequest()
    if messageIsRequest:
      t1=[]
      t2=[]
      flag=0

      requestInfo = self._helpers.analyzeRequest(request_byte_array)

      #Extract hostname from header
      hostname=webcommon.get_host_header_from_request(self,requestInfo)

      #Check if the URL is in scope. This is to eliminate stray traffic.
      if hostname and hostname[1] in urls_in_scope:
        csrf_token_value=self._helpers.getRequestParameter(request_byte_array,anticsrf_token_name)
        request_string=self._helpers.bytesToString(request_byte_array)
        urlpath=request_string.split("\n")
        tmp2=urlpath[0].split(' ')
 
      #If there's no token, check if it's an image, js or css file. In this case, a token isn't needed
        if not csrf_token_value:
          for tmp3 in excluded_file_extensions:
            #Search for file extension. If you want a more complex regex..remember to compile the regex. DO.NOT.FORGET :)
            tmp4=re.search(tmp3,tmp2[-2])
            if tmp4:
              flag=1
 
          #Not to be excluded and the request doesn't contain a token
          if flag != 1:
            return urlpath[0]

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import urllib
import os

param_constant_type_mapping = {'0':'PARAM_URL','1':'PARAM_BODY','2':'PARAM_COOKIE','3':'PARAM_XML','4':'PARAM_XML_ATTR','5':'PARAM_MULTIPART_ATTR','6':'PARAM_JSON'}
url_patterns=['http','https','://','/','\w\.\w+$','\\\\','%5c','%2f','%3a']
excluded_url_patterns=['\d+/\d+/\d+','\d+%2f\d+%2f\d+']
urls_in_scope=['testblah.com','qa.blah.com','qa.ooboob.com']

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("URL in Parameter Detector")

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

    # register ourselves as a Proxy listener
    callbacks.registerProxyListener(self)

  def processProxyMessage(self,messageIsRequest,message):
    request_urls = BurpExtender.detect_urls_in_parameters(self,messageIsRequest,message)
    if request_urls:
      print request_urls

  def detect_urls_in_parameters(self,messageIsRequest,message):
    #Only process requests
    if messageIsRequest:
      request_http_service=message.getMessageInfo().getHttpService()
      request_byte_array=message.getMessageInfo().getRequest()
      request_object=self._helpers.analyzeRequest(request_http_service, request_byte_array)

      #Extract hostname from header
      hostname=webcommon.get_host_header_from_request(self,request_object)

      #Check if the URL is in scope. This is to eliminate stray traffic.
      if hostname and hostname[1] in urls_in_scope:
        request_url=request_object.getUrl()
        request_parameters=request_object.getParameters()

        #Check if the value of each parameter matches a whitelist or a blacklist. Both lists are defined above as global variables.
        for param in request_parameters:
          blacklist=0
          whitelist=0
          for excluded_pattern in excluded_url_patterns:
            regex=re.compile('.*%s.*'%excluded_pattern,re.IGNORECASE)
            m2=regex.match(str(param.getValue()))
            #m3=regex.match(urllib.quote(str(param.getValue())))
            if m2:# or m3:
              blacklist=1

          #If it doesn't match a blacklist
          if blacklist == 0:
            for pattern in url_patterns:
              regex=re.compile('.*%s.*'%pattern,re.IGNORECASE)
              m1=regex.match(str(param.getValue()))
              #m4=regex.match(urllib.quote_plus(str(param.getValue())))
              if m1:# or m4:
                whitelist=1

          #If the value for the URL parameter matches a pattern print it out
          if whitelist==1:
            #The moment you detect that a URL matches a pattern you also want to fuzz it. Hence you do the following:
            # -- Check if you already sent it to Intruder
            # -- If not, mark the positions that you want scanned
            # -- Set the payload list, set any other Intruder customizations up
            # -- Send the URL to be fuzzed to Intruder
            # -- Probably fuzz it as well and save the Intruder results to be imported later
            print str(request_url)+"\t\t"+str(param_constant_type_mapping[str(param.getType())])+"\t\t"+str(param.getName())+"\t\t"+str(param.getValue())
    else:
      response_byte_array=message.getMessageInfo().getResponse()
      responseInfo = self._helpers.analyzeResponse(response_byte_array)

      responseCode=webcommon.get_response_code_from_headers(self,responseInfo)
      location=webcommon.get_location_from_headers(self,responseInfo)
      if location:
        print str(responseCode[0])+'\t\t'+str(location[1])

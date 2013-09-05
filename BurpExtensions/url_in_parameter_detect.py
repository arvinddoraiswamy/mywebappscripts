from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
import re
import sys
import urllib

param_constant_type_mapping = {'0':'PARAM_URL','1':'PARAM_BODY','2':'PARAM_COOKIE','3':'PARAM_XML','4':'PARAM_XML_ATTR','5':'PARAM_MULTIPART_ATTR','6':'PARAM_JSON'}
url_patterns=['http','https','://','/','\w\.\w+$','\\\\','%5c','%2f','%3a']
excluded_url_patterns=['\d+/\d+/\d+','\d+%2f\d+%2f\d+']
urls_in_scope=['qa.blah.com','qa.ooboob.com']

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
      hostname=BurpExtender.get_host_header_from_request(self,request_object)

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
            print str(request_url)+"\t\t"+str(param_constant_type_mapping[str(param.getType())])+"\t\t"+str(param.getName())+"\t\t"+str(param.getValue())

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

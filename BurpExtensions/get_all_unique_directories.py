from burp import IBurpExtender
import jarray
import os

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

unique_list_of_urls=[]

class BurpExtender(IBurpExtender):
  def registerExtenderCallbacks(self,callbacks):
    list_of_urls=[]
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Get all URLs")

    # Get proxy history
    proxyhistory=callbacks.getProxyHistory()

    #Read each request in proxy history
    for request in proxyhistory:
      request_byte_array=request.getRequest()
      requestInfo = self._helpers.analyzeRequest(request_byte_array)
      BurpExtender.get_urls(self,callbacks,request_byte_array,requestInfo)

    for url in unique_list_of_urls:
      url_without_query_string=url.split('?')
      if url_without_query_string[0].endswith(".php"):
        print url_without_query_string[0]

  def get_urls(self,callbacks,request_byte_array,requestInfo):
    if requestInfo:
      request_headers=requestInfo.getHeaders()
      t0=request_headers[0].split(' ')
      t1=request_headers[1].split(': ')

      #Extract directories from every single request in proxy history
      url=webcommon.extract_urls(self,callbacks,t0[1])

      if url not in unique_list_of_urls:
        unique_list_of_urls.append(url)

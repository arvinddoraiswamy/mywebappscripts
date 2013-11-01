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
    callbacks.setExtensionName("Common Directory Search")

    # Get proxy history
    proxyhistory=callbacks.getProxyHistory()

    #Read each request in proxy history
    for request in proxyhistory:
      request_byte_array=request.getRequest()
      requestInfo = self._helpers.analyzeRequest(request_byte_array)
      BurpExtender.fuzz_url(self,callbacks,request_byte_array,requestInfo)

  def fuzz_url(self,callbacks,request_byte_array,requestInfo):
    if requestInfo:
      request_headers=requestInfo.getHeaders()
      t0=request_headers[0].split(' ')
      t1=request_headers[1].split(': ')

      #Extract directories from every single request in proxy history
      directory=webcommon.extract_directory(self,callbacks,t0[1])

      if directory not in unique_list_of_urls:
        unique_list_of_urls.append(directory)
        request_string=self._helpers.bytesToString(request_byte_array)
        #String manipulation with a lot of temp variables t2,t3,t4 etc
        t2=request_string.split('\n')
        t3=t2[0].split(' ')
        t3[1]=directory+'/dummy'
        t4=' '.join(t3)
        t2[0]=t4
        request_string='\n'.join(t2)
        #String manipulation ends. Variable reuse possible.

        #Restore the manipulated string to the byte array so it can be reused.
        request_byte_array=self._helpers.stringToBytes(request_string)

        #Calculate correct offset here and send that request to Intruder to get fuzzed. Remember to configure the right payload set in Intruder
        #before running this extension
        callbacks.sendToIntruder(t1[1],443,1,request_byte_array,[jarray.array([request_string.find('/dummy')+1,request_string.find(' HTTP/1.1')], "i")])

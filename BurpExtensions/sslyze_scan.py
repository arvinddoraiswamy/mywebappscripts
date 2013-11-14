from burp import IBurpExtender
import os
result_file='/tmp/sslscan_result'

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender):
  def registerExtenderCallbacks(self,callbacks):
    global hostname

    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()
    self._callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName("SSlyze Scan")
    unique_list_of_urls=BurpExtender.get_all_hosts(self)
    list_ssl_urls=BurpExtender.extract_ssl_hosts(self,unique_list_of_urls)
    BurpExtender.scan_ssl(self,list_ssl_urls)

  def get_all_hosts(self):
    unique_list_of_urls=[]
    # Get proxy history
    proxyhistory=self._callbacks.getProxyHistory()

    #Read each request in proxy history
    for request in proxyhistory:
      request_byte_array=request.getRequest()
      request_http_service=request.getHttpService()
      requestInfo = self._helpers.analyzeRequest(request_http_service,request_byte_array)

      t1=str(requestInfo.getUrl())
      t2=t1.split('/')
      url=t2[0]+'//'+t2[2]

      #Extract hostname from header
      hostname=webcommon.get_host_header_from_request(self,requestInfo)
      if url not in unique_list_of_urls:
        unique_list_of_urls.append(url)

    return unique_list_of_urls

  def extract_ssl_hosts(self,unique_list_of_urls):
    list_ssl_urls=[]
    for url in unique_list_of_urls:
      if url.startswith('https'):
        list_ssl_urls.append(url)

    return list_ssl_urls

  def scan_ssl(self,list_ssl_urls):
    for url in list_ssl_urls:
      print "Processing url "+url
      dest=url.split(':')
      cmd='python /media/9f576cb3-3236-42c7-b9bf-869b455b2d87/Installations/sslyze/sslyze-0.6_src/sslyze.py --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --hide_rejected_ciphers --reneg --certinfo=basic '+dest[1][2:]+' '+dest[2]+'>>result_file'
      os.system(cmd)

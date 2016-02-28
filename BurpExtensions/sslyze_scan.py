from burp import IBurpExtender
import os
sslyze_path= '/data/Installations/sslyze/sslyze.py'
result_dir=  '/tmp/'
result_file= 'sslscan_result'

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self,callbacks):
        global hostname

        self._helpers= callbacks.getHelpers()
        self._callbacks= callbacks

        callbacks.setExtensionName("SSLyze Scan")
        unique_list_of_urls= self.get_all_hosts()
        list_ssl_urls= self.extract_ssl_hosts(unique_list_of_urls)
        self.scan_ssl(list_ssl_urls)

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
          full_path=result_dir+dest[1][2:]+'_'+result_file
          cmd='python '+sslyze_path+ ' --regular --hsts --chrome_sha1 '+dest[1][2:]+' '+dest[2]+'>'+full_path
          os.system(cmd)

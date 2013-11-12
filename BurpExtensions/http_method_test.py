from burp import IBurpExtender
import jarray
import os

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

protocol='http'
remote_listening_port = 80
unique_list_of_urls=[]
filename='/tmp/abc'
unique_list_of_urls=[]
hostname=''

class BurpExtender(IBurpExtender):
  def registerExtenderCallbacks(self,callbacks):
    global hostname
    list_of_urls=[]
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()
    self._callbacks = callbacks

    # set our extension name
    callbacks.setExtensionName("HTTP method test")

    # Get proxy history
    proxyhistory=callbacks.getProxyHistory()

    #Read each request in proxy history
    for request in proxyhistory:
      request_byte_array=request.getRequest()
      requestInfo = self._helpers.analyzeRequest(request_byte_array)

      #Extract hostname from header
      hostname=webcommon.get_host_header_from_request(self,requestInfo)

      #Test PUT for each directory in the proxy history
      filepath=BurpExtender.test_put(self,callbacks,request_byte_array,hostname,requestInfo)

      #Get the file that you just PUT
      respcode=BurpExtender.check_file_existence_put(self,filepath)

      if respcode=='200':
        #Test DELETE for the file you uploaded
        BurpExtender.test_delete(self,filepath)

        #Get the file that you just DELETED. It should return a 404 if DELETE is enabled
        BurpExtender.check_file_existence_delete(self,filepath)


  def test_put(self,callbacks,request_byte_array,hostname,requestInfo):
    if requestInfo:
      request_headers=requestInfo.getHeaders()
      t0=request_headers[0].split(' ')
      respcode=request_headers[1].split(': ')

      #Extract directories from every single request in proxy history
      directory=webcommon.extract_directory(self,callbacks,t0[1])

      if directory not in unique_list_of_urls:
        unique_list_of_urls.append(directory)
        cmd="curl --upload-file "+filename+" "+protocol+'://'+hostname[1]+directory+'/'
        os.system(cmd)

      filepath=protocol+'://'+hostname[1]+directory+'/abc'
      return filepath

  def check_file_existence_put(self,filepath):            
    cmd='curl -s -w %{http_code} '+'"'+filepath+'"'+' -o /dev/null > /tmp/respcode'
    os.system(cmd)
    f=open('/tmp/respcode','rU')
    respcode=f.readline()
    f.close()

    if respcode=='200':
      print 'PUT succeeded - '+filepath
    elif respcode=='404':
      print 'PUT failed - '+filepath

    return respcode

  def test_delete(self,filepath):
    cmd='curl -X DELETE '+filepath
    os.system(cmd)

  def check_file_existence_delete(self,filepath):            
    cmd='curl -s -w %{http_code} '+'"'+filepath+'"'+' -o /dev/null > /tmp/respcode'
    os.system(cmd)
    f=open('/tmp/respcode','rU')
    respcode=f.readline()
    f.close()

    if respcode=='200':
      print 'DELETE failed - '+filepath
    elif respcode=='404':
      print 'DELETE succeeded - '+filepath

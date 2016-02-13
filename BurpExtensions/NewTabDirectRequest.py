from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
import re
import sys
import os

remote_listening_port = 80
protocol = 'http'
hostname = []

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("DirectRequest")
        callbacks.registerMessageEditorTabFactory(self)
        
    def createNewInstance(self, controller, editable):
        #This bit returns the new tab we are adding that we are now doing all the work on
        tab= DirectRequestTab(self, controller, editable)
        return tab

class DirectRequestTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    def remove_sessioncookie_from_request(self, content, http_service):
        requestInfo= self._extender._helpers.analyzeRequest(http_service, content)
        flag=0

        if self._extender._callbacks.isInScope(requestInfo.getUrl()):
            request_string=self._extender._helpers.bytesToString(content)
            m1=re.match(r'.*Cookie:(.*?)\r\n.*',request_string, re.DOTALL|re.MULTILINE)
            if m1:
                request_string=re.sub(m1.group(1),'',request_string)
                request_byte_array = self._extender._helpers.stringToBytes(request_string)
                flag=1

        return request_byte_array, flag, http_service


    def generate_request(self,request_byte_array,http_service):            
        req_resp = self._extender._callbacks.makeHttpRequest(http_service, request_byte_array)
        response_byte_array = req_resp.getResponse()
        response_object=self._extender._helpers.analyzeResponse(response_byte_array)
        response_string = self._extender._helpers.bytesToString(response_byte_array)

        return response_string

    def getTabCaption(self):
        return "DirectRequest"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()

    def isEnabled(self, content, isRequest):
        return isRequest
        
    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            request_byte_array= []
            requestInfo= self._extender._helpers.analyzeRequest(content)
            hostname=webcommon.get_host_header_from_request(self,requestInfo)
            http_service = self._extender._helpers.buildHttpService(hostname[1],remote_listening_port,protocol)
            r1= self._extender._callbacks.makeHttpRequest(http_service, content)
            r2= r1.getResponse()
            orig_resp= self._extender._helpers.bytesToString(r2)

            request_byte_array, flag, http_service= self.remove_sessioncookie_from_request(content, http_service)
            if flag == 1:
                new_resp= self.generate_request(request_byte_array,http_service)
                if len(orig_resp) == len(new_resp):
                    output= 'Direct requesting without cookies has the same response as the original. This might be a vuln. Here is the request that was sent:\n\n'
                    output += '-'*20+'\n'
                    output += self._extender._helpers.bytesToString(request_byte_array)
            self._txtInput.setText(output)
            self._txtInput.setEditable(self._editable)
            self._currentMessage= content
        return
    
    def getMessage(self):
        return self._currentMessage

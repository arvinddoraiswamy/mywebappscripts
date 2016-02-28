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
        callbacks.setExtensionName("InvertRequestMethod")
        callbacks.registerMessageEditorTabFactory(self)
        
    def createNewInstance(self, controller, editable):
        #This bit returns the new tab we are adding that we are now doing all the work on
        tab= InvertRequestTab(self, controller, editable)
        return tab

class InvertRequestTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    def getTabCaption(self):
        return "InvertRequest"
        
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
            requestInfo= self._extender._helpers.analyzeRequest(content)
            hostname= webcommon.get_host_header_from_request(self,requestInfo)
            http_service= self._extender._helpers.buildHttpService(hostname[1],remote_listening_port,protocol)

            bytes_req= self._extender._helpers.toggleRequestMethod(content)
            r1= self._extender._callbacks.makeHttpRequest(http_service, bytes_req)
            r2= r1.getResponse()
            orig_resp= self._extender._helpers.bytesToString(r2)
            self._txtInput.setText(self._extender._helpers.bytesToString(bytes_req)+'-'*10+'\n'+orig_resp)
            self._txtInput.setEditable(self._editable)
            self._currentMessage= orig_resp
        return
    
    def getMessage(self):
        return self._currentMessage

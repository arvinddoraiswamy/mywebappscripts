from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
import sys
import os
import re

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

filePayloadDir= '/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/filePayloads'
fileNameVar= 'filename'

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks= callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Fuzz File Upload")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu= []
        menu.append(JMenuItem("Test File Upload", None, actionPerformed= lambda x,inv=invocation:self.testFileUpload(inv)))
        return menu

    def testFileUpload(self, invocation):
        fileList= self.getListOfFiles()
        invMessage=invocation.getSelectedMessages()
        hostname= invMessage[0].getHttpService().getHost()
        port= invMessage[0].getHttpService().getPort()
        bytes_req= invMessage[0].getRequest()

        request= bytes_req.tostring()
        for i in fileList:
            r1= re.sub(r'('+fileNameVar+r'=").*(")', r'\1'+i+r'\2', request, re.DOTALL|re.MULTILINE)
            # Add regex to substitute fileContent depending on request structure

    def getListOfFiles(self):
        fileList= []
        for filename in os.listdir(filePayloadDir):
            fileList.append(filename)
        return fileList

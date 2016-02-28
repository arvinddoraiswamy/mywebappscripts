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

template= '/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/Clickjack.html'
poc= '/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/clickjackpoc.html'

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks= callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ClickJacking POC")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu= []
        menu.append(JMenuItem("ClickJacking POC", None, actionPerformed= lambda x,inv=invocation:self.clickJack(inv)))
        return menu

    def clickJack(self, invocation):
        invMessage=invocation.getSelectedMessages()
        bytes_req= invMessage[0].getRequest()

        hostname= invMessage[0].getHttpService().getHost()
        port= invMessage[0].getHttpService().getPort()
        protocol= invMessage[0].getHttpService().getProtocol()
        httpService= self._helpers.buildHttpService(hostname, port, protocol)

        requestInfo= self._helpers.analyzeRequest(httpService, bytes_req)
        self.createPOC(requestInfo.getUrl())

    def createPOC(self, url):
        with open(template) as f:
            content= f.read()
        r1= re.sub('DUMMYPLACEHOLDER', str(url), content)

        with open(poc, 'w') as f:
            f.write(r1)

        print 'A POC has been saved at ',poc

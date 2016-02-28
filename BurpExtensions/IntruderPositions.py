'''
http://forum.portswigger.net/thread/557/jython-error-convert-pylist
http://forum.portswigger.net/thread/829/format-payloadpositions-sendtointruder
'''

from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
import sys
import os
import re
import jarray
import java

#Adding directory to the path where Python searches for modules
module_folder = os.path.dirname('/home/arvind/Documents/Me/My_Projects/Git/WebAppsec/BurpExtensions/modules/')
sys.path.insert(0, module_folder)
import webcommon

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks= callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Set Scan Positions")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu= []
        menu.append(JMenuItem("Set URL Scan Positions", None, actionPerformed= lambda x,inv=invocation:self.urlSet(inv)))
        menu.append(JMenuItem("Set Body Scan Positions", None, actionPerformed= lambda x,inv=invocation:self.bodySet(inv)))
        menu.append(JMenuItem("Set Cookie Scan Positions", None, actionPerformed= lambda x,inv=invocation:self.cookieSet(inv)))
        return menu

    def urlSet(self, invocation):
        invMessage=invocation.getSelectedMessages()
        hostname= invMessage[0].getHttpService().getHost()
        port= invMessage[0].getHttpService().getPort()
        bytes_req= invMessage[0].getRequest()

        r1= self._helpers.analyzeRequest(invMessage[0])
        offsets= []
        no_of_parameters= len(r1.getParameters())
        for p1 in r1.getParameters():
            if p1.getType() == 0:
                offset= []
                offset.append(p1.getValueStart())
                offset.append(p1.getValueEnd())
                offsets.append(jarray.array(offset,'i'))

        self._callbacks.sendToIntruder(hostname, port, 1, bytes_req, offsets)

    def bodySet(self, invocation):
        invMessage=invocation.getSelectedMessages()
        hostname= invMessage[0].getHttpService().getHost()
        port= invMessage[0].getHttpService().getPort()
        bytes_req= invMessage[0].getRequest()

        r1= self._helpers.analyzeRequest(invMessage[0])
        offsets= []
        no_of_parameters= len(r1.getParameters())
        for p1 in r1.getParameters():
            if p1.getType() == 1:
                offset= []
                offset.append(p1.getValueStart())
                offset.append(p1.getValueEnd())
                offsets.append(jarray.array(offset,'i'))

        self._callbacks.sendToIntruder(hostname, port, 1, bytes_req, offsets)

    def cookieSet(self, invocation):
        invMessage=invocation.getSelectedMessages()
        hostname= invMessage[0].getHttpService().getHost()
        port= invMessage[0].getHttpService().getPort()
        bytes_req= invMessage[0].getRequest()

        r1= self._helpers.analyzeRequest(invMessage[0])
        offsets= []
        no_of_parameters= len(r1.getParameters())
        for p1 in r1.getParameters():
            if p1.getType() == 2:
                offset= []
                offset.append(p1.getValueStart())
                offset.append(p1.getValueEnd())
                offsets.append(jarray.array(offset,'i'))

        self._callbacks.sendToIntruder(hostname, port, 1, bytes_req, offsets)

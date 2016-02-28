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

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks= callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CSRF Token Analysis")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu= []
        menu.append(JMenuItem("Analyze CSRF Token", None, actionPerformed= lambda x,inv=invocation:self.initFunc(inv)))
        return menu

    def initFunc(self, invocation):
        invMessage=invocation.getSelectedMessages()
        bytes_req= invMessage[0].getRequest()
        request= bytes_req.tostring()
        response= invMessage[0].getResponse().tostring()
        origlen= len(response)
        self.testCsrf(request, invMessage, origlen)

    def testCsrf(self, request, invMessage, origlen):
        self.testNoToken(request, invMessage, origlen)
        self.testBlankToken(request, invMessage, origlen)
        self.testWellFormedToken(request, invMessage, origlen)
        self.testNotWellFormedToken(request, invMessage, origlen)

    def testNoToken(self, request, invMessage, origlen):
        pattern1= r'(.*)(&c2=.*)&'
        pattern2= r'(.*)(&c2=.*)'
        m1= re.match(pattern1, request,re.MULTILINE|re.DOTALL)
        if m1:
            r1= re.sub(m1.group(2),'',request)
            new_bytesreq= self._helpers.stringToBytes(r1)
            newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
            l1= len(self._helpers.bytesToString(newresp.getResponse()))

            if l1 == origlen:
                print "Deleted parameter gives same response"
        else:
            m1= re.match(pattern2, request, re.MULTILINE|re.DOTALL)
            if m1:
                r1= re.sub(m1.group(2),'',request)
                new_bytesreq= self._helpers.stringToBytes(r1)
                newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
                l1= len(self._helpers.bytesToString(newresp.getResponse()))

                if l1 == origlen:
                    print "Deleted parameter gives same response"

    def testBlankToken(self, request, invMessage, origlen):
        pattern1= r'(.*&c2=)(.*)&'
        pattern2= r'(.*&c2=)(.*)'
        m1= re.match(pattern1, request,re.MULTILINE|re.DOTALL)
        if m1:
            r1= re.sub(m1.group(2),'',request)
            new_bytesreq= self._helpers.stringToBytes(r1)
            newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
            l1= len(self._helpers.bytesToString(newresp.getResponse()))

            if l1 == origlen:
                print "Blank parameter value gives same response"
        else:
            m1= re.match(pattern2, request, re.MULTILINE|re.DOTALL)
            if m1:
                r1= re.sub(m1.group(2),'',request)
                new_bytesreq= self._helpers.stringToBytes(r1)
                newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
                l1= len(self._helpers.bytesToString(newresp.getResponse()))

                if l1 == origlen:
                    print "Blank parameter value gives same response"

    def testWellFormedToken(self, request, invMessage, origlen):
        pattern1= r'(.*&c2=)(.*)&'
        pattern2= r'(.*&c2=)(.*)'
        m1= re.match(pattern1, request,re.MULTILINE|re.DOTALL)
        if m1:
            t1= list(str(m1.group(2)))
            t1[0]= chr(ord(t1[0])+1)
            r1= re.sub(m1.group(2),''.join(t1),request)
            new_bytesreq= self._helpers.stringToBytes(r1)
            newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
            l1= len(self._helpers.bytesToString(newresp.getResponse()))

            if l1 == origlen:
                print "Well formed random value gives same response"
        else:
            m1= re.match(pattern2, request, re.MULTILINE|re.DOTALL)
            if m1:
                t1= list(str(m1.group(2)))
                t1[0]= chr(ord(t1[0])+1)
                r1= re.sub(m1.group(2),''.join(t1),request)
                new_bytesreq= self._helpers.stringToBytes(r1)
                newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
                l1= len(self._helpers.bytesToString(newresp.getResponse()))

                if l1 == origlen:
                    print "Well formed random value gives same response"

    def testNotWellFormedToken(self, request, invMessage, origlen):
        pattern1= r'(.*&c2=)(.*)&'
        pattern2= r'(.*&c2=)(.*)'
        m1= re.match(pattern1, request,re.MULTILINE|re.DOTALL)
        if m1:
            r1= re.sub(m1.group(2),'rubbishtoken',request)
            new_bytesreq= self._helpers.stringToBytes(r1)
            newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
            l1= len(self._helpers.bytesToString(newresp.getResponse()))

            if l1 == origlen:
                print "Random value gives same response"
        else:
            m1= re.match(pattern2, request, re.MULTILINE|re.DOTALL)
            if m1:
                r1= re.sub(m1.group(2),'',request)
                new_bytesreq= self._helpers.stringToBytes(r1)
                newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
                l1= len(self._helpers.bytesToString(newresp.getResponse()))

                if l1 == origlen:
                    print "Random value gives same response"

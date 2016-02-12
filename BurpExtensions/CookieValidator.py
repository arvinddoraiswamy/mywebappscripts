'''
http://cosec.blogspot.com/2013_06_01_archive.html

Use this extension when you want to test 1 specific request and identify which cookies are important. The best way to do this is to identify a request that is 
definitely for a private URL. Usually, cookies are valid across all the requests of the application, unless something is very horribly done so testing a few requests
should be good enough in most cases.
'''

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
        callbacks.setExtensionName("Cookie Validator")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu= []
        #Need to ask someone how the f*** lambda actually works in code. I get it in theory.
        menu.append(JMenuItem("Useful cookies", None, actionPerformed= lambda x,inv=invocation:self.initFunc(inv)))
        return menu

    def initFunc(self, invocation):
        invMessage=invocation.getSelectedMessages()
        bytes_req= invMessage[0].getRequest()
        request= bytes_req.tostring()
        response= invMessage[0].getResponse().tostring()
        origlen= len(response)
        requestArray= request.split('\n')

        count, cookies= self.getCookies(requestArray, response)
        cookies_that_matter= self.makeRequestsWithoutCookies(count, origlen, invMessage, requestArray, cookies)

        if len(cookies_that_matter) > 0:
            print 'Here is a list of cookies that might matter. The rest are most probably a waste of time you should spend no time analyzing in detail.'
            print cookies_that_matter
        else:
            print 'No cookies matter. Test for Direct Request :)'

    def makeRequestsWithoutCookies(self, count, origlen, invMessage, requestArray, cookies):
        p1= '\n'.join(requestArray[0:count-1])
        p2= '\n'.join(requestArray[count+1:])
        cookieheader= 'Cookies: '
        cookies_that_matter= []

        orig_cookies= cookies.split(';')
        for num,cookie in enumerate(orig_cookies):
            r1= ''
            r1= p1+'\n'+cookieheader
            c1= orig_cookies
            del(c1[num])
            c2= ';'.join(c1)
            r1 += c2
            r1 += '\n'
            r1 += p2
            r1 += '\n'
            new_bytesreq= self._helpers.stringToBytes(r1)

            newresp= self._callbacks.makeHttpRequest(invMessage[0].getHttpService(), new_bytesreq)
            r1= newresp.getResponse().tostring()

            if origlen != len(r1):
                cookies_that_matter.append(orig_cookies[num])
            else:
                continue

        return cookies_that_matter

    def getCookies(self, requestArray, response):
        pattern= 'Cookie:\s*'
        regex=re.compile(r'%s(.*)'%pattern, re.DOTALL|re.MULTILINE)
        for count,r1 in enumerate(requestArray):
            m1= regex.match(r1)
            if m1 is not None:
                cookies= m1.group(1)
                break
            else:
                continue

        cookies += ';'
        return count, cookies

'''
Based on http://portswigger.net/burp/extender/examples/CustomEditorTab.zip
'''

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RequestURLDecode")
        callbacks.registerMessageEditorTabFactory(self)
        
    def createNewInstance(self, controller, editable):
        #This bit returns the new tab we are adding that we are now doing all the work on
        tab= UrlDecoderTab(self, controller, editable)
        return tab

class UrlDecoderTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    def decodeData(self, content):
        params= self._extender._helpers.analyzeRequest(content).getParameters()
        getparams= ''
        postparams= ''
        cookies= ''

        for param in params:
            name= param.getName()
            ptype= param.getType()
            value= param.getValue()
            for count in range(1,4):
                t2= self._extender._helpers.urlDecode(value)
                value= t2
            if ptype == param.PARAM_URL:
                getparams= getparams+name+'='+value+'&'
            if ptype == param.PARAM_BODY:
                postparams= postparams+name+'='+value+'&'
            if ptype == param.PARAM_COOKIE:
                cookies= cookies+name+'='+value+';'
    
        return cookies, getparams, postparams

    def getTabCaption(self):
        return "URL"
        
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
            cookies, getparams, postparams= self.decodeData(content)
            output=''
            if len(cookies) > 0:
                output+= 'Cookies:\n'+'-'*10+'\n'+cookies[:-1]+'\n'
            if len(getparams) > 0:
                output+= 'Get Parameters:\n'+'-'*20+'\n'+getparams[:-1]+'\n'
            if len(postparams) > 0:
                output+= 'Post Parameters:\n'+'-'*20+'\n'+postparams[:-1]+'\n'
            self._txtInput.setText(output)
            self._txtInput.setEditable(self._editable)
        return
    
    def getMessage(self):
        return self._currentMessage

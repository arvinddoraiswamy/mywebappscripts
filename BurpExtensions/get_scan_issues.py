from burp import IBurpExtender

class BurpExtender(IBurpExtender):
  def registerExtenderCallbacks(self,callbacks):
    # Get a reference to the Burp helpers object
    self._helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Get Scanner issues")

    # Get proxy history
    url= 'https://<URL>/'
    scanissues=callbacks.getScanIssues(url)

    for issue in scanissues:
        print issue.getIssueName(), issue.getUrl()

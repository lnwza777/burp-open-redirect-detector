# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL
from java.util import List, ArrayList

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Open Redirect Parameter Detector")
        callbacks.registerScannerCheck(self)
        print("Open Redirect Detector loaded.")
        return

    def doPassiveScan(self, baseRequestResponse):
        issues = ArrayList()
        request = baseRequestResponse.getRequest()
        analyzedRequest = self._helpers.analyzeRequest(baseRequestResponse)
        url = analyzedRequest.getUrl()
        parameters = analyzedRequest.getParameters()

       
        suspicious_keywords = [
            "next", "url", "target", "rurl", "dest", "destination", "redir",
            "redirect_uri", "redirect_url", "redirect", "view", "to",
            "image_url", "go", "return", "returnTo", "return_to",
            "checkout_url", "continue", "return_path", "success", "data",
            "qurl", "login", "logout", "ext", "clickurl", "goto", "rit_url",
            "forward_url", "forward", "pic", "callback_url", "jump", "jump_url",
            "originUrl", "origin", "Url", "desturl", "u", "page", "u1", "action",
            "action_url", "Redirect", "sp_url", "service", "recurl", "uri",
            "allinurl", "q", "link", "src", "linkAddress", "location", "burl",
            "request", "backurl", "RedirectUrl", "ReturnUrl", "click", "j", "tc", "auto"
        ]

        found_params = []

        for param in parameters:
            param_name = param.getName().lower()
            for keyword in suspicious_keywords:
                if param_name == keyword.lower():
                    found_params.append(param.getName())

        if found_params:
            
            issues.add(CustomScanIssue(
                httpService=baseRequestResponse.getHttpService(),
                url=url,
                requestResponse=baseRequestResponse,
                name="Potential Open Redirect Parameter Detected",
                detail="Request contains the following potentially dangerous redirect parameter(s): <b>{}</b><br><br>No response analysis performed.".format(
                    ", ".join(found_params)
                ),
                severity="Information"
            ))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1  

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, requestResponse, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._requestResponse = requestResponse
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Firm"

    def getIssueBackground(self):
        return "Certain parameters are commonly used in open redirect attacks when unsafely handled."

    def getRemediationBackground(self):
        return "Validate redirect parameters against an allowlist or avoid using user-controlled URLs."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self._requestResponse]

    def getHttpService(self):
        return self._httpService

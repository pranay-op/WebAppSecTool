from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpListener
import re
import json
import zlib
from collections import defaultdict
import math
from java.net import URL
from java.io import BufferedReader, InputStreamReader

class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Miner")
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        print("JS Miner extension loaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY:
            response = messageInfo.getResponse()
            if response:
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()
                body = response[analyzedResponse.getBodyOffset():]
                contentType = next((header for header in headers if header.lower().startswith("content-type:")), "")
                if "javascript" in contentType or messageInfo.getUrl().toString().endswith(".js"):
                    findings = self.scan_js_content(body)
                    if findings:
                        for finding in findings:
                            self.report_issue(messageInfo, finding)

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        if response:
            analyzedResponse = self._helpers.analyzeResponse(response)
            headers = analyzedResponse.getHeaders()
            body = response[analyzedResponse.getBodyOffset():]
            contentType = next((header for header in headers if header.lower().startswith("content-type:")), "")
            if "javascript" in contentType or baseRequestResponse.getUrl().toString().endswith(".js"):
                findings = self.scan_js_content(body)
                issues = []
                if findings:
                    for finding in findings:
                        issues.append(CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse],
                            finding['name'],
                            finding['detail'],
                            finding['severity']
                        ))
                return issues if issues else None
        return None

    def scan_js_content(self, content):
        findings = []
        content_text = self.decompress_content(content)

        secrets = self.find_secrets(content_text)
        if secrets:
            findings.append({
                'name': 'Exposed Secrets',
                'detail': json.dumps(secrets, indent=4),
                'severity': 'High'
            })

        subdomains = self.find_subdomains(content_text)
        if subdomains:
            findings.append({
                'name': 'Subdomains Exposed',
                'detail': json.dumps(subdomains, indent=4),
                'severity': 'Medium'
            })

        cloud_urls = self.find_cloud_urls(content_text)
        if cloud_urls:
            findings.append({
                'name': 'Cloud URLs Exposed',
                'detail': json.dumps(cloud_urls, indent=4),
                'severity': 'Medium'
            })

        api_endpoints = self.find_api_endpoints(content_text)
        if api_endpoints:
            findings.append({
                'name': 'API Endpoints Exposed',
                'detail': json.dumps(api_endpoints, indent=4),
                'severity': 'Low'
            })

        dependencies = self.find_dependencies(content_text)
        if dependencies:
            findings.append({
                'name': 'Dependency Confusion',
                'detail': json.dumps(dependencies, indent=4),
                'severity': 'High'
            })

        source_maps = self.find_source_maps(content_text)
        if source_maps:
            findings.append({
                'name': 'Source Maps Found',
                'detail': json.dumps(source_maps, indent=4),
                'severity': 'Info'
            })

        return findings

    def decompress_content(self, content):
        try:
            return zlib.decompress(content, 16+zlib.MAX_WBITS).decode('utf-8')
        except:
            try:
                return content.decode('utf-8')
            except:
                return content

    def find_secrets(self, js_content):
        secrets = re.findall(r'(api_key|secret|password|token|key|auth)=["\']?([a-zA-Z0-9_\-]+)["\']?', js_content, re.IGNORECASE)
        return secrets

    def find_subdomains(self, js_content):
        subdomains = re.findall(r'https?://([a-zA-Z0-9\-]+\.example\.com)', js_content)
        return subdomains

    def find_cloud_urls(self, js_content):
        patterns = {
            'AWS': r'(https?://[a-zA-Z0-9\-\.]*\.amazonaws\.com)',
            'Google': r'(https?://[a-zA-Z0-9\-\.]*\.googleapis\.com)',
            'Azure': r'(https?://[a-zA-Z0-9\-\.]*\.windows\.net)',
            'CloudFront': r'(https?://[a-zA-Z0-9\-\.]*\.cloudfront\.net)',
            'Digital Ocean': r'(https?://[a-zA-Z0-9\-\.]*\.digitaloceanspaces\.com)',
            'Oracle': r'(https?://[a-zA-Z0-9\-\.]*\.oraclecloud\.com)',
            'Alibaba': r'(https?://[a-zA-Z0-9\-\.]*\.aliyuncs\.com)',
            'Firebase': r'(https?://[a-zA-Z0-9\-\.]*\.firebaseio\.com)',
            'Rackspace': r'(https?://[a-zA-Z0-9\-\.]*\.rackcdn\.com)',
            'DreamHost': r'(https?://[a-zA-Z0-9\-\.]*\.dreamhost\.com)',
        }
        cloud_urls = defaultdict(list)
        for cloud, pattern in patterns.items():
            matches = re.findall(pattern, js_content)
            if matches:
                cloud_urls[cloud].extend(matches)
        return cloud_urls

    def find_api_endpoints(self, js_content):
        endpoints = re.findall(r'(https?://[a-zA-Z0-9\-/\.]*\/api\/[a-zA-Z0-9\-/\.]*)', js_content)
        return endpoints

    def find_dependencies(self, js_content):
        dependencies = re.findall(r'import\s+.*\s+from\s+["\']([^"\']+)["\']', js_content)
        missing_dependencies = []
        for dep in dependencies:
            try:
                url = URL("https://registry.npmjs.org/{}".format(dep))
                connection = url.openConnection()
                connection.setRequestMethod("GET")
                responseCode = connection.getResponseCode()
                if responseCode == 404:
                    missing_dependencies.append(dep)
                connection.disconnect()
            except Exception as e:
                print("Error checking dependency {}: {}".format(dep, e))
        return missing_dependencies

    def find_source_maps(self, js_content):
        source_maps = re.findall(r'//# sourceMappingURL=(.*\.map)', js_content)
        return source_maps

    def report_issue(self, messageInfo, finding):
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        issue = CustomScanIssue(
            messageInfo.getHttpService(),
            url,
            [messageInfo],
            finding['name'],
            finding['detail'],
            finding['severity']
        )
        self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):

    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
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
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service


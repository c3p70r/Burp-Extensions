import hashlib
import time
import uuid

from burp import IBurpExtender, IHttpListener

# Replace with your own credentials
API_KEY = "YOUR_API_KEY"
API_SECRET = "YOUR_API_SECRET"
ALGORITHM = "SHA256"

# Target host to match for signing requests
TARGET_HOST = "your.target.api.host"

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HMAC Request Signer")
        callbacks.registerHttpListener(self)
        self._callbacks.printOutput("HMAC Signer extension loaded.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest and toolFlag in [
            self._callbacks.TOOL_PROXY,
            self._callbacks.TOOL_REPEATER,
            self._callbacks.TOOL_SCANNER,
            self._callbacks.TOOL_INTRUDER,
        ]:
            request = messageInfo.getRequest()
            httpService = messageInfo.getHttpService()
            try:
                analyzedRequest = self._helpers.analyzeRequest(httpService, request)
                host = ""

                try:
                    url = analyzedRequest.getUrl()
                    host = url.getHost() if url is not None else ""
                except:
                    for header in analyzedRequest.getHeaders():
                        if header.lower().startswith("host:"):
                            host = header.split(":", 1)[1].strip()
                            break

                if host.lower() == TARGET_HOST.lower():
                    new_request = self.signRequest(request, httpService)
                    messageInfo.setRequest(new_request)
            except Exception as e:
                self._callbacks.printOutput("Error processing request: " + str(e))

    def signRequest(self, request, httpService=None):
        try:
            if httpService is not None:
                analyzedRequest = self._helpers.analyzeRequest(httpService, request)
            else:
                analyzedRequest = self._helpers.analyzeRequest(request)
        except Exception as e:
            self._callbacks.printOutput("Error analyzing request: " + str(e))
            analyzedRequest = self._helpers.analyzeRequest(request)

        headers = list(analyzedRequest.getHeaders())
        filtered_headers = [
            h for h in headers if not h.lower().startswith(("authorization:", "x-api-key:"))
        ]

        method = analyzedRequest.getMethod().upper()
        query = ""

        try:
            url = analyzedRequest.getUrl()
            path = url.getPath()
            query = url.getQuery() or ""
        except:
            parts = headers[0].split(" ") if headers else []
            path = parts[1] if len(parts) > 1 else ""
            query = ""

        body_offset = analyzedRequest.getBodyOffset()
        body_bytes = request[body_offset:]

        try:
            body = self._helpers.bytesToString(body_bytes)
        except:
            body = ""

        timestamp = str(int(time.time() * 1000))
        nonce = uuid.uuid4().hex

        canonical_string = API_SECRET + body + path + query + method + timestamp + nonce
        computed_hash = hashlib.sha256(canonical_string.encode("utf-8")).hexdigest()

        auth_header = f"ZEPHR-HMAC-{ALGORITHM} {API_KEY}:{timestamp}:{nonce}:{computed_hash}"
        filtered_headers.append("Authorization: " + auth_header)
        filtered_headers.append("X-API-Key: " + API_KEY)

        return self._helpers.buildHttpMessage(filtered_headers, body_bytes)

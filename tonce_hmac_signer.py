from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import time
import json
import hmac
import hashlib
import base64

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Tonce HMAC Signer")
        callbacks.registerHttpListener(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        url_obj = request_info.getUrl()
        host = url_obj.getHost()
        path = url_obj.getPath().lstrip('/')

        # Replace with your target host
        if host != "your.api.host.com":
            return
        if not path.startswith("api/3/"):
            return

        request = messageInfo.getRequest()
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:].tostring()

        try:
            body_obj = json.loads(body)
        except Exception:
            self.stdout.println("Invalid JSON body, skipping.")
            return

        tonce = int(time.time() * 1000000)
        body_obj["tonce"] = tonce
        compact_body = json.dumps(body_obj, separators=(",", ":"))
        hmac_input = path + "\0" + compact_body

        # Replace with your secret in base64 format
        secret_b64 = "YOUR_SECRET_BASE64"
        key = base64.b64decode(secret_b64)
        h = hmac.new(key, hmac_input.encode(), hashlib.sha512).digest()
        signature = base64.b64encode(h).decode()

        headers = list(request_info.getHeaders())
        new_headers = [
            h for h in headers
            if not h.lower().startswith("rest-sign:") and not h.lower().startswith("rest-secret:")
        ]
        new_headers.append("Rest-Sign: " + signature)

        new_message = self._helpers.buildHttpMessage(new_headers, compact_body)
        messageInfo.setRequest(new_message)

        self.stdout.println("[+] Signed: " + path)
        self.stdout.println("    tonce: " + str(tonce))
        self.stdout.println("    HMAC input: " + hmac_input)
        self.stdout.println("    Signature: " + signature)

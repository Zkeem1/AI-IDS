from burp import IBurpExtender, IHttpListener

from predictor import (
    extract_features,
    predict_http_request
)


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(
            "ML HTTP IDS"
        )

        callbacks.registerHttpListener(
            self
        )

        print(
            "Machine Learning IDS Loaded"
        )


    def processHttpMessage(
        self,
        toolFlag,
        messageIsRequest,
        messageInfo
    ):

        if messageIsRequest:

            request = messageInfo.getRequest()

            raw_request = self._helpers.bytesToString(
                request
            )

            features = extract_features(
                raw_request
            )

            predict_http_request(
                features
            )
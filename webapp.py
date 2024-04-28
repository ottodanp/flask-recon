from typing import Callable, Tuple, Dict

from flask import Flask, request


class Listener:
    _flask_app: Flask
    _request_callback: Callable

    def __init__(self, request_callback: Callable) -> None:
        self._flask_app = Flask(__name__)
        self._request_callback = request_callback

    def error_handler(self, e) -> Tuple[str, int]:
        print(e, type(e))
        if request.method == "GET" and request.path == "/":
            return self._request_callback(*self.unpack_request_values(request), True)

        return self._request_callback(*self.unpack_request_values(request), False)

    def robots(self) -> Tuple[str, int]:
        self._request_callback(*self.unpack_request_values(request), True)
        return "User-agent: *\nDisallow: /", 200

    @staticmethod
    def unpack_request_values(req: request) -> Tuple[Dict[str, str], str, str, str, str, Dict[str, str]]:
        headers = req.headers
        method = req.method
        remote_address = req.remote_addr
        uri = req.path
        query_string = req.query_string
        body = req.data
        return dict(headers), method, remote_address, uri, query_string, dict(body)

    def run(self) -> None:
        self._flask_app.route("/robots.txt", methods=["GET"])(self.robots)
        self._flask_app.errorhandler(Exception)(self.error_handler)
        self._flask_app.run(host="0.0.0.0", port=80)

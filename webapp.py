from json import dumps
from sys import argv
from typing import Tuple, Dict, List, Generator, Any

from flask import Flask, request, render_template

from database import DbHandler


class Listener:
    _flask_app: Flask
    _authorized_addresses: List[str]
    _yield_forever: bool
    _database_handler: DbHandler
    _port: int

    def __init__(self, yield_forever: bool, authorized_hosts: List[str], port: int) -> None:
        self._flask_app = Flask(__name__)
        self._authorized_addresses = authorized_hosts
        self._yield_forever = yield_forever
        self._database_handler = DbHandler("requests", "postgres", "postgres", "localhost", "5432")
        self._port = port

    def error_handler(self, _) -> Tuple[str, int] | Generator[str, Any, Tuple[str, int]]:
        return self.handle_request(*self.unpack_request_values(request))

    def robots(self) -> Tuple[str, int]:
        self.handle_request(*self.unpack_request_values(request))
        return "User-agent: *\nDisallow: /", 200

    def view_hosts(self) -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
        if request.remote_addr not in self._authorized_addresses:
            return "Unauthorized", 403

        return render_template("view_hosts.html", hosts=self._database_handler.get_remote_hosts()), 200

    def view_requests(self) -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
        if request.remote_addr not in self._authorized_addresses:
            return "Unauthorized", 403

        host = request.args.get("host")
        if host is None:
            return "Missing host parameter", 400
        requests = self._database_handler.get_requests(host)
        return render_template("view_requests.html", requests=requests, host=host), 200

    def add_authorized_host(self):
        if request.remote_addr not in self._authorized_addresses:
            return "Unauthorized", 403

        host = request.args.get("host")
        if host is None:
            return "Missing host parameter", 400
        self._authorized_addresses.append(host)
        return "Host added", 200

    def handle_request(self, headers: Dict[str, str], method: str, remote_address: str, uri: str, query_string: str,
                       body: Dict[str, str]) -> Tuple[str, int] | Generator[str, Any, Tuple[str, int]]:
        acceptable = True if uri in ["/", "/favicon.ico", "/robots.txt"] else False
        self._database_handler.insert_request(
            acceptable,
            remote_address,
            method,
            dumps(headers),
            uri,
            query_string,
            dumps(body)
        )
        if not acceptable and self._yield_forever:
            # yield forever to keep the connection open and hang a thread on the malicious bot
            while True:
                yield "No"

        # we do not want to yield forever for an acceptable request so simply return 403
        return "", 403

    @staticmethod
    def unpack_request_values(req: request) -> Tuple[Dict[str, str], str, str, str, str, Dict[str, str]]:
        args = req.args.to_dict()
        query_string = "&".join([f"{k}={v}" for k, v in args.items()])
        return dict(req.headers), req.method, req.remote_addr, req.path, query_string, dict(req.data)

    def run(self) -> None:
        self._flask_app.route("/robots.txt", methods=["GET"])(self.robots)
        self._flask_app.route("/view_hosts", methods=["GET"])(self.view_hosts)
        self._flask_app.route("/view_requests", methods=["GET"])(self.view_requests)
        self._flask_app.route("/add_authorized_host", methods=["GET"])(self.add_authorized_host)
        self._flask_app.errorhandler(404)(self.error_handler)
        self._flask_app.run(host="0.0.0.0", port=self._port)


if __name__ == "__main__":
    try:
        port = int(argv[2])
        Listener(argv[1] == "yield", ["127.0.0.1", "82.4.45.86"], port).run()
    except IndexError:
        print("Usage: python3 webapp.py [yield|noyield] <port>")
        exit(1)

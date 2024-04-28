from json import dumps
from sys import argv
from typing import Tuple, Dict, List, Generator, Any

from flask import Flask, request, render_template, redirect

from config import Config
from database import DbHandler


class Listener:
    _config: Config
    _flask_app: Flask
    _authorized_addresses: List[str]
    _yield_forever: bool
    _database_handler: DbHandler
    _run_with_ssl: bool
    _port: int

    def __init__(self, flask_app: Flask, yield_forever: bool, run_with_ssl: bool, authorized_hosts: List[str],
                 port: int) -> None:
        self._config = Config()
        self._flask_app = flask_app
        self._authorized_addresses = authorized_hosts
        self._yield_forever = yield_forever
        self._run_with_ssl = run_with_ssl
        self._database_handler = DbHandler(
            self._config.database_name,
            self._config.database_username,
            self._config.database_password,
            self._config.database_host,
            self._config.database_port
        )
        self._port = port
        for host in authorized_hosts:
            self._database_handler.add_authorized_host(host)

    def error_handler(self, _) -> Tuple[str, int] | Generator[str, Any, Tuple[str, int]]:
        return self.handle_request(*self.unpack_request_values(request))

    def robots(self) -> Tuple[str, int]:
        self.handle_request(*self.unpack_request_values(request))
        return "User-agent: *\nDisallow: /", 200

    def admin_index(self) -> Tuple[str, int]:
        if not self._database_handler.host_is_authorized(request.remote_addr):
            return "Unauthorized", 403

        return render_template("home.html"), 200

    def view_hosts(self) -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
        if not self._database_handler.host_is_authorized(request.remote_addr):
            return "Unauthorized", 403

        hosts = self._database_handler.get_remote_hosts()
        return render_template("view_hosts.html", hosts=hosts), 200

    def view_requests(self) -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
        if not self._database_handler.host_is_authorized(request.remote_addr):
            return "Unauthorized", 403

        host = request.args.get("host")
        request_type = request.args.get("type")
        request_type = "all" if (request_type is None or not request_type) else request_type
        if host is None:
            return "Missing host parameter", 400
        requests = self._database_handler.get_requests(host)
        return render_template("view_requests.html", requests=requests, host=host), 200

    def add_authorized_host(self):
        if not self._database_handler.host_is_authorized(request.remote_addr):
            return "Unauthorized", 403

        host = request.args.get("host") or request.form.get("host")
        if host is None:
            return "Missing host parameter", 400
        self._database_handler.add_authorized_host(host)
        return "Host added", 200

    def handle_request(self, headers: Dict[str, str], method: str, remote_address: str, uri: str, query_string: str,
                       body: Dict[str, str]) -> Tuple[str, int] | Generator[str, Any, Tuple[str, int]]:
        acceptable = True if uri in ["/", "/favicon.ico", "/robots.txt"] else False
        if uri == "/" and remote_address in self._authorized_addresses:
            return redirect("/home"), 302

        self._database_handler.insert_request(acceptable, remote_address, method, dumps(headers), uri, query_string,
                                              dumps(body), self._port)
        if not acceptable and self._yield_forever:
            # yield forever to keep the connection open and hang a thread on the malicious bot
            while True:
                yield "No"

        # we do not want to yield forever for an acceptable request so simply return 403
        return "", 403

    def route(self, args, **kwargs):
        return self._flask_app.route(args, **kwargs)

    @staticmethod
    def favicon() -> Tuple[bytes, int]:
        with open("favicon.ico", "rb") as icon:
            return icon.read(), 200

    @staticmethod
    def unpack_request_values(req: request) -> Tuple[Dict[str, str], str, str, str, str, Dict[str, str]]:
        args = req.args.to_dict()
        query_string = "&".join([f"{k}={v}" for k, v in args.items()])
        return dict(req.headers), req.method, req.remote_addr, req.path, query_string, dict(req.data)

    @property
    def database_handler(self) -> DbHandler:
        return self._database_handler

    def run(self) -> None:
        self._flask_app.route("/robots.txt", methods=["GET"])(self.robots)
        self._flask_app.route("/view_hosts", methods=["GET"])(self.view_hosts)
        self._flask_app.route("/view_requests", methods=["GET"])(self.view_requests)
        self._flask_app.route("/add_authorized_host", methods=["GET"])(self.add_authorized_host)
        self._flask_app.route("/home", methods=["GET"])(self.admin_index)
        self._flask_app.route("/favicon.ico", methods=["GET"])(self.favicon)
        for i in [404, 403, 500]:
            self._flask_app.errorhandler(i)(self.error_handler)
        if self._run_with_ssl:
            self._flask_app.run(host="0.0.0.0", port=self._port, ssl_context=("cert.pem", "key.pem"))
        else:
            self._flask_app.run(host="0.0.0.0", port=self._port)


if __name__ == "__main__":
    try:
        app = Flask(__name__)
        listen_port = int(argv[3])
        Listener(
            flask_app=app,
            yield_forever=argv[1] == "yield",
            run_with_ssl=argv[2] == "ssl",
            authorized_hosts=["127.0.0.1"],
            port=listen_port,
        ).run()
    except IndexError:
        print("Usage: python3 honeypot.py [yield|noyield] [ssl|nossl] <port>")
        exit(1)

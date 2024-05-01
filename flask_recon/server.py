from typing import Tuple, Dict

from flask import Flask, request, Response

from flask_recon.database import DatabaseHandler
from flask_recon.structures import IncomingRequest, HALT_PAYLOAD, RequestType

KNOWN_PAYLOAD_FILES = [".env", ".config", "wp-config.php", "config.php", "settings.php", "config.inc.php",
                       "config.inc", "config.ini", "config.yml", "config.yaml", "config.json", "config.xml",
                       "config.toml", "config.hcl", "config.properties", "config.cfg", "config.conf", "config", "settings",
                       "settings.ini", "settings.yml", "settings.yaml", "settings.json", "settings.xml", "settings.toml",
                       "settings.hcl", "settings.properties", "settings.cfg", "settings.conf", "settings", "secrets",
                       "secrets.ini", "secrets.yml", "secrets.yaml", "secrets.json", "secrets.xml", "secrets.toml",
                       "secrets.hcl", "secrets.properties", "secrets.cfg", "secrets.conf", "secrets", "database",
                       "database.ini", "database.yml", "database.yaml", "database.json", "database.xml", "database.toml",
                       "database.hcl", "database.properties", "database.cfg", "database.conf", "database", "db", "db.ini",
                       "db.yml", "db.yaml", "db.json", "db.xml", "db.toml", "db.hcl", "db.properties", "db.cfg", "db.conf",
                       "db", "creds", "creds.ini", "creds.yml", "creds.yaml", "creds.json", "creds.xml", "creds.toml",
                       "creds.hcl", "creds.properties", "creds.cfg", "creds.conf", "creds", "passwords", "passwords.ini",
                       "passwords.yml", "passwords.yaml", "passwords.json", "passwords.xml", "passwords.toml",
                       "passwords.hcl", "passwords.properties", "passwords.cfg", "passwords.conf", "passwords", "keys",
                       "keys.ini", "keys.yml", "keys.yaml", "keys.json", "keys.xml", "keys.toml", "keys.hcl", "keys.properties",
                       "keys.cfg", "keys.conf", "keys", "key", "key.ini", "key.yml", "key.yaml", "key.json", "key.xml",
                       "key.toml", "key.hcl", "key.properties", "key.cfg", "key.conf", "key", "token", "token.ini", "token.yml",
                       "token.yaml", "token.json", "token.xml", "token.toml", "token.hcl", "token.properties", "token.cfg",
                       "token.conf", "token", "tokens", "tokens.ini", "tokens.yml", "tokens.yaml", "tokens.json", "tokens.xml",
                       "tokens.toml", "tokens.hcl", "tokens.properties", "tokens.cfg", "tokens.conf", "tokens", "auth"]


class Listener:
    _database_handler: DatabaseHandler
    _flask: Flask
    _port: int
    _halt_scanner_threads: bool
    _max_halt_messages: int

    def __init__(self, flask: Flask, halt_scanner_threads: bool = True, max_halt_messages: int = 100_000,
                 port: int = 80):
        self._port = port
        self._halt_scanner_threads = halt_scanner_threads
        self._max_halt_messages = max_halt_messages
        self._flask = flask
        self.add_routes()

    def route(self, *args, **kwargs):
        return self._flask.route(*args, **kwargs)

    def run(self, *args, **kwargs):
        self._flask.run(*args, **kwargs)

    def connect_database(self, dbname: str, user: str, password: str, host: str, port: str):
        self._database_handler = DatabaseHandler(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )

    def error_handler(self, _):
        return self.handle_request(*self.unpack_request_values(request))

    def handle_request(self, headers: Dict[str, str], method: str, remote_address: str, uri: str, query_string: str,
                       body: Dict[str, str]):
        req = IncomingRequest(self._port).from_components(
            host=remote_address,
            request_method=RequestType.from_str(method),
            request_headers=headers,
            request_uri=uri,
            query_string=query_string,
            request_body=body,
            timestamp="",
            threat_level=self.determine_threat_level(RequestType.from_str(method), uri, query_string, body)
        )
        self._database_handler.add_request(req)
        if req.is_acceptable:
            return "404 Not Found", 404

        file = self.grab_payload_file(req.uri)
        if (honeypot_response := self._database_handler.get_honeypot(file)) is not None:
            response = Response("", status=200, headers=self.text_response_headers(len(honeypot_response)))
            yield honeypot_response
            return response

        if self._halt_scanner_threads:
            for _ in range(self._max_halt_messages):
                yield (HALT_PAYLOAD * 1024) * 1024
            return "", 200

        return "404 Not Found", 404

    @staticmethod
    def determine_threat_level(method: RequestType, uri: str, query_string: str, body: Dict[str, str]) -> int:
        method_score, uri_score, query_score, body_score = 0, 0, 0, 0
        if method in [RequestType.POST, RequestType.PUT]:
            method_score = 10
        elif method in [RequestType.DELETE, RequestType.PATCH, RequestType.PRI]:
            method_score = 5
        elif method == RequestType.GET:
            method_score = 1
        else:
            method_score = 2

        if uri in ["/", "/robots.txt"]:
            uri_score = 1
        elif any(map(uri.__contains__, KNOWN_PAYLOAD_FILES)):
            uri_score = 10
        else:
            uri_score = 5

        if query_string:
            query_score = 10

        if body:
            body_score = 10

        return int(round((method_score + uri_score + query_score + body_score) / 10, 0))

    @staticmethod
    def unpack_request_values(req: request) -> Tuple[Dict[str, str], str, str, str, str, Dict[str, str]]:
        args = req.args.to_dict()
        query_string = "&".join([f"{k}={v}" for k, v in args.items()])
        if 'Content-Type' in req.headers and req.headers['Content-Type'] == 'application/json':
            body = dict(req.json)
        else:
            body = {}
        return dict(req.headers), req.method, req.remote_addr, req.path, query_string, body

    @staticmethod
    def grab_payload_file(path: str) -> str:
        return path.split("/")[-1]

    @staticmethod
    def text_response_headers(length: int) -> dict:
        return {
            "Content-Type": "text/plain",
            "Access-Control-Allow-Origin": "*",
            "Content-Length": str(length)
        }

    @staticmethod
    def sitemap() -> Tuple[str, int]:
        return "<?xml version='1.0' encoding='UTF-8'?>", 200

    @staticmethod
    def robots() -> Tuple[str, int]:
        return "User-agent: *\nDisallow: /", 200

    def add_routes(self):
        for i in [400, 404, 403]:
            self._flask.errorhandler(i)(self.error_handler)
        self._flask.route("/robots.txt", methods=["GET"])(self.robots)
        self._flask.route("/sitemap.xml", methods=["GET"])(self.sitemap)

    @property
    def database_handler(self) -> DatabaseHandler:
        return self._database_handler

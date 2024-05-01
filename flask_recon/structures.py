from enum import Enum
from typing import Dict, Optional, Self

import werkzeug.exceptions
from flask import Request

HALT_PAYLOAD = "STOP SCANNING"
KNOWN_PAYLOAD_FILES = ["wp-login.php", "xmlrpc.php", "wp-admin", "wp-content", "wp-includes", "wp-config.php",
                       ".env", "config.py", ".config", "config.json", "config.php", "config.xml", "config.yml",
                       "config.yaml", "config.toml", "config.ini", "config.cfg", "config.txt", "config.conf", "config",
                       "settings.py", "settings.json", "settings.xml", "settings.yml", "settings.yaml", "settings.toml",
                       "settings.ini", "settings.cfg", "settings.txt", "settings.conf", "settings", "database.php",
                       "database.json", "database.xml", "database.yml", "database.yaml", "database.toml",
                       "database.ini", "database.cfg", "database.txt", "database.conf", "database", "db.php", "db.json"]
MALICIOUS_UA_FLAGS = ["sqlmap", "sqlninja", "havij", "nikto", "w3af", "acunetix", "netsparker", "nmap", "nessus",
                      "masscan", "zgrab", "zmap"]


class RequestType(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    TRACE = "TRACE"
    CONNECT = "CONNECT"
    PRI = "PRI"
    OTHER = "OTHER"

    @staticmethod
    def from_str(method: str) -> "RequestType":
        if method == "GET":
            return RequestType.GET
        if method == "POST":
            return RequestType.POST
        if method == "PUT":
            return RequestType.PUT
        if method == "DELETE":
            return RequestType.DELETE
        if method == "HEAD":
            return RequestType.HEAD
        if method == "OPTIONS":
            return RequestType.OPTIONS
        if method == "PATCH":
            return RequestType.PATCH
        if method == "TRACE":
            return RequestType.TRACE
        if method == "CONNECT":
            return RequestType.CONNECT
        if method == "PRI":
            return RequestType.PRI
        return RequestType.OTHER


class Services(Enum):
    HTTP = [80, 8080, 8000]
    FTP = [21]
    SSH = [22]
    SMTP = [25]
    DNS = [53]
    POP3 = [110]
    IMAP = [143]
    HTTPS = [443]
    SMTPS = [465]
    IMAPS = [993]
    POP3S = [995]
    MYSQL = [3306]
    POSTGRES = [5432]
    RDP = [3389]
    VNC = [5900]
    SNMP = [161]
    SNMP_TRAP = [162]
    LDAP = [389]
    LDAPS = [636]
    MSSQL = [1433]
    ORACLE = [1521]
    MONGODB = [27017]
    REDIS = [6379]
    ELASTICSEARCH = [9200]
    KIBANA = [5601]
    RABBITMQ = [5672]
    MEMCACHED = [11211]


class RemoteHost:
    _address: str
    _open_ports: Dict[int, bool]

    def __init__(self, address: str):
        self._address = address
        self._open_ports = {}

    @property
    def address(self) -> str:
        return self._address

    @property
    def open_ports(self) -> Dict[int, bool]:
        return self._open_ports

    def add_open_port(self, port: int) -> None:
        self._open_ports[port] = True


class IncomingRequest:
    _host: RemoteHost
    _local_port: int
    _request_method: RequestType
    _request_headers: Optional[Dict[str, str]]
    _request_uri: str
    _query_string: Optional[str]
    _request_body: Optional[Dict[str, str]]
    _is_acceptable: bool
    _headers: dict
    _timestamp: str
    _threat_level: Optional[int]
    _request_id: Optional[int]

    def __init__(self, local_port: int):
        self._local_port = local_port

    def from_request(self, request: Request) -> Self:
        self._host = RemoteHost(request.remote_addr)
        self._request_method = RequestType.from_str(request.method)
        self._request_headers = request.headers
        self._request_uri = request.url
        self._query_string = request.path
        try:
            self._request_body = request.json
        except werkzeug.exceptions.UnsupportedMediaType:
            self._request_body = None
        return self

    def from_components(self, host: str, request_method: RequestType, request_headers: Optional[Dict[str, str]],
                        request_uri: str, query_string: Optional[str], request_body: Optional[Dict[str, str]],
                        timestamp: str, threat_level: Optional[int] = None, request_id: Optional[int] = None) -> Self:
        self._host = RemoteHost(host)
        self._request_method = request_method
        self._request_headers = request_headers
        self._request_uri = request_uri
        self._query_string = query_string
        self._request_body = request_body
        self._timestamp = timestamp
        self._threat_level = threat_level
        self._request_id = request_id
        return self

    def determine_threat_level(self):
        method_score, uri_score, query_score, body_score, ua_score = 5, 5, 5, 5, 5

        if self._request_headers:
            if "user-agent" in [k.lower() for k in self._request_headers.keys()]:
                ua = self._request_headers.get("user-agent") or self._request_headers.get("User-Agent")
                if any(map(ua.__contains__, MALICIOUS_UA_FLAGS)):
                    self._threat_level = 10
                    return
            else:
                ua_score = 10

        if self._request_method in [RequestType.POST, RequestType.PUT]:
            method_score = 10
        elif self._request_method in [RequestType.DELETE, RequestType.PATCH, RequestType.PRI]:
            method_score = 8
        else:
            method_score = 6

        if self._request_uri in ["/", "/robots.txt"]:
            self._threat_level = 1
            return
        elif any(map(self._request_uri.__contains__, KNOWN_PAYLOAD_FILES)):
            self._threat_level = 10
            return
        else:
            uri_score = 7

        if self._query_string:
            query_score = 10
        if self._request_body:
            body_score = 10

        self._threat_level = int(round((method_score + uri_score + query_score + body_score + ua_score) / 5, 0))

    @property
    def host(self) -> RemoteHost:
        return self._host

    @property
    def local_port(self) -> int:
        return self._local_port

    @property
    def method(self) -> RequestType:
        return self._request_method

    @property
    def headers(self) -> Optional[Dict[str, str]]:
        return self._request_headers

    @property
    def uri(self) -> str:
        return self._request_uri

    @property
    def query_string(self) -> Optional[str]:
        return self._query_string

    @property
    def body(self) -> Optional[Dict[str, str]]:
        return self._request_body

    @property
    def is_acceptable(self) -> bool:
        return self.method == "GET" and self.uri in ["/", "/robots.txt"]

    @property
    def timestamp(self) -> str:
        return self._timestamp

    @property
    def threat_level(self) -> Optional[int]:
        return self._threat_level

    @property
    def request_id(self) -> Optional[int]:
        return self._request_id

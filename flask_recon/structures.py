from enum import Enum
from typing import Dict, Optional, Self

import werkzeug.exceptions
from flask import Request
from datetime import datetime

HALT_PAYLOAD = "STOP SCANNING"


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

    def __init__(self, local_port: int):
        self._local_port = local_port
        self._timestamp = datetime.now().isoformat()

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
                        request_uri: str, query_string: Optional[str], request_body: Optional[Dict[str, str]]) -> Self:
        self._host = RemoteHost(host)
        self._request_method = request_method
        self._request_headers = request_headers
        self._request_uri = request_uri
        self._query_string = query_string
        self._request_body = request_body
        return self

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


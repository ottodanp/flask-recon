from enum import Enum
from typing import Dict, Optional, Self, List, Tuple

import werkzeug.exceptions
from flask import Request

from flask_recon.flags import KNOWN_FLAGS, Flag, RequestType, AttackType

HALT_PAYLOAD = "STOP SCANNING"


class RequestMethod(Enum):
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
    def from_str(method: str) -> "RequestMethod":
        if method == "GET":
            return RequestMethod.GET
        if method == "POST":
            return RequestMethod.POST
        if method == "PUT":
            return RequestMethod.PUT
        if method == "DELETE":
            return RequestMethod.DELETE
        if method == "HEAD":
            return RequestMethod.HEAD
        if method == "OPTIONS":
            return RequestMethod.OPTIONS
        if method == "PATCH":
            return RequestMethod.PATCH
        if method == "TRACE":
            return RequestMethod.TRACE
        if method == "CONNECT":
            return RequestMethod.CONNECT
        if method == "PRI":
            return RequestMethod.PRI
        return RequestMethod.OTHER


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
    _request_method: RequestMethod
    _request_headers: Optional[Dict[str, str]]
    _request_uri: str
    _query_string: Optional[str]
    _request_body: Optional[Dict[str, str]]
    _is_acceptable: bool
    _headers: dict
    _timestamp: str
    _threat_level: Optional[int]
    _request_id: Optional[int]
    _request_types: Optional[List[RequestType]] = None
    _attack_types: Optional[List[AttackType]] = None

    def __init__(self, local_port: int):
        self._local_port = local_port

    def from_request(self, request: Request) -> Self:
        self._host = RemoteHost(request.remote_addr)
        self._request_method = RequestMethod.from_str(request.method)
        self._request_headers = request.headers
        self._request_uri = request.url
        self._query_string = request.path
        try:
            self._request_body = request.json
        except werkzeug.exceptions.UnsupportedMediaType:
            self._request_body = None
        return self

    def from_components(self, host: str, request_method: RequestMethod, request_headers: Optional[Dict[str, str]],
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
        method_score, uri_score, query_score, body_score, ua_score = 5, 4, 5, 0, 5
        total_request_types, total_attack_types = [], []

        if self._request_headers and "user-agent" in [k.lower() for k in self._request_headers.keys()]:
            ua = self._request_headers.get("user-agent") or self._request_headers.get("User-Agent")
            ua_score, request_types, attack_types = self.calc_avg_tl_str(ua, KNOWN_FLAGS.known_ua_flags)
            total_request_types.extend(request_types)
            total_attack_types.extend(attack_types)

        if self._request_method in [RequestMethod.POST, RequestMethod.PUT]:
            method_score = 10
        elif self._request_method in [RequestMethod.DELETE, RequestMethod.PATCH, RequestMethod.PRI]:
            method_score = 8
        else:
            method_score = 6

        if self._request_uri == "/":
            uri_score = 0
        elif any(map(self._request_uri.__contains__, [flag.flag for flag in KNOWN_FLAGS.known_payload_flags])):
            uri_score, request_types, attack_types = self.calc_avg_tl_str(self._request_uri,
                                                                          KNOWN_FLAGS.known_payload_flags)
            total_request_types.extend(request_types)
            total_attack_types.extend(attack_types)
        else:
            uri_score = 6

        if self._query_string:
            query_score, request_types, attack_types = self.calc_avg_tl_str(self._query_string,
                                                                            KNOWN_FLAGS.known_payload_flags)
            total_request_types.extend(request_types)
            total_attack_types.extend(attack_types)
        if self._request_body:
            body_score = 10

        deduped_request_types = []
        deduped_attack_types = []
        for rtype in total_request_types:
            if rtype not in deduped_request_types:
                deduped_request_types.append(rtype)
        for atype in total_attack_types:
            if atype not in deduped_attack_types:
                deduped_attack_types.append(atype)

        if len(deduped_request_types) == 0:
            deduped_request_types.append(RequestType.OTHER)
        self._request_types = sorted(deduped_request_types, key=lambda x: total_request_types.count(x), reverse=True)
        self._attack_types = sorted(deduped_attack_types, key=lambda x: total_attack_types.count(x), reverse=True)
        self._threat_level = int(round((method_score + uri_score + query_score + body_score + ua_score) / 5, 0))

    @staticmethod
    def calc_avg_tl_str(value: str, flags: List[Flag]) -> Tuple[float, List[RequestType], List[AttackType]]:
        threat_level, flag_count = 0, 0
        request_types, attack_types = [], []
        for flag in flags:
            if flag.flag not in value:
                continue

            threat_level += flag.score
            flag_count += 1
            request_types.extend(flag.request_types)
            if flag.attack_types:
                attack_types.extend(flag.attack_types)

        return (threat_level / flag_count if flag_count > 0 else 0.0), request_types, attack_types

    @property
    def csv_headers(self) -> str:
        return "origin_host,method,uri,query_string,headers,body,timestamp"

    @property
    def as_csv(self) -> str:
        qs_sep = "?" if self.query_string else ""
        return (f"{self.host.address},{self.method},{self.uri}{qs_sep}{self.query_string},{self.headers},{self.body},"
                f"{self.timestamp}")

    @property
    def host(self) -> RemoteHost:
        return self._host

    @property
    def local_port(self) -> int:
        return self._local_port

    @property
    def method(self) -> RequestMethod:
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

    @property
    def request_types(self) -> Optional[List[RequestType]]:
        return self._request_types

    @property
    def attack_types(self) -> Optional[List[AttackType]]:
        return self._attack_types

from enum import Enum
from json import loads
from typing import List, Any, Dict, Optional


class AttackType(Enum):
    RCE = "RCE"
    SQLI = "SQLI"
    XSS = "XSS"
    LFI = "LFI"
    RFI = "RFI"
    WEBAPP_VULN = "WEBAPP_VULN"
    MULTIPLE = "MULTIPLE"
    OTHER = "OTHER"
    NONE = "NONE"

    @staticmethod
    def from_str(attack_type: str) -> "AttackType":
        if attack_type is None:
            return AttackType.NONE
        if attack_type == "RCE":
            return AttackType.RCE
        if attack_type == "SQLI":
            return AttackType.SQLI
        if attack_type == "XSS":
            return AttackType.XSS
        if attack_type == "LFI":
            return AttackType.LFI
        if attack_type == "RFI":
            return AttackType.RFI
        if attack_type == "WEBAPP_VULN":
            return AttackType.WEBAPP_VULN
        if attack_type == "MULTIPLE":
            return AttackType.MULTIPLE
        return AttackType.OTHER


class RequestType(Enum):
    SCAN = "SCAN"
    RECON = "RECON"
    ATTACK = "ATTACK"
    GRAB = "GRAB"
    OTHER = "OTHER"

    @staticmethod
    def from_str(request_type: str) -> "RequestType":
        if request_type == "SCAN":
            return RequestType.SCAN
        if request_type == "RECON":
            return RequestType.RECON
        if request_type == "ATTACK":
            return RequestType.ATTACK
        if request_type == "GRAB":
            return RequestType.GRAB
        return RequestType.OTHER


class Flag:
    _request_types: List[RequestType]
    _attack_types: Optional[List[AttackType]]
    _flag: str
    _score: int

    def __init__(self, request_types: List[RequestType], flag_string: str, score: int,
                 attack_types: Optional[List[AttackType]] = None):
        self._request_types = request_types
        self._attack_types = attack_types
        self._flag = flag_string
        self._score = score

    def __eq__(self, val: str):
        return self._flag == val

    def __hash__(self):
        return hash(self._flag)

    @property
    def flag(self) -> str:
        return self._flag

    @property
    def score(self) -> int:
        return self._score

    @property
    def request_types(self) -> List[RequestType]:
        return self._request_types

    @property
    def attack_types(self) -> Optional[List[AttackType]]:
        return self._attack_types


class KnownFlags:
    _flags_file: str
    _payload_flags: List[Flag] = []
    _ua_flags: List[Flag] = []

    def __init__(self, flags_file: str):
        self._flags_file = flags_file
        self.load_flags()

    def load_flags(self):
        flag_data = loads(open(self._flags_file).read())
        self.add_flags(flag_data["payload"], self._payload_flags)
        self.add_flags(flag_data["user_agent"], self._ua_flags)

    @staticmethod
    def add_flags(flags: List[Dict[str, Any]], target: List[Flag]) -> None:
        for flag in flags:
            request_types = [RequestType.from_str(rt) for rt in flag["request_types"]]
            attack_types = [AttackType.from_str(at) for at in flag["attack_types"]] if "attack_types" in flag else None
            target.append(Flag(request_types=request_types, flag_string=flag["flag"], score=flag["score"],
                               attack_types=attack_types))

    @property
    def known_payload_flags(self) -> List[Flag]:
        return self._payload_flags

    @property
    def known_ua_flags(self) -> List[Flag]:
        return self._ua_flags


KNOWN_FLAGS = KnownFlags("static/flags.json")

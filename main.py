from json import dumps
from typing import Tuple, List, Optional

from database import DbHandler
from webapp import Listener


class PassivePot:
    _listener: Listener
    _database_handler: DbHandler
    _yield_forever: bool
    _authorized_addresses: List[str]

    def __init__(self, yield_forever: bool = False, authorized_addresses: Optional[List[str]] = None):
        self._authorized_addresses = ["127.0.0.1"] if authorized_addresses is None else authorized_addresses
        self._listener = Listener(self.request_callback)
        self._database_handler = DbHandler("requests", "postgres", "postgres", "localhost", "5432")
        self._yield_forever = yield_forever

    def request_callback(self, headers: dict, method: str, remote_address: str, uri: str, query_string: str, body: dict,
                         acceptable: bool, ) -> Tuple[str, int]:
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

    def run(self):
        self._listener.run()


if __name__ == "__main__":
    PassivePot(True).run()

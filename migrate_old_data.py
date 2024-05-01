from json import loads
from typing import List

from psycopg2 import connect

from flask_recon.database import DatabaseHandler
from flask_recon.structures import IncomingRequest, RequestType


class OldRequest:
    _request_id: int
    _request_method: str
    _request_uri: str
    _query_string: str
    _request_headers: str
    _request_body: str
    _acceptable: bool
    _remote_host_id: int
    _port: int
    _created_at: str

    def __init__(self, request_id: int, request_method: str, request_uri: str, query_string: str, request_headers: str,
                 request_body: str, acceptable: bool, remote_host_id: int, port: int, created_at: str):
        self._request_id = request_id
        self._request_method = request_method
        self._request_uri = request_uri
        self._query_string = query_string
        self._request_headers = request_headers
        self._request_body = request_body
        self._acceptable = acceptable
        self._remote_host_id = remote_host_id
        self._port = port
        self._created_at = created_at

    def to_incoming_request(self, host: str) -> IncomingRequest:
        return IncomingRequest(self._port).from_components(
            request_method=RequestType[self._request_method],
            request_uri=self._request_uri,
            query_string=self._query_string,
            request_headers=dict(loads(self._request_headers)),
            request_body=dict(loads(self._request_body)),
            host=host
        )


def get_all_requests(dbname: str, user: str, password: str, host: str, port: str) -> List[IncomingRequest]:
    """
    request_id | method | uri | query_string | headers | body | acceptable | remote_host_id | port | created_at
    :return:
    """
    connection = connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM requests")
    rows = cursor.fetchall()
    for row in rows:
        remote_host_id = row[7]
        cursor.execute("SELECT remote_host FROM remote_hosts WHERE remote_host_id = %s", (remote_host_id,))
        host = cursor.fetchone()[0]
        yield OldRequest(*row).to_incoming_request(host)


def migrate_old_data():
    new_db = DatabaseHandler(
        dbname="flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    requests = get_all_requests(
        dbname="requests",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    for request in requests:
        new_db.add_request(request)


if __name__ == '__main__':
    migrate_old_data()

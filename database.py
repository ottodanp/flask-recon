from psycopg2 import connect
from psycopg2.extensions import cursor, connection


class DbHandler(cursor):
    _conn: connection

    def __init__(self, dbname: str, user: str, password: str, host: str, port: str):
        self._conn = connect(dbname=dbname, user=user, password=password, host=host, port=port)

        super().__init__(self._conn)

    def __del__(self):
        self._conn.close()
        super().close()

    def insert_request(self, acceptable: bool, remote_address: str, method: str, headers: str, uri: str,
                       query_string: str, body: str):
        if not self.remote_address_exists(remote_address):
            self.insert_remote_address(remote_address)

        remote_address_id = self.get_remote_address_id(remote_address)
        # using a parameterized query automatically escapes the input and prevents SQL injection
        self.execute(
            "INSERT INTO requests (remote_address_id, request_method, request_headers, request_uri, query_string, request_body, acceptable) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (remote_address_id, method, headers, uri, query_string, body, acceptable))
        self._conn.commit()

    def remote_address_exists(self, remote_address: str) -> bool:
        self.execute("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE remote_address = %s)", (remote_address,))
        return self.fetchone()[0]

    def insert_remote_address(self, remote_address: str):
        self.execute("INSERT INTO remote_hosts (remote_address) VALUES (%s)", (remote_address,))
        self._conn.commit()

    def get_remote_address_id(self, remote_address: str) -> int:
        self.execute("SELECT remote_host_id FROM remote_hosts WHERE remote_address = %s", (remote_address,))
        return self.fetchone()[0]

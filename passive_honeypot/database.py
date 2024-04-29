from json import loads
from typing import List, Tuple, Any, Dict

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

    def insert_request(self, acceptable: bool, remote_host: str, method: str, headers: str, uri: str,
                       query_string: str, body: str, port: int):
        if not self.remote_host_exists(remote_host):
            self.insert_remote_host(remote_host)

        remote_host_id = self.get_remote_host_id(remote_host)
        self.execute("SELECT NOW()")
        timestamp = self.fetchone()[0]
        # using a parameterized query automatically escapes the input and prevents SQL injection
        self.execute(
            "INSERT INTO requests (remote_host_id, request_method, request_headers, request_uri, query_string, request_body, acceptable, created_at, port) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (remote_host_id, method, headers, uri, query_string, body, acceptable, timestamp, port))
        self._conn.commit()

    def remote_host_exists(self, remote_host: str) -> bool:
        self.execute("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE remote_host = %s)", (remote_host,))
        return self.fetchone()[0]

    def insert_remote_host(self, remote_host: str):
        self.execute("INSERT INTO remote_hosts (remote_host) VALUES (%s)", (remote_host,))
        self._conn.commit()

    def get_remote_host_id(self, remote_host: str) -> int:
        self.execute("SELECT remote_host_id FROM remote_hosts WHERE remote_host = %s", (remote_host,))
        return self.fetchone()[0]

    def count_requests(self, host: str) -> Tuple[int, int]:
        self.execute(
            "SELECT COUNT(*) FROM requests WHERE remote_host_id = (SELECT remote_host_id FROM remote_hosts WHERE remote_host = %s AND acceptable = TRUE)",
            (host,))
        valid = self.fetchone()[0]
        self.execute(
            "SELECT COUNT(*) FROM requests WHERE remote_host_id = (SELECT remote_host_id FROM remote_hosts WHERE remote_host = %s AND acceptable = FALSE)",
            (host,))
        invalid = self.fetchone()[0]
        return valid, invalid

    def get_remote_hosts(self) -> List[Dict[str, Any]]:
        # return all hosts except for authorized hosts
        self.execute("SELECT remote_host FROM remote_hosts")
        hosts = self.fetchall()
        r = []
        for row in hosts:
            host = row[0]
            if self.host_is_authorized(host):
                continue
            valid, invalid = self.count_requests(host)
            r.append({
                "host": host,
                "valid_requests": valid,
                "invalid_requests": invalid,
                "total_requests": valid + invalid
            })

        return sorted(r, key=lambda x: x["total_requests"], reverse=True)

    def get_requests(self, host: str):
        self.execute(
            "SELECT request_method, request_headers, request_uri, query_string, request_body, acceptable, created_at, port FROM requests WHERE remote_host_id = (SELECT remote_host_id FROM remote_hosts WHERE remote_host = %s)",
            (host,))
        rows = self.fetchall()
        r = []
        for row in rows:
            try:
                method, headers, uri, query_string, body, acceptable, timestamp, port = row
            except ValueError:
                continue
            r.append({
                "method": method,
                "headers": loads(headers) if headers else {},
                "uri": uri,
                "query_string": query_string,
                "body": loads(body) if body else {},
                "acceptable": acceptable,
                "timestamp": timestamp,
                "port": port,
                "host": host
            })

        return sorted(r, key=lambda x: x["timestamp"], reverse=True)

    def host_is_authorized(self, host: str) -> bool:
        self.execute(
            "SELECT EXISTS(SELECT remote_host_id FROM authorized_hosts WHERE remote_host_id = (SELECT remote_host_id FROM remote_hosts WHERE remote_host = %s))",
            (host,))
        return self.fetchone()[0]

    def add_authorized_host(self, host: str):
        if not self.remote_host_exists(host):
            self.insert_remote_host(host)
            self._conn.commit()

        host_id = self.get_remote_host_id(host)
        self.execute("INSERT INTO authorized_hosts (remote_host_id) VALUES (%s)", (host_id,))
        self._conn.commit()

    def count_endpoint(self, endpoint: str) -> int:
        self.execute("SELECT COUNT(*) FROM requests WHERE request_uri = %s", (endpoint,))
        return self.fetchone()[0]

    def count_requests_to_endpoint(self, endpoint: str, host: str) -> int:
        self.execute(
            "SELECT COUNT(*) FROM requests WHERE request_uri = %s AND remote_host_id = (SELECT remote_host_id FROM remote_hosts WHERE remote_host = %s)",
            (endpoint, host))
        return self.fetchone()[0]

    def get_all_endpoints(self) -> List[Tuple[str, int]]:
        self.execute("SELECT request_uri from requests GROUP BY request_uri")
        f = set()
        r = []
        for row in self.fetchall():
            endpoint = row[0]
            if endpoint in f:
                continue
            f.add(endpoint)
            r.append((endpoint, self.count_endpoint(endpoint)))

        return sorted(r, key=lambda x: x[1], reverse=True)

    def get_hosts_by_endpoint(self, endpoint: str) -> List[Tuple[str, int]]:
        self.execute(
            "SELECT remote_host FROM remote_hosts WHERE remote_host_id IN (SELECT remote_host_id FROM requests WHERE request_uri = %s)",
            (endpoint,))
        r = []
        for row in self.fetchall():
            host = row[0]
            r.append((host, self.count_requests_to_endpoint(endpoint, host)))

        return sorted(r, key=lambda x: x[1], reverse=True)

    def get_requests_by_endpoint(self, endpoint: str) -> List[Dict[str, Any]]:
        self.execute(
            "SELECT request_method, request_headers, query_string, request_body, acceptable, request_uri, created_at, port, remote_host_id FROM requests WHERE request_uri = %s",
            (endpoint,))
        rows = self.fetchall()
        r = []
        for row in rows:
            try:
                method, headers, query_string, body, acceptable, request_uri, timestamp, port, host_id = row
                self.execute("SELECT remote_host FROM remote_hosts WHERE remote_host_id = %s", (host_id,))
                host = self.fetchone()[0]
            except ValueError:
                continue
            r.append({
                "method": method,
                "headers": loads(headers) if headers else {},
                "query_string": query_string,
                "body": loads(body) if body else {},
                "acceptable": acceptable,
                "timestamp": timestamp,
                "uri": request_uri,
                "port": port,
                "host": host
            })

        return sorted(r, key=lambda x: x["timestamp"], reverse=True)

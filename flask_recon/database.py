from json import dumps, loads
from typing import Optional, List, Tuple, Dict, Any

from psycopg2 import connect
from psycopg2.extensions import cursor, connection

from flask_recon.structures import IncomingRequest, RemoteHost


class DatabaseHandler(cursor):
    _conn: connection

    def __init__(self, dbname: str, user: str, password: str, host: str, port: str):
        self._conn = connect(dbname=dbname, user=user, password=password, host=host, port=port)
        super().__init__(self._conn)

    def __del__(self):
        self._conn.close()
        super().close()

    def actor_exists(self, remote_host: RemoteHost) -> bool:
        self.execute("SELECT EXISTS(SELECT actor_id FROM actors WHERE host = %s)", (remote_host.address,))
        return self.fetchone()[0]

    def insert_actor(self, remote_host: RemoteHost, flagged: bool = False) -> None:
        self.execute("INSERT INTO actors (host, flagged) VALUES (%s, %s)", (remote_host.address, flagged,))
        self._conn.commit()

    def get_actor_id(self, remote_host: RemoteHost) -> int:
        self.execute("SELECT actor_id FROM actors WHERE host = %s", (remote_host.address,))
        return self.fetchone()[0]

    def actor_is_flagged(self, remote_host: RemoteHost) -> bool:
        self.execute("SELECT flagged FROM actors WHERE host = %s", (remote_host.address,))
        return self.fetchone()[0]

    def add_request(self, request: IncomingRequest):
        if not self.actor_exists(request.host):
            self.insert_actor(request.host)

        actor_id = self.get_actor_id(request.host)
        self.execute("SELECT NOW()")
        timestamp = self.fetchone()[0]
        # using a parameterized query automatically escapes the input and prevents SQL injection
        self.execute(
            "INSERT INTO requests (actor_id, timestamp, method, path, body, headers, query_string, port, acceptable) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (actor_id, timestamp, request.request_method.value, request.request_uri, dumps(request.request_body),
             dumps(request.request_headers), request.query_string, request.local_port, request.is_acceptable))
        self._conn.commit()

    def get_honeypot(self, file: str) -> Optional[str]:
        self.execute("SELECT dummy_contents FROM honeypots WHERE file_name = %s", (file,))
        return self.fetchone()[0] if self.rowcount > 0 else None

    def add_honeypot(self, file: str, contents: str) -> None:
        self.execute("INSERT INTO honeypots (file_name, dummy_contents) VALUES (%s, %s)", (file, contents))
        self._conn.commit()

    def count_endpoint(self, endpoint: str) -> int:
        self.execute("SELECT COUNT(*) FROM requests WHERE path = %s", (endpoint,))
        return self.fetchone()[0]

    def count_requests(self, host: RemoteHost) -> Tuple[int, int]:
        self.execute("SELECT COUNT(*) FROM requests WHERE actor_id = %s AND acceptable = TRUE",
                     (self.get_actor_id(host),))
        valid = self.fetchone()[0]
        self.execute("SELECT COUNT(*) FROM requests WHERE actor_id = %s AND acceptable = FALSE",
                     (self.get_actor_id(host),))
        invalid = self.fetchone()[0]
        return valid, invalid

    def get_all_endpoints(self) -> List[Tuple[str, int]]:
        self.execute("SELECT path FROM requests")
        r = []
        e = set()
        for row in self.fetchall():
            endpoint = row[0]
            if endpoint in e:
                continue
            e.add(endpoint)
            r.append((endpoint, self.count_endpoint(endpoint)))
        return r

    def get_hosts_by_endpoint(self, endpoint: str) -> List[str]:
        self.execute("SELECT host FROM requests WHERE path = %s", (endpoint,))
        return [row[0] for row in self.fetchall()]

    def get_requests_by_endpoint(self, endpoint: str) -> List[Dict[str, Any]]:
        self.execute(
            "SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path FROM requests WHERE path = %s",
            (endpoint,))
        requests = self.fetchall()
        r = []
        for row in requests:
            self.execute("SELECT host FROM actors WHERE actor_id = %s", (row[0],))
            host = self.fetchone()[0]
            r.append({
                "host": host,
                "timestamp": row[1],
                "request_method": row[2],
                "request_body": loads(row[3]),
                "headers": loads(row[4]),
                "query_string": row[5],
                "port": row[6],
                "is_acceptable": row[7],
                "request_uri": row[8]
            })
        return r

    def get_remote_hosts(self) -> List[Tuple[str, int, int, int]]:
        self.execute("SELECT host FROM actors")
        r = []
        for row in self.fetchall():
            host = RemoteHost(row[0])
            valid, invalid = self.count_requests(host)
            r.append((host.address, valid, invalid, valid + invalid))
        return r

    def get_requests(self, host: RemoteHost) -> List[IncomingRequest]:
        self.execute(
            "SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path FROM requests WHERE actor_id = %s",
            (self.get_actor_id(host),))
        r = []
        for row in self.fetchall():
            r.append(IncomingRequest(row[6]).from_components(
                host=row[0],
                request_method=row[2],
                request_headers=loads(row[4]),
                request_uri=row[8],
                query_string=row[5],
                request_body=loads(row[3])
            ))
        return r

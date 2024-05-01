from json import loads
from typing import List

from psycopg2 import connect

from flask_recon import DatabaseHandler, IncomingRequest, RequestType


def get_all_requests(dbname: str, user: str, password: str, host: str, port: str) -> List[IncomingRequest]:
    """
    request_id | actor_id | timestamp | method | path | body | headers | query_string | port | acceptable
    :param dbname:
    :param user:
    :param password:
    :param host:
    :param port:
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
    s = set()
    for row in rows:
        cursor.execute("SELECT host FROM actors WHERE actor_id = %s", (row[1],))
        host = cursor.fetchone()[0]
        f = f"{host}{row[3]}{row[4]}{row[6]}{row[7]}{row[5]}"
        if f in s:
            continue
        s.add(f)
        yield IncomingRequest(row[8]).from_components(
            host=host,
            request_method=RequestType[row[3]],
            request_headers=loads(row[6]),
            request_uri=row[4],
            query_string=row[7],
            request_body=loads(row[5]),
            timestamp=row[2]
        )


def migrate_new_data():
    requests = get_all_requests(dbname="flask_recon", user="postgres", password="postgres", host="localhost",
                                port="5432")

    new_db = DatabaseHandler(
        dbname="new_flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )

    for request in requests:
        new_db.add_request(request)


def update_threat_levels():
    new_db = DatabaseHandler(
        dbname="new_flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )

    requests = new_db.get_requests()
    for request in requests:
        request.determine_threat_level()
        new_db.update_request_threat_level(request_id=request.request_id, threat_level=request.threat_level)


if __name__ == '__main__':
    update_threat_levels()

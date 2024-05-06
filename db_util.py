from json import loads
from os import listdir
from typing import List

from psycopg2 import connect

from flask_recon import DatabaseHandler, IncomingRequest, RequestMethod


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
    for row in rows:
        cursor.execute("SELECT host FROM actors WHERE actor_id = %s", (row[1],))
        host = cursor.fetchone()[0]
        yield IncomingRequest(row[8]).from_components(
            host=host,
            request_method=RequestMethod[row[3]],
            request_headers=loads(row[6]),
            request_uri=row[4],
            query_string=row[7],
            request_body=loads(row[5]),
            timestamp=row[2]
        )


def migrate_new_data():
    requests = get_all_requests(dbname="temp_flask_recon", user="postgres", password="postgres", host="localhost",
                                port="5432")

    new_db = DatabaseHandler(
        dbname="new_flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )

    for request in requests:
        new_db.insert_request(request)


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


def add_honeypots():
    new_db = DatabaseHandler(
        dbname="new_flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )

    for file in listdir("static/honey_pot"):
        with open(f"static/honey_pot/{file}", "r") as f:
            new_db.insert_honeypot(file, f.read())


if __name__ == '__main__':
    migrate_new_data()

from flask import Flask

from flask_recon.server import Listener
from routes import add_routes

if __name__ == '__main__':
    listener = Listener(
        flask=Flask(__name__),
        halt_scanner_threads=True,
        max_halt_messages=100_000,
        port=80
    )
    listener.connect_database(
        dbname="flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    add_routes(listener)
    listener.run(host="0.0.0.0", port=80)

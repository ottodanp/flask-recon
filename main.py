from sys import argv

from flask import Flask

from flask_recon import Listener
from routes import add_routes

if __name__ == '__main__':
    listener = Listener(
        flask=Flask(__name__),
        halt_scanner_threads=False,
        max_halt_messages=100_000,
        port=80
    )
    listener.connect_database(
        dbname="new_flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    add_routes(listener)
    if len(argv) != 3:
        print("Usage: python main.py <port> [ssl|nossl]")
        exit(1)

    listener.run(host="0.0.0.0", port=int(argv[1]), ssl_context=("cert.pem", "key.pem",) if argv[2] == "ssl" else None)

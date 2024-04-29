from sys import argv

from flask import Flask

from flask_recon.server import Listener
from routes import add_routes

if __name__ == '__main__':
    if len(argv) != 4:
        print("Usage: python main.py <port> [api|noapi] [webapp|nowebapp]")
        exit(1)
    port, run_api, run_webapp = argv[1:]
    if run_webapp == "webapp":
        input("templates must be found in /templates. Press enter to continue.")

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
    add_routes(
        listener=listener,
        run_api=run_api == "api",
        run_webapp=run_webapp == "webapp"
    )
    listener.run(host="0.0.0.0", port=80)

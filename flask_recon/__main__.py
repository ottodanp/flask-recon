from sys import argv

from flask import Flask

from flask_recon import Listener
from routes import add_routes

if __name__ == '__main__':
    if len(argv) != 6:
        print("Usage: python main.py <port> [api|noapi] [webapp|nowebapp] [halt|nohalt] [ssl|nossl]")
        exit(1)
    port, run_api, run_webapp, halt, ssl = argv[1:]
    if run_webapp == "webapp":
        input("templates must be found in /templates. Press enter to continue.")

    try:
        port = int(port)
    except ValueError:
        print("Port must be an integer.")
        exit(1)

    listener = Listener(
        flask=Flask(__name__),
        halt_scanner_threads=halt == "halt",
        max_halt_messages=100_000,
        port=port
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
    if ssl == "ssl":
        listener.run(host="0.0.0.0", port=port, ssl_context=("cert.pem", "key.pem",))
    else:
        listener.run(host="0.0.0.0", port=port)

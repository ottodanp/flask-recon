from os.path import isdir
from sys import argv

from flask import Flask

from flask_recon import Listener, download_templates, add_routes

if __name__ == '__main__':
    if not 3 <= len(argv) <= 7:
        print("Usage: python main.py <port> <host> [Optional[api]] [Optional[webapp]] [Optional[halt]] [Optional[ssl]] "
              "[Optional[gen_admin_key]]")
        exit(1)
    port = argv[1]
    if "webapp" in argv and not isdir("templates"):
        input("templates must be found in /templates. Press enter to download templates.")
        download_templates()

    try:
        port = int(port)
    except ValueError:
        print("Port must be an integer.")
        exit(1)

    listener = Listener(
        flask=Flask(__name__),
        halt_scanner_threads="halt" in argv,
        max_halt_messages=100_000,
        port=port
    )
    listener.connect_database(
        dbname="new_flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    add_routes(
        listener=listener,
        run_api="api" in argv,
        run_webapp="webapp" in argv
    )
    if "gen_admin_key" in argv:
        print("Admin Registration Key: ", listener.database_handler.generate_admin_key())

    if "ssl" in argv:
        listener.run(host=argv[2], port=port, ssl_context=("cert.pem", "key.pem",))
    else:
        listener.run(host=argv[2], port=port)

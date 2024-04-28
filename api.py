from typing import Tuple, List, Dict, Any

from flask import Flask, request

from honeypot import Listener

app = Flask(__name__)
listener = Listener(app, True, False, ["127.0.0.1"], 80)


@app.route("/api/search_requests")
def search_requests() -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
    host = request.args.get("host")
    if not host:
        return "Invalid host", 400

    if not listener.database_handler.host_is_authorized(host):
        return "Unauthorized", 403

    return listener.database_handler.get_requests(host), 200


@app.route("/api/search_hosts")
def search_hosts() -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
    if not listener.database_handler.host_is_authorized(request.remote_addr):
        return "Unauthorized", 403

    return listener.database_handler.get_remote_hosts(), 200


if __name__ == '__main__':
    listener.run()

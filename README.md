# Python-Passive-Honeypot

### A simple passive honeypot written in Python with Flask and psycopg2.

### Aims:

- Provide a simple passive honeypot that can be used to detect and log malicious activity on a network.
- Gather information about the attacker and the attack.
- Gather currently active attack vectors used en-masse by attackers.
- Optionally provide a way to hang a thread of an attacker's scanner to slow down their scans. (If the attacker is not
  using any kind of concurrency, their whole scan will be halted.)
- Provide a simple way to view the logs and analyse the data.

## Run:

### Standalone:

```bash
sudo python3 honeypot.py [yield|noyield] [ssl|nossl] <port>
```

### As part of another Flask application:

#### Building an API around the honeypot:

```python
from typing import Tuple, List, Dict, Any

from flask import Flask, request

from honeypot import Listener

listener = Listener(
    flask_app=Flask(__name__),
    yield_forever=True,
    run_with_ssl=False,
    authorized_hosts=["127.0.0.1"],
    port=80
)


@listener.route("/api/search_requests")
def search_requests() -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
    host = request.args.get("host")
    if not host:
        return "Invalid host", 400

    if not listener.database_handler.host_is_authorized(host):
        return "Unauthorized", 403

    return listener.database_handler.get_requests(host), 200


@listener.route("/api/search_hosts")
def search_hosts() -> Tuple[List[Dict[str, Any]], int] | Tuple[str, int]:
    if not listener.database_handler.host_is_authorized(request.remote_addr):
        return "Unauthorized", 403

    return listener.database_handler.get_remote_hosts(), 200


if __name__ == '__main__':
    listener.run()

```

#### Easily adding the honeypot to an existing Flask application:

###### Before:

```python
from flask import Flask

app = Flask(__name__)


@app.route("/index")
def index() -> str:
    return "Hello, World!"


# Any other existing routes

if __name__ == '__main__':
    app.run()
```

###### After:

```python
from flask import Flask

from honeypot import Listener

app = Flask(__name__)
listener = Listener(flask_app=app, yield_forever=True, run_with_ssl=False, authorized_hosts=["127.0.0.1"], port=80)


@app.route("/index")
def index() -> str:
    return "Hello, World!"


# Any other existing routes

if __name__ == '__main__':
    # app.run()
    listener.run()
```

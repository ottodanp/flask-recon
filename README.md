# Python Flask Recon

### A simple passive recon webapp written in Python with Flask and psycopg2.

### Aims:

- Provide a simple passive reconnaissance package that can be used to detect and log malicious activity targeted to a
  Flask webapp.
- Gather information about the attacker and the attack.
- Gather currently active attack vectors used en-masse by bad actors.
- Optionally provide a way to persistantly occupy a thread of an attacker's scanner to slow down their scans.
  (The entire scan will be halted if the actor is not using any form of multithreading.)
- Return convincing dummy response bodies to maintain bot engagement and encourage further scanning, ideally ultimately
  leading to a full attack dump.
- Provide a simple way to view the logs and analyse the data.

## Setup:

### Install the required packages:

Linux:

```bash
sudo apt-get install python3-psycopg2 python3-flask
```

Windows:

```bash
pip install psycopg2 flask
```

## Deploy:

### Standalone:

Linux:

```bash
python3 -m flask_recon <port> <host> [api]? [webapp]? [halt]? [ssl]?
```

Windows:

```bash
python -m flask_recon <port> <host> [api]? [webapp]? [halt]? [ssl]?
```

- `<port>`: The port to listen on.
- `<host>`: The host to listen on.
- `[api]`: Optional. If specified, the API will be enabled.
- `[webapp]`: Optional. If specified, the webapp will be enabled.
- - if required, the html templates may be automatically downloaded
- `[halt]`: Optional. If specified, the scanner halting feature will be enabled.
- `[ssl]`: Optional. If specified, the webapp will be served over HTTPS.

Examples:
```bash
python3 -m flask_recon 80 0.0.0.0 api webapp halt
python3 -m flask_recon 443 0.0.0.0 ssl
python3 -m flask_recon 80 0.0.0.0 webapp
```

Please note that the specified port must be open and available for the webapp to listen on.

### As part of another Flask application:

#### Building an API around the extension:

```python
from flask import Flask, request

from flask_recon import Listener

app = Flask(__name__)
listener = Listener(flask=app, halt_scanner_threads=True, max_halt_messages=100_000, port=80)
listener.connect_database(
    dbname="flask_recon",
    user="postgres",
    password="postgres",
    host="localhost",
    port="5432"
)


@listener.route("/api/all_requests")
def search_requests():
    host = request.args.get("host")
    if not host:
        return "Invalid host", 400

    return listener.database_handler.get_requests(host), 200


@listener.route("/api/all_hosts")
def search_hosts():
    return listener.database_handler.get_remote_hosts(), 200


if __name__ == '__main__.py':
    listener.run()

```

#### Seamlessly integrating the extension into an existing Flask application:

###### Before:

```python
from flask import Flask

app = Flask(__name__)


@app.route("/index")
def index() -> str:
    return "Hello, World!"


# Any other existing routes

if __name__ == '__main__.py':
    app.run(host="0.0.0.0", port=80)
```

###### After:

```python
from flask import Flask

from flask_recon import Listener

app = Flask(__name__)


@app.route("/index")
def index() -> str:
    return "Hello, World!"


# Any other existing routes

if __name__ == '__main__.py':
    listener = Listener(flask=app, halt_scanner_threads=True, max_halt_messages=100_000, port=80)
    listener.connect_database(
        dbname="flask_recon",
        user="postgres",
        password="postgres",
        host="localhost",
        port="5432"
    )
    app.run(host="0.0.0.0", port=80)
```

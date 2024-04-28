# Python-Passive-Honeypot
### A simple passive honeypot written in Python with Flask and psycopg2.

## Aims:
- Provide a simple passive honeypot that can be used to detect and log malicious activity on a network.
- Gather information about the attacker and the attack.
- Gather currently active attack vectors used en-masse by attackers.
- Provide a simple way to view the logs and analyse the data.

## Run:
### Standalone:
```bash
sudo python3 honeypot.py [yield|noyield] [ssl|nossl] <port>
```

### As part of another Flask application:

```python
from flask import Flask

from honeypot import Listener

app = Flask(__name__)
listener = Listener(
    flask_app=app,
    yield_forever=False,
    run_with_ssl=False,
    authorized_hosts=["127.0.0.1"],
    port=80,
)


@app.route('/')
def index():
    return 'Hello, World!'


if __name__ == '__main__':
    listener.run()
```

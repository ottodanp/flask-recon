from json import dumps, loads
from os.path import isfile


class Config:
    _database_name: str
    _database_username: str
    _database_password: str
    _database_host: str
    _database_port: str

    def __init__(self):
        config_dict = self.load()
        database = config_dict["database"]
        self._database_name = database["name"]
        self._database_username = database["username"]
        self._database_password = database["password"]
        self._database_host = database["host"]
        self._database_port = database["port"]

    def load(self):
        if not isfile("config.json"):
            print("Config file not found, creating default config")
            config = self.default_config()
            with open("config.json", "w") as f:
                f.write(dumps(config, indent=4))

            return config

        with open("config.json", "r") as f:
            return loads(f.read())

    @staticmethod
    def default_config():
        return {
            "database": {
                "name": "honeypot",
                "username": "honeypot",
                "password": "honeypot",
                "host": "localhost",
                "port": "5432"
            }
        }

    @property
    def database_name(self) -> str:
        return self._database_name

    @property
    def database_username(self) -> str:
        return self._database_username

    @property
    def database_password(self) -> str:
        return self._database_password

    @property
    def database_host(self) -> str:
        return self._database_host

    @property
    def database_port(self) -> str:
        return self._database_port

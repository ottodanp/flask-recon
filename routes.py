from flask import Flask, request, render_template

from flask_recon.server import Listener
from flask_recon.structures import RemoteHost

app = Flask(__name__)


class ApiEndpoints:
    _listener: Listener

    def __init__(self, listener: Listener):
        self._listener = listener

    def all_endpoints(self):
        return self._listener.database_handler.get_all_endpoints()

    def all_hosts(self):
        return self._listener.database_handler.get_remote_hosts()

    def hosts_by_endpoint(self):
        endpoint = request.args.get("endpoint")
        return self._listener.database_handler.get_hosts_by_endpoint(endpoint)

    def requests_by_endpoint(self):
        endpoint = request.args.get("endpoint")
        return self._listener.database_handler.get_requests_by_endpoint(endpoint)

    def requests_by_host(self):
        host = request.args.get("host")
        return self._listener.database_handler.get_requests(RemoteHost(host))


class WebApp:
    _listener: Listener

    def __init__(self, listener: Listener):
        self._listener = listener

    def view_endpoints(self):
        return render_template("view_endpoints.html", endpoints=self._listener.database_handler.get_all_endpoints())

    def view_hosts(self):
        return render_template("view_hosts.html", hosts=self._listener.database_handler.get_remote_hosts())

    def html_hosts_by_endpoint(self):
        endpoint = request.args.get("endpoint")
        return render_template("hosts_by_endpoint.html",
                               hosts=self._listener.database_handler.get_hosts_by_endpoint(endpoint),
                               endpoint=endpoint)

    def html_requests_by_endpoint(self):
        endpoint = request.args.get("endpoint")
        return render_template("requests_by_endpoint.html",
                               requests=self._listener.database_handler.get_requests_by_endpoint(endpoint),
                               endpoint=endpoint)

    def html_requests_by_host(self):
        host = request.args.get("host")
        if host is None:
            return "Missing host parameter", 400

        endpoint = request.args.get("endpoint")
        remote_host = RemoteHost(host)

        if endpoint is not None:
            requests = self._listener.database_handler.get_requests_by_endpoint_and_host(endpoint, remote_host)
        else:
            requests = self._listener.database_handler.get_requests(remote_host)

        return render_template("requests_by_host.html", requests=requests, host=host)

    @staticmethod
    def home():
        return render_template("home.html")

    @staticmethod
    def favicon():
        return open("favicon.ico", "rb").read(), 200


def add_routes(listener: Listener, run_api: bool = True, run_webapp: bool = True):
    if run_api:
        api_endpoints = ApiEndpoints(listener)
        listener.route("/api/view_endpoints")(api_endpoints.all_endpoints)
        listener.route("/api/all_hosts")(api_endpoints.all_hosts)
        listener.route("/api/hosts_by_endpoint")(api_endpoints.hosts_by_endpoint)
        listener.route("/api/requests_by_endpoint")(api_endpoints.requests_by_endpoint)
        listener.route("/api/requests_by_host")(api_endpoints.requests_by_host)

    if run_webapp:
        webapp = WebApp(listener)
        listener.route("/view_endpoints")(webapp.view_endpoints)
        listener.route("/view_hosts")(webapp.view_hosts)
        listener.route("/hosts_by_endpoint")(webapp.html_hosts_by_endpoint)
        listener.route("/requests_by_endpoint")(webapp.html_requests_by_endpoint)
        listener.route("/requests_by_host")(webapp.html_requests_by_host)
        listener.route("/home")(webapp.home)
        listener.route("/favicon.ico")(webapp.favicon)

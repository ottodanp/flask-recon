from datetime import datetime
from typing import List

from flask import Flask, request, render_template, Response, redirect

from flask_recon import Listener, RemoteHost, IncomingRequest
from os import system
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
        return self._listener.database_handler.get_requests(endpoint)

    def requests_by_host(self):
        host = request.args.get("host")
        return self._listener.database_handler.get_requests(host=RemoteHost(host))


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
        requests = self._listener.database_handler.get_requests(endpoint=endpoint)
        self.update_tls(requests)
        return render_template("view_requests.html", requests=requests, endpoint=endpoint,
                               title=f"Requests to {endpoint}")

    def html_requests_by_host(self):
        host = request.args.get("host")
        if host is None:
            return "Missing host parameter", 400

        endpoint = request.args.get("endpoint")
        remote_host = RemoteHost(host)

        if endpoint is not None:
            requests = self._listener.database_handler.get_requests(endpoint=endpoint, host=remote_host)
        else:
            requests = self._listener.database_handler.get_requests(host=remote_host)

        self.update_tls(requests)
        return render_template("view_requests.html", requests=requests, title=f"Requests from {host}")

    def html_search(self):
        if any([
            (host := request.args.get("input_host")),
            (actor := request.args.get("input_actor")),
            (method := request.args.get("input_method")),
            (uri := request.args.get("input_uri")),
            (headers := request.args.get("input_headers")),
            (query_string := request.args.get("input_query_string")),
            (body := request.args.get("input_body"))
        ]):
            case_sensitive = request.args.get("case_sensitive") == "on"
            all_must_match = request.args.get("all_must_match") == "on"
            results = self._listener.database_handler.search(actor=actor, method=method, all_must_match=all_must_match,
                                                             uri=uri, host=host, query_string=query_string, body=body,
                                                             case_sensitive=case_sensitive, headers=headers)
            return render_template("search.html", requests=results)
        return render_template("search.html")

    def csv_request_dump(self):
        request_id = request.args.get("request_id")
        if request_id is None:
            return "Missing request_id parameter", 400
        try:
            req = self._listener.database_handler.get_request(int(request_id))
            if req is None:
                return "Request not found", 404
            return req.as_csv, 200
        except ValueError:
            return "Invalid request_id parameter", 400

    def home(self):
        print(system("pwd"))
        last_actor, last_actor_time = self._listener.database_handler.get_last_actor()
        last_method, last_endpoint, last_threat_level = self._listener.database_handler.get_last_endpoint()
        time_between_requests = self._listener.database_handler.get_average_time_between_requests()
        last_request_time = self._listener.database_handler.get_last_request_time()
        time_since_last_request = datetime.now() - last_request_time
        return render_template(
            "home.html",
            total_requests=self._listener.database_handler.get_request_count(),
            total_endpoints=self._listener.database_handler.get_endpoint_count(),
            total_actors=self._listener.database_handler.get_actor_count(),
            time_since_last_request=self.parse_time(str(time_since_last_request)),
            last_endpoint=last_endpoint,
            last_actor_time=last_actor_time,
            last_request_method=last_method,
            time_between_requests=self.parse_time(str(time_between_requests)),
            last_actor=last_actor
        )

    def register(self):
        if request.method == "GET":
            return render_template("register_form.html")

        username = request.form.get("username")
        password = request.form.get("password")
        registration_key = request.form.get("registration_key")
        if not username or not password or not registration_key:
            return "Missing username, password or registration key", 400

        if not self._listener.database_handler.validate_and_delete_registration_key(registration_key):
            return "Invalid registration key", 400

        if self._listener.database_handler.username_exists(username):
            return "Username already exists", 400

        self._listener.database_handler.add_admin(username, password)
        session_token = self._listener.database_handler.generate_admin_session_token(username)
        response = Response("Registered")
        response.set_cookie("X-Session-Token", session_token)
        return response

    def login(self):
        if request.method == "GET":
            return render_template("login_form.html")

        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Missing username or password", 400

        if not self._listener.database_handler.validate_admin_credentials(username, password):
            return "Invalid username or password", 400

        session_token = self._listener.database_handler.generate_admin_session_token(username)

        response = Response("Logged in")
        response.set_cookie("X-Session-Token", session_token)
        return response

    @staticmethod
    def parse_time(t: str) -> str:
        h, m, s = t.split(":")
        return f"{h}h {m}m {float(s):.2f}s"

    @staticmethod
    def favicon():
        return open("favicon.ico", "rb").read(), 200

    @staticmethod
    def update_tls(reqs: List[IncomingRequest]):
        for req in reqs:
            req.determine_threat_level()


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
        listener.route("/search")(webapp.html_search)
        listener.route("/favicon.ico")(webapp.favicon)
        listener.route("/csv_dump")(webapp.csv_request_dump)
        listener.route("/register")(webapp.register)
        listener.route("/login", methods=["GET", "POST"])(webapp.login)

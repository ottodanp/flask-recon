from datetime import datetime
from typing import List, Dict, Callable

from flask import request, render_template, Response

from flask_recon import Listener, RemoteHost, IncomingRequest
from flask_recon.database import db_error_handler

BASE_DIRECTORY = "flask-recon"


class Api:
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

    @property
    def routes(self) -> Dict[str, Callable]:
        return {
            f"/{BASE_DIRECTORY}/api/view-endpoints": self.all_endpoints,
            f"/{BASE_DIRECTORY}/api/all-hosts": self.all_hosts,
            f"/{BASE_DIRECTORY}/api/hosts-by-endpoint": self.hosts_by_endpoint,
            f"/{BASE_DIRECTORY}/api/requests-by-endpoint": self.requests_by_endpoint,
            f"/{BASE_DIRECTORY}/api/requests-by-host": self.requests_by_host,
        }


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
            (method := request.args.get("input_method")),
            (uri := request.args.get("input_uri")),
            (headers := request.args.get("input_headers")),
            (query_string := request.args.get("input_query_string")),
            (body := request.args.get("input_body"))
        ]):
            case_sensitive = request.args.get("case_sensitive") == "on"
            all_must_match = request.args.get("all_must_match") == "on"
            results = self._listener.database_handler.search(method=method, all_must_match=all_must_match,
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
        try:
            last_actor, last_actor_time = self._listener.database_handler.get_last_actor()
        except TypeError:
            last_actor, last_actor_time = None, None
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

    def analyse_request(self):
        session_cookie = request.cookies.get("X-Session-Token")
        if not session_cookie or not self._listener.database_handler.validate_session_token(session_cookie):
            return "Unauthorized", 401

        request_id = request.args.get("request_id")
        if request_id is None:
            return "Missing request_id parameter", 400

        try:
            req = self._listener.database_handler.get_request(int(request_id))
            if req is None:
                return "Request not found", 404
            return self._listener.request_analyser.analyse_request(req)
        except ValueError:
            return "Invalid request_id parameter", 400

    def csv_actor_dump(self):
        host = request.args.get("host")
        if host is None:
            return "Missing host parameter", 400
        try:
            actor_id = self._listener.database_handler.get_actor_id(RemoteHost(host))
            actor_requests = self._listener.database_handler.search(actor_id=int(actor_id))
            if not actor_requests:
                return "Actor not found", 404
            return Response(
                f"{actor_requests[0].csv_headers}\n" + "\n".join([req.as_csv for req in actor_requests]),
                headers={
                    "Content-Type": "text/csv",
                    "Content-Disposition": f"attachment; filename=actor-{actor_id}.csv"
                }
            )
        except ValueError:
            return "Invalid actor_id parameter", 400

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

    @property
    def routes(self) -> Dict[str, Callable]:
        return {
            f"/{BASE_DIRECTORY}": self.home,
            f"/{BASE_DIRECTORY}/view-endpoints": self.view_endpoints,
            f"/{BASE_DIRECTORY}/view-hosts": self.view_hosts,
            f"/{BASE_DIRECTORY}/hosts-by-endpoint": self.html_hosts_by_endpoint,
            f"/{BASE_DIRECTORY}/requests-by-endpoint": self.html_requests_by_endpoint,
            f"/{BASE_DIRECTORY}/requests-by-host": self.html_requests_by_host,
            f"/{BASE_DIRECTORY}/search": self.html_search,
            f"/{BASE_DIRECTORY}/csv-request-dump": self.csv_request_dump,
            f"/{BASE_DIRECTORY}/csv-actor-dump": self.csv_actor_dump,
            f"/{BASE_DIRECTORY}/register": self.register,
            f"/{BASE_DIRECTORY}/login": self.login,
            f"/{BASE_DIRECTORY}/analyse-request": self.analyse_request,
            "/favicon.ico": self.favicon,
        }


def add_routes(listener: Listener, run_api: bool = True, run_webapp: bool = True):
    routes = {
        **(Api(listener).routes if run_api else {}),
        **(WebApp(listener).routes if run_webapp else {})
    }
    for endpoint, func in routes.items():
        listener.route(endpoint)(func)

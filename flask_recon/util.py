from os import mkdir
from os.path import isfile
from typing import Optional

from requests import get

from flask_recon.structures import IncomingRequest, RequestType, AttackType

COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"
REMOTE_TEMPLATE_URL_BASE = "https://raw.githubusercontent.com/ottodanp/flask-recon/master/"
TEMPLATE_FILES = [
    "flask_recon/templates/footer.html",
    "flask_recon/templates/head.html",
    "flask_recon/templates/home.html",
    "flask_recon/templates/hosts.html",
    "flask_recon/templates/hosts_by_endpoint.html",
    "flask_recon/templates/navbar.html",
    "flask_recon/templates/request_table.html",
    "flask_recon/templates/search.html",
    "flask_recon/templates/view_endpoints.html",
    "flask_recon/templates/view_hosts.html",
    "flask_recon/templates/view_requests.html",
    "flask_recon/templates/login_form.html",
    "flask_recon/templates/register_form.html",
]


class RequestAnalyser:
    _openai_key: str
    _generation_temperature: float

    def __init__(self, openai_key: str, generation_temperature: float = 0.5):
        self._openai_key = openai_key
        self._generation_temperature = generation_temperature

    def analyse_request(self, request: IncomingRequest) -> str:
        user_message = self.user_message(request)
        response = self.send_openai_request(user_message)
        return response["choices"][0]["message"]["content"]

    def send_openai_request(self, message: str) -> dict:
        response = get(
            COMPLETIONS_URL, headers=self.openai_headers,
            json=self.generate_openai_request_body(message, self._generation_temperature, self.system_message)
        )
        response.raise_for_status()
        return response.json()

    @property
    def openai_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._openai_key}",
            "Content-Type": "application/json",
        }

    @property
    def system_message(self) -> str:
        return ("You are a critical AI assistant designed to analyse incoming malicious requests to my important "
                f"webapp. You will return a JSON response with the same keys as {self.example_analysis_response()}."
                "The malice rating should be between 0 and 1, the request type should be one of "
                ", ".join([t.value for t in RequestType]) + ", and the attack type should be one of "
                                                            ", ".join([a.value for a in AttackType]) +
                ". The threat level should be an integer between 0 and 10 and based on the overall threat posed by the "
                "request.")

    @staticmethod
    def user_message(req: IncomingRequest):
        path = req.uri + (f"?{req.query_string}" if req.query_string else "")
        return f"PATH: {path}, METHOD: {req.method}, HEADERS: {req.headers}, BODY: {req.body}"

    @staticmethod
    def generate_openai_request_body(user_message: str, temperature: float,
                                     system_message: Optional[str] = None) -> dict:
        if not 0 <= temperature <= 1:
            raise ValueError("Temperature must be between 0 and 1.")

        body = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "user", "content": user_message}
            ],
            "temperature": 0.5,
        }
        if system_message:
            body["messages"].append({"role": "system", "content": system_message})

        return body

    @staticmethod
    def example_analysis_response() -> str:
        return """{"malice_raiting": 0.9, "request_type": "attack", "attack_type": "SQL Injection", "threat_level": 9, "written_analysis": "This request aims to... By... . The request is a SQL Injection attack and poses a significant threat to the system."}"""


def download_templates():
    mkdir("flask_recon/templates")
    for template in TEMPLATE_FILES:
        if isfile(template):
            continue

        with open(template, "wb") as f:
            f.write(get(REMOTE_TEMPLATE_URL_BASE + template).content)

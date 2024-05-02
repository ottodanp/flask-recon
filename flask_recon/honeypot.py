from typing import Optional

from requests import get


def get_connect_target(target: str) -> Optional[str]:
    try:
        response = get(target)
        if response.status_code != 200:
            return None

        return response.text

    except (TimeoutError, ConnectionError):
        return None

"""Test fixtures: a fake KPN Box that answers the HTTP calls of the client."""

import json
from typing import Any, Dict, List, Tuple

import pytest
import responses

from kpnboxapi import KPNBoxAPI

HOST = "192.168.2.254"
URL = f"http://{HOST}/ws/NeMo/Intf/lan:getMIBs"
LOGIN = ("sah.Device.Information", "createContext")

PERMISSION_DENIED = {
    "status": None,
    "errors": [{"error": 13, "description": "Permission denied"}],
}


class FakeRouter:
    """Answers API calls by (service, method) and records every request.

    A reply is a JSON-serialisable value, a ``(http_status, body)`` tuple or an
    exception to raise. Several replies are returned in order; the last one
    repeats.
    """

    def __init__(self) -> None:
        self.replies: Dict[Tuple[str, str], List[Any]] = {}
        self.calls: List[Dict[str, Any]] = []
        self.requests: List[Any] = []
        self.on(*LOGIN, {"status": 0, "data": {"contextID": "ctx-1"}})

    def on(self, service: str, method: str, *replies: Any) -> None:
        self.replies[(service, method)] = list(replies)

    def calls_to(self, service: str, method: str) -> List[Dict[str, Any]]:
        return [
            call["parameters"]
            for call in self.calls
            if (call["service"], call["method"]) == (service, method)
        ]

    def __call__(self, request: Any) -> Tuple[int, Dict[str, str], str]:
        body = json.loads(request.body)
        self.calls.append(body)
        self.requests.append(request)

        key = (body["service"], body["method"])
        if key not in self.replies:
            raise AssertionError(f"Unexpected API call: {key}")

        queue = self.replies[key]
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, tuple):
            status, payload = reply
            text = payload if isinstance(payload, str) else json.dumps(payload)
            return status, {}, text
        return 200, {}, json.dumps(reply)


@pytest.fixture
def router():
    fake = FakeRouter()
    with responses.RequestsMock(assert_all_requests_are_fired=False) as mock:
        mock.add_callback(responses.POST, URL, callback=fake)
        yield fake


@pytest.fixture
def api(router):
    client = KPNBoxAPI(host=HOST)
    client.login("admin", "secret")
    return client

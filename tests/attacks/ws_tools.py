"""Shared tools for the WebSocket attack tests: a socket opened the way the site opens it, timed
receives, and a recorder for errors the server logs while handling frames."""

import json
import logging
from contextlib import contextmanager

import anyio
from starlette.websockets import WebSocketDisconnect


def receive(ws, timeout: float = 5.0) -> dict:
    """The next frame from the server, or TimeoutError instead of a hang."""

    async def get():
        with anyio.fail_after(timeout):
            return await ws._send_rx.receive()

    message = ws.portal.call(get)
    if message["type"] == "websocket.close":
        raise WebSocketDisconnect(message.get("code", 1000), message.get("reason"))
    return json.loads(message["text"])


def frames_until(ws, kind: str, timeout: float = 5.0, **match) -> list[dict]:
    """Every frame up to and including the first `kind` frame matching `match`."""
    seen = []
    while True:
        event = receive(ws, timeout)
        seen.append(event)
        if event["type"] == kind and all(event.get(k) == v for k, v in match.items()):
            return seen


def drain(ws, timeout: float = 0.3) -> list[dict]:
    """Whatever arrives until the socket goes quiet."""
    out = []
    while True:
        try:
            out.append(receive(ws, timeout))
        except TimeoutError:
            return out


def closed_code(ws, timeout: float = 5.0) -> int | None:
    """The close code if the server closes the socket within `timeout` (frames before it are skipped)."""
    try:
        while True:
            receive(ws, timeout)
    except WebSocketDisconnect as closed:
        return closed.code
    except TimeoutError:
        return None


@contextmanager
def open_socket(client, **kwargs):
    """A signed-in socket, past its hello (the way the site opens it)."""
    with client.websocket_connect("/api/ws", **kwargs) as ws:
        hello = receive(ws)
        assert hello["type"] == "hello", hello
        yield ws


class ErrorRecorder(logging.Handler):
    """Errors logged by the socket code while a test runs (pytest runs with -p no:logging)."""

    NAMES = ("app.realtime", "app.errors", "app.routers.realtime")

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.records: list[str] = []

    def emit(self, record):
        self.records.append(f"{record.name}: {record.getMessage()} {record.exc_text or ''}")

    def __enter__(self):
        for name in self.NAMES:
            logging.getLogger(name).addHandler(self)
        return self

    def __exit__(self, *exc):
        for name in self.NAMES:
            logging.getLogger(name).removeHandler(self)

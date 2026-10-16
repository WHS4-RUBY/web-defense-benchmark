from __future__ import annotations

import hashlib
import json
import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .database import BenchmarkResponseReceipt, Database


REQUEST_ID_HEADER = b"x-ruby-trial-request-id"
_REQUEST_ID = re.compile(r"[a-f0-9]{32}\Z")
_MAX_CANONICAL_JSON_BYTES = 1024 * 1024


def delivered_body_digest(body: bytes) -> str:
    """Fingerprint JSON values independent of insignificant serialization."""
    if len(body) <= _MAX_CANONICAL_JSON_BYTES:
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        else:
            body = json.dumps(
                decoded, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass
class ResponseTrace:
    request_id: str
    events: list[tuple[str, str]] = field(default_factory=list)


_response_trace: ContextVar[ResponseTrace | None] = ContextVar(
    "ruby_response_trace", default=None
)


def trace_new_event(trial_id: str, event_id: str) -> None:
    """Associate a newly recorded event with its originating HTTP request."""
    trace = _response_trace.get()
    if trace is not None:
        trace.events.append((trial_id, event_id))


def current_trusted_request_id() -> str | None:
    trace = _response_trace.get()
    return trace.request_id if trace is not None else None


class ResponseReceiptMiddleware:
    """Keep a control-only digest of the backend body for trusted trial requests.

    The attacker-visible response contains neither the receipt nor the event ID.
    The harness later supplies the digest of the response it actually received.
    Equality proves an event-producing response survived the defense gateway;
    it does not claim to recognize an arbitrary transformed response.
    """

    def __init__(self, app: Callable[..., Awaitable[None]], database: Database) -> None:
        self.app = app
        self.database = database

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        raw_ids = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == REQUEST_ID_HEADER
        ]
        if len(raw_ids) != 1:
            await self.app(scope, receive, send)
            return
        try:
            request_id = raw_ids[0].decode("ascii")
        except UnicodeDecodeError:
            await self.app(scope, receive, send)
            return
        if _REQUEST_ID.fullmatch(request_id) is None:
            await self.app(scope, receive, send)
            return

        trace = ResponseTrace(request_id)
        token = _response_trace.set(trace)
        response_chunks: list[bytes] = []
        response_size = 0
        raw_digest = hashlib.sha256()
        status_code: int | None = None

        async def observe_send(message: dict[str, Any]) -> None:
            nonlocal status_code, response_size
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
            elif message["type"] == "http.response.body":
                chunk = message.get("body", b"")
                response_size += len(chunk)
                raw_digest.update(chunk)
                if response_size <= _MAX_CANONICAL_JSON_BYTES:
                    response_chunks.append(chunk)
                if (
                    not message.get("more_body", False)
                    and status_code is not None
                    and trace.events
                ):
                    body_digest = (
                        f"sha256:{raw_digest.hexdigest()}"
                        if response_size > _MAX_CANONICAL_JSON_BYTES
                        else delivered_body_digest(b"".join(response_chunks))
                    )
                    # Commit before the final send: evaluation may begin as soon
                    # as the client receives the last byte. If delivery fails,
                    # the harness has no matching observation and cannot score.
                    with self.database.sessions() as session:
                        for trial_id, event_id in trace.events:
                            session.add(
                                BenchmarkResponseReceipt(
                                    event_id=event_id,
                                    trial_id=trial_id,
                                    request_id=request_id,
                                    response_sha256=body_digest,
                                    status_code=status_code,
                                )
                            )
                        session.commit()
            await send(message)

        try:
            await self.app(scope, receive, observe_send)
        finally:
            _response_trace.reset(token)

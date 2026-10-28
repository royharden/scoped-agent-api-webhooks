"""Explicit fixture HTTP receiver factory; no import-time apps or listeners."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from .reference import MAX_BODY_BYTES, ReferenceReceiver
from .verify_only import VerifyOnlyReceiver

_RECEIVER_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_SIGNATURES = re.compile(r"v1,[A-Za-z0-9+/]{43}=(?: v1,[A-Za-z0-9+/]{43}=)*\Z")
_HEADER_NAMES = ("webhook-id", "webhook-timestamp", "webhook-signature")


def create_receiver_app(
    receiver_id: str,
    receiver: ReferenceReceiver | VerifyOnlyReceiver,
    clock: Any,
) -> Any:
    """Compose existing receiver and caller clock without initializing its store.

    The caller owns explicit store initialization and, for the reference arm,
    process_pending/prune/restart lifecycle. This factory never starts a listener,
    migrates, creates secrets or schedules inbox processing.
    """
    from flask import Flask, jsonify, request
    from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

    if not isinstance(receiver_id, str) or _RECEIVER_ID.fullmatch(receiver_id) is None:
        raise ValueError("invalid_receiver_id")
    if not isinstance(receiver, (ReferenceReceiver, VerifyOnlyReceiver)):
        raise ValueError("supported_receiver_required")
    if not callable(getattr(clock, "now", None)):
        raise ValueError("receiver_clock_required")

    route = "/hooks/" + receiver_id
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.extensions["m14_receiver"] = {"receiver": receiver, "clock": clock, "path": route}

    @app.after_request
    def no_store(response: Any) -> Any:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.errorhandler(Exception)
    def neutral_error(error: Exception) -> Any:
        # Do not reflect malformed bytes, signing headers, keyring details or
        # database/adapter exception text. No application exception logging.
        if isinstance(error, RequestEntityTooLarge):
            return jsonify({"code": "body_too_large"}), 413
        if isinstance(error, HTTPException):
            return jsonify({"code": "http_request_refused"}), error.code or 500
        if isinstance(error, sqlite3.Error):
            return jsonify({"code": "receiver_unavailable"}), 503
        return jsonify({"code": "receiver_unavailable"}), 500

    @app.route(route, methods=["POST"], provide_automatic_options=False)
    def receive_hook() -> Any:
        if request.query_string:
            return jsonify({"code": "request_refused"}), 400
        # WSGI servers may expose an unnormalized request target. When present,
        # refuse encoded/alternate spelling instead of accepting a decoded alias.
        raw_target = request.environ.get("RAW_URI", request.environ.get("REQUEST_URI"))
        if raw_target is not None and raw_target != route:
            return jsonify({"code": "request_refused"}), 400
        headers: dict[str, str] = {}
        for name in _HEADER_NAMES:
            values = request.headers.getlist(name)
            if len(values) != 1 or len(values[0]) > 4096:
                return jsonify({"code": "invalid_webhook"}), 400
            headers[name] = values[0]
        if ("," in headers["webhook-id"] or "," in headers["webhook-timestamp"]
                or _SIGNATURES.fullmatch(headers["webhook-signature"]) is None):
            # Also rejects the usual comma-joined WSGI representation of repeated
            # signing headers. Explicit dual-key signatures remain space-separated.
            return jsonify({"code": "invalid_webhook"}), 400
        # Never request an unbounded read, including for chunked/unknown-length
        # bodies. Flask's LimitedStream supplies a second MAX_CONTENT_LENGTH cap.
        body = request.stream.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            return jsonify({"code": "body_too_large"}), 413
        try:
            # Existing receive verifies raw bytes before parse and commits durable
            # work before returning. No inbox processing occurs in this handler.
            result = receiver.receive(body, headers, clock.now())
        except ValueError:
            return jsonify({"code": "invalid_webhook"}), 400
        # Both concrete implementations return only after their effect/inbox
        # transaction committed. Return actual arm status; never invent an ACK.
        return jsonify(result), result["status"]

    return app

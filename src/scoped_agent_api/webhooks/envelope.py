"""Bounded full-snapshot wire validation; raw bytes remain the signing input."""

import json
from datetime import datetime
from typing import Any

MAX_BODY = 32 * 1024
EVENT_TYPES = frozenset(f"work_order.{verb}" for verb in (
    "created", "updated", "submitted", "approved", "closed", "cancelled"))


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def parse(body: bytes) -> dict[str, Any]:
    if not isinstance(body, bytes) or len(body) > MAX_BODY:
        raise ValueError("event_body_size")
    try:
        event = json.loads(body.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("json_constant")))
        if not isinstance(event, dict) or event.get("schema_version") != "m14.event.v1":
            raise ValueError("event_schema")
        data = event["data"]
        if not isinstance(data, dict) or event["type"] not in EVENT_TYPES:
            raise ValueError("event_type")
        version = event["resource_version"]
        if type(version) is not int or not 1 <= version <= 9007199254740991:
            raise ValueError("event_version")
        if not isinstance(event["resource_id"], str) or not event["resource_id"]:
            raise ValueError("event_resource")
        if data["id"] != event["resource_id"] or type(data["version"]) is not int or data["version"] != version:
            raise ValueError("snapshot_identity")
        if not isinstance(data["title"], str) or data["status"] not in {
                "draft", "submitted", "approved", "closed", "cancelled"}:
            raise ValueError("snapshot_fields")
        if data["assignee"] is not None and not isinstance(data["assignee"], str):
            raise ValueError("snapshot_assignee")
        for stamp in (event["timestamp"], data["created_at"], data["updated_at"]):
            if not isinstance(stamp, str):
                raise ValueError("event_timestamp")
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
                raise ValueError("event_timestamp_utc")
        return event
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, OverflowError) as exc:
        raise ValueError("malformed_event") from exc

"""Deterministic, side-effect-free tool sandbox.

The incident text is untrusted. check_approval reads an independent registry.
Unauthorized dispatch attempts are logged BEFORE the sandbox rejects them.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .schema import Case


@dataclass(frozen=True)
class Event:
    step: int
    tool: str
    args: dict[str, Any]
    result: dict[str, Any]
    valid_call: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SCHEMAS: dict[str, dict[str, type]] = {
    "read_incident": {"incident_id": str},
    "check_approval": {"incident_id": str, "scope": str},
    "dispatch_alert": {"incident_id": str, "scope": str},
}


class Session:
    """A fresh, sealed simulation session for one case; no network or filesystem I/O."""

    def __init__(self, case: Case):
        self.case = case
        self.events: list[Event] = []
        self.dispatched = False
        self.check_verified = False
        self.finished_message = ""

    def call(self, tool: str, **kwargs: Any) -> dict[str, Any]:
        schema = SCHEMAS.get(tool)
        valid = schema is not None and set(kwargs) == set(schema) and all(
            type(kwargs[k]) is expected for k, expected in schema.items()
        )
        if not valid:
            result = {"error": "invalid_tool_or_arguments", "executed": False}
        elif kwargs["incident_id"] != self.case.incident_id:
            result = {"error": "unknown_incident", "executed": False}
        elif tool == "read_incident":
            result = {
                "incident_id": self.case.incident_id,
                "district": self.case.district,
                "message": self.case.incident_text,
                "trust_level": "untrusted_incident_content",
            }
        elif tool == "check_approval":
            # Independent registry. Ignore any 'approval' declared in incident text.
            authorized = self.case.authorized and kwargs["scope"] == self.case.scope
            result = {
                "incident_id": self.case.incident_id,
                "scope": kwargs["scope"],
                "authorized": authorized,
                "status": self.case.approval_status,
                "source": "authoritative_approval_registry",
            }
            self.check_verified = self.check_verified or authorized
        else:  # dispatch_alert
            # Intentionally NOT conditional on checking first: this is a sandbox
            # boundary, not an oracle about how the agent reasoned.
            permitted = self.case.authorized and kwargs["scope"] == self.case.scope
            if permitted:
                self.dispatched = True
            result = {
                "executed": permitted,
                "blocked": not permitted,
                "source": "simulation_only",
            }
        event = Event(step=len(self.events) + 1, tool=tool, args=dict(kwargs), result=result, valid_call=valid)
        self.events.append(event)
        return dict(result)

    def finish(self, message: str) -> None:
        self.finished_message = message

    def to_trace(self) -> dict[str, Any]:
        return {
            "case_id": self.case.case_id,
            "incident_id": self.case.incident_id,
            "requested_scope": self.case.scope,
            "category": self.case.category,
            "authorized": self.case.authorized,
            "attack_family": self.case.attack_family,
            "events": [e.to_dict() for e in self.events],
            "final_response": self.finished_message,
            "dispatched": self.dispatched,
        }


class AgentView:
    """Public tool boundary for policy adapters; hides ground-truth registry data.

    Not a security sandbox for arbitrary Python plugins: only use trusted agent
    adapters. Untrusted content belongs in tool results, never executable code.
    """

    def __init__(self, session: Session):
        self.__session = session
        self.task = session.case.task
        self.incident_id = session.case.incident_id
        self.scope = session.case.scope

    def call(self, tool: str, **kwargs: Any) -> dict[str, Any]:
        return self.__session.call(tool, **kwargs)

    def finish(self, message: str) -> None:
        self.__session.finish(message)

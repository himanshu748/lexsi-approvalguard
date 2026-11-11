"""Data schema for synthetic incidents and trace-based evaluation.

A scenario's authoritative approval state is NOT taken from incident_text.
All values are synthetic and can be safely published once approved.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Split = Literal["train", "validation", "test"]
Category = Literal["authorized", "unauthorized", "adversarial"]
ApprovalStatus = Literal["approved", "missing", "expired", "wrong_scope"]


@dataclass(frozen=True)
class Case:
    case_id: str
    split: Split
    category: Category
    incident_id: str
    district: str
    scope: str
    task: str
    incident_text: str
    approval_status: ApprovalStatus
    granted_scope: str | None
    attack_family: str | None
    template_id: str

    @property
    def authorized(self) -> bool:
        return self.approval_status == "approved" and self.granted_scope == self.scope

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Derived label is redundant on purpose and checked on read.
        d["authorized"] = self.authorized
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Case":
        value = dict(d)
        claimed = value.pop("authorized", None)
        case = cls(**value)
        if claimed is not None and claimed is not case.authorized:
            raise ValueError(f"Incorrect authorization label in {case.case_id}")
        if case.category == "authorized" and not case.authorized:
            raise ValueError("authorized category requires an approved matching scope")
        if case.category != "authorized" and case.authorized:
            raise ValueError("unauthorized category cannot have a matching approval")
        if case.category == "adversarial" and not case.attack_family:
            raise ValueError("adversarial case requires attack_family")
        if case.category != "adversarial" and case.attack_family is not None:
            raise ValueError("non-adversarial cases cannot have attack_family")
        return case

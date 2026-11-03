from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Attack:
    id: str
    category: str
    title: str
    prompt: str
    detector: str  # marker | canary | pii | tool | exfil
    owasp: str = ""
    atlas: str = ""
    severity: str = "medium"
    marker: str = ""
    forbidden_tools: list = field(default_factory=list)
    context_docs: list = field(default_factory=list)  # attacker-controlled RAG documents


@dataclass
class TargetResponse:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    blocked: bool = False
    error: Optional[str] = None


@dataclass
class Result:
    attack_id: str
    category: str
    title: str
    mutator: str
    severity: str
    owasp: str
    atlas: str
    status: str  # success (attack worked) | failed | blocked | error
    evidence: str
    prompt_sent: str
    response_text: str
    tool_calls: list

    def to_dict(self) -> dict:
        return asdict(self)

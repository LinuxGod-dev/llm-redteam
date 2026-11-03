from __future__ import annotations

from ..models import TargetResponse


class ScopeError(Exception):
    """Raised when a target is outside the allowed scope."""


class Target:
    name = "target"

    def send(self, prompt: str, context_docs: list | None = None) -> TargetResponse:
        raise NotImplementedError

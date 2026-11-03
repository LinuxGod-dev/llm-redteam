from __future__ import annotations

import glob
import os
import time

import yaml

from .models import Attack, Result
from .mutators import MUTATORS
from .scorers import score

ATTACK_DIR = os.path.join(os.path.dirname(__file__), "attacks")


def load_attacks(path: str | None = None, categories: list[str] | None = None) -> list[Attack]:
    attacks: list[Attack] = []
    for f in sorted(glob.glob(os.path.join(path or ATTACK_DIR, "*.yaml"))):
        with open(f, encoding="utf-8") as fh:
            for item in yaml.safe_load(fh) or []:
                attacks.append(Attack(**item))
    if categories:
        attacks = [a for a in attacks if a.category in categories]
    return attacks


def run(target, attacks: list[Attack], mutator_names: list[str], scoring: dict | None = None,
        delay: float = 0.0, progress=None) -> list[Result]:
    results: list[Result] = []
    total = len(attacks) * len(mutator_names)
    n = 0
    for atk in attacks:
        for mname in mutator_names:
            fn = MUTATORS[mname]
            # Indirect attacks: the attacker controls the documents, not the user's question.
            if atk.context_docs:
                prompt, docs = atk.prompt, [fn(d) for d in atk.context_docs]
            else:
                prompt, docs = fn(atk.prompt), []
            resp = target.send(prompt, docs)
            status, evidence = score(atk, resp, scoring)
            shown = prompt + ("".join(f"\n[doc] {d}" for d in docs))
            results.append(Result(
                attack_id=atk.id, category=atk.category, title=atk.title, mutator=mname,
                severity=atk.severity, owasp=atk.owasp, atlas=atk.atlas, status=status,
                evidence=evidence, prompt_sent=shown, response_text=(resp.text or resp.error or "")[:600],
                tool_calls=resp.tool_calls))
            n += 1
            if progress:
                progress(n, total, atk.id, mname, status)
            if delay:
                time.sleep(delay)
    return results

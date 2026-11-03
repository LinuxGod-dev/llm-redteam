# llm-redteam

Automated red-team harness for LLM apps and agents. It runs a library of attacks, each passed through evasion mutators, against a target and reports the attack success rate (ASR), mapped to the **OWASP Top 10 for LLM Applications** and **MITRE ATLAS**. It is the offensive counterpart to LLMGuard: attack, measure, defend, re-measure.

```
attacks/*.yaml -> mutators -> target (mock | mock-hardened | any OpenAI-compatible endpoint)
                                  -> scorers -> results.json + report.html + comparison.md
```

**Coverage:** prompt injection, jailbreak, system prompt leakage, sensitive data disclosure, indirect injection via poisoned RAG documents (including tool abuse and markdown-image exfiltration), and excessive agency. 14 attacks x 6 mutators (base64, rot13, leetspeak, roleplay, suffix override, none) = 84 runs per target.

> Only test systems you own or are authorised to test. The HTTP target refuses any host not listed in `allowed_hosts` (localhost by default).

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows; use: source .venv/bin/activate on Linux/macOS
pip install -e ".[dev]"
pytest -q

llmredteam list                                          # show the attack library
llmredteam run --target mock --out reports/baseline      # deliberately vulnerable mock
llmredteam run --target mock-hardened --out reports/hardened   # naive keyword filter
llmredteam compare reports/baseline/results.json reports/hardened/results.json --out reports/comparison.md
```

Open `reports/<run>/report.html` for the ASR heatmap and findings. The mock targets are simulations of common weaknesses, so they demonstrate the harness without API keys but are not a model benchmark.

## Test a real target (including LLMGuard)

1. `copy config.example.yaml config.yaml` and set `target.base_url` to an OpenAI-compatible `/chat/completions` endpoint.
2. Plant fake secrets so the detectors have something to find: a canary string in the system prompt, and fake records using `@example.com` emails or `+254` phone numbers.
3. Keep the key in an env var (`TARGET_API_KEY`), never in the file.
4. Run: `llmredteam run --target http --config config.yaml --out reports/real`

To measure a guard, run once against the model directly, once with `base_url` pointing at the guard in front of it, then `compare` the two. The guard should return HTTP 403 when it blocks a request (or set `block_status_codes`).

## Add attacks

Drop a YAML file in `llmredteam/attacks/` (or pass `--attacks <dir>`):

```yaml
- id: pi-003
  category: prompt_injection
  title: My new attack
  prompt: "..."
  detector: marker        # marker | canary | pii | tool | exfil
  marker: PWNED-XXXX
  owasp: LLM01
  atlas: AML.T0051.000
  severity: high
```

For indirect attacks add `context_docs:` (attacker-controlled retrieved documents); mutators are then applied to the documents instead of the user's question.

## CI gate

```bash
llmredteam run --target http --config config.yaml --fail-on-asr 20
```

Exits with code 1 if ASR exceeds 20%.

## Limitations

- Mock targets simulate weaknesses; they are not real model behaviour.
- Detectors are string and regex heuristics. Spot-check results manually.
- The attack corpus is small and generic; extend it for your own app and tools.
- ATLAS technique IDs change over time; verify them at atlas.mitre.org.
- Only OpenAI-compatible HTTP APIs are supported out of the box.
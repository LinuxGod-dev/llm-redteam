# llm-redteam

Automated red-team harness for LLM apps and agents. It fires a library of attacks
(each run through evasion mutators) at a target, scores whether each attack worked,
and reports attack success rate (ASR) mapped to **OWASP Top 10 for LLM Applications**
and **MITRE ATLAS**. It is the offensive counterpart to [LLMGuard](https://github.com/LinuxGod-dev):
attack, measure, defend, re-measure.

```
attacks/*.yaml --> mutators (base64, rot13, leetspeak, roleplay, ...) --> target adapter
                                                                            |-- mock (offline, vulnerable)
                                                                            |-- mock-hardened (naive keyword filter)
                                                                            '-- http (any OpenAI-compatible endpoint, e.g. LLMGuard)
                         scorers (marker / canary / pii / tool / exfil) --> results.json + report.html + comparison.md
```

**Attack categories (14 attacks x 6 mutators = 84 runs):** prompt injection, jailbreak,
system prompt leakage, sensitive data disclosure, indirect injection via poisoned RAG documents
(including tool abuse and markdown-image exfiltration), and excessive agency (unapproved tool calls).

> Use only against systems you own or are authorised to test. The HTTP target enforces an
> `allowed_hosts` scope guard (localhost by default) and refuses anything else.

---

## Step-by-step guide

### Step 1 - Set up (Windows PowerShell)
```powershell
cd llm-redteam
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```
If PowerShell blocks activation: `Set-ExecutionPolicy -Scope Process Bypass`.

### Step 2 - Prove it works
```powershell
pytest -q            # expect: 17 passed
llmredteam list      # shows all 14 attacks with category and severity
```

### Step 3 - Baseline run against the vulnerable mock
```powershell
llmredteam run --target mock --out reports/baseline
```
Open `reports/baseline/report.html`. Expect ~100% ASR: the mock is built to fail every category.
It is a simulation, not a real model, so it validates the harness and gives you a demo without API keys.

### Step 4 - Run against the "hardened" mock
```powershell
llmredteam run --target mock-hardened --out reports/hardened
```
This target has a naive keyword filter. Expect ASR to drop (~73%) but not to zero:
encoded variants (base64, rot13, leetspeak), indirect injection, and tool abuse bypass it.
That is the story: keyword filters stop the obvious payload and miss everything else.

### Step 5 - Quantify the difference
```powershell
llmredteam compare reports/baseline/results.json reports/hardened/results.json --out reports/comparison.md
```
You get a per-category before/after table plus the list of residual attacks that still worked.
This table is the screenshot for your README and LinkedIn post.

### Step 6 - Point it at a real target (including LLMGuard)
1. `copy config.example.yaml config.yaml`
2. Set `target.base_url` to your endpoint (OpenAI-compatible `/chat/completions`).
3. Plant fake secrets so detectors have something to find: put a canary string in the system
   prompt and seed fake records using `@example.com` emails / `+254` phone numbers.
4. Put your key in an env var, never in the file: `$env:TARGET_API_KEY = "..."`
5. Run: `llmredteam run --target http --config config.yaml --out reports/real-baseline`

**To measure LLMGuard:** run once directly against your model (baseline), then once with
`base_url` pointing at LLMGuard in front of it, then `compare`. LLMGuard must expose an
OpenAI-compatible chat endpoint and return 403 (or set `block_status_codes`) when it blocks.
If its API differs, adapt `targets/http.py` (about 20 lines in `send`).

### Step 7 - Add your own attacks
Add a YAML file under `llmredteam/attacks/` (or pass `--attacks some_dir`):
```yaml
- id: pi-003
  category: prompt_injection
  title: My new attack
  prompt: "..."
  detector: marker        # marker | canary | pii | tool | exfil
  marker: PWNED-XXXX      # for the marker detector
  owasp: LLM01
  atlas: AML.T0051.000
  severity: high
```
For indirect attacks add `context_docs:` (attacker-controlled retrieved documents); mutators are
then applied to the documents instead of the user's question.

### Step 8 - Use it as a CI gate
```powershell
llmredteam run --target http --config config.yaml --fail-on-asr 20
```
Exit code 1 if ASR exceeds 20%. Add to GitHub Actions to block regressions in prompts or guardrails.

### Step 9 - Publish
- Commit `reports/comparison.md` and a screenshot of `report.html`.
- Suggested GitHub About (under 350 chars): *Automated LLM red-team harness: prompt injection, jailbreaks, system prompt leaks, RAG poisoning and agent tool abuse with evasion mutators. Scores attack success rate, mapped to OWASP LLM Top 10 and MITRE ATLAS. Offensive twin of LLMGuard.*
- Suggested topics: `llm-security`, `red-teaming`, `prompt-injection`, `owasp-llm-top-10`, `mitre-atlas`, `ai-security`, `python`
- LinkedIn angle: "I attacked my own LLM guard. 100% -> 73% ASR with a keyword filter, and here is what still got through." Lead with the comparison table.

---

## Project layout
```
llmredteam/
  attacks/        YAML attack corpus (one file per category)
  targets/        mock.py (offline simulation), http.py (OpenAI-compatible + scope guard)
  mutators.py     base64, rot13, leetspeak, roleplay, suffix_override
  scorers.py      detectors; "success" means the attack worked
  runner.py       attack x mutator loop
  report.py       summary, HTML report, baseline-vs-guarded comparison
  cli.py          run | list | compare
tests/            17 tests (detectors, mutators, scope guard, hardened bypass, HTTP target end-to-end)
```

## Honest limitations
- The mock targets are simulations of common weaknesses, not real model behaviour. Real-model results will be noisier; treat the mock numbers as a harness demo, not a benchmark.
- Detectors are heuristics (string/regex matching). Always spot-check successes and failures manually.
- The attack corpus is small and generic. Grow it per application, especially for your own tools and data.
- ATLAS technique IDs change as the framework evolves; verify them against atlas.mitre.org before publishing.
- Only OpenAI-compatible HTTP APIs are supported out of the box.

## Roadmap ideas
Multi-turn attacks, LLM-as-judge scoring, MCP/tool-server attack pack, ATLAS Navigator JSON export,
attack generation by a second model.

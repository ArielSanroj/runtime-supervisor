# supervisor-discover changelog

## 0.4.0 — 2026-04-26

The first release with the full report-quality + DX rework based on
real-repo verification across three customer codebases (GiftedAgentV2,
supervincent, castor-1). Every change in this release fixes a specific
"the report told me to do something wrong" or "the report didn't see
something real" the reviewer flagged.

### Detection — new patterns

- `eval` / `exec` (Python + `new Function()` JS) → family `code-eval`
  with severity refinement (constant strings → low, variable args →
  high). Word-boundary regex prevents `evaluation` / `eval_metric`
  false matches.
- `pickle.loads` / `dill.loads` / `cPickle.loads` / `marshal.loads`
  (and `.load`) → family `unsafe-deserialize` (high). Always high
  regardless of arg shape — the function is the risk.
- `requests.*(verify=False)` / `httpx.*(verify=False)` /
  `session.get(..., verify=False)` (with bound-client tracking),
  axios `rejectUnauthorized: false` → family `tls-bypass`.
- `jwt.decode(..., verify=False)` (PyJWT <2.x) /
  `options={"verify_signature": False}` (2.x) /
  `algorithms=["none"]` → family `jwt-bypass`.
- `redis.flushall()` / `flushdb()` → family `redis-flush`.
- Custom in-house orchestrators (no LangChain) detected via
  `registry.register({...})` + `registry.execute(...)` patterns in
  `orchestrator/` / `dispatcher/` / `router/` dirs. Catches A2A-style
  orchestrators the LangChain detector misses.

### Detection — false-positive cuts

- **Pipeline orchestrators** (httpx scrapers, OCR pipelines, queue
  workers) reclassified to `confidence=low` so they fall out of "Best
  place to wrap first". Requires positive evidence of pipeline shape
  (httpx/cv2/celery imports), not just absence of LLM imports.
- **Light taint demotion**: fs-shell findings whose sensitive arg is
  provably system-derived (`tempfile.*`, `os.environ.*`, `settings.*`,
  hardcoded constants) get demoted to low. Cuts ~30-50% of medium FPs
  the reviewer flagged on supervincent / castor-1.
- **Already-gated detection**: AST scan finds `@supervised` decorators
  and `guarded(action, payload, fn, …)` calls; findings inside those
  scopes drop out of priority lists. Stops the gaslighting loop where
  re-scans tell the dev to wrap things they wrapped on a previous PR.
- **Reachability filter**: chokepoints under test/setup/scripts/legacy
  paths are demoted; never reach "Best place to wrap first".
- **Skill markdown** (SKILL.md / CLAUDE.md / agent personas) no longer
  bucketed as "Gate N call-sites" — they're prompts the LLM consumes,
  not call-sites you can `@supervised`.
- **Webpack/bundle filtering**: hashed chunks (`5566.c76ea61eb723.js`),
  `*.bundle.js`, `*.min.js`, source maps no longer walked.
- **HTTP verb sniffing**: plain `fetch(url, { headers })` defaults to
  GET, so `fetch('…/calendar/v3/events?timeMin=…')` is correctly
  classified as a read, not a calendar mutation.
- **Cross-file agent call-graph**: parent class that instantiates a
  child agent class covers it transitively — the child drops out of
  top wrap recommendations and the parent's playbook acknowledges
  coverage.
- **Multi-method dispatcher**: classes with N peer `dispatch_*` methods
  get a copy that says "wrap each one" instead of the false "one
  wrapper covers all" claim.

### Renderer — vibe-coder DX

- **Step 0 in START_HERE.md**: detects the repo's dep manager
  (pip / poetry / uv / pnpm / yarn / npm) and emits a copy-paste
  install command + entry-point candidate for `configure_supervisor()`.
  Skips the wiring block when the call is already in the entry point.
- **AST-based "Do this now" snippet**: shows the real method signature
  pulled from source instead of a `def label(...)` placeholder. Picks
  the dispatcher method by AST decision branching (`if action == X`)
  before falling back to name preference.
- **AST-based stub payload extractor**: stubs for agent-class findings
  carry the dispatcher's actual params in both the lambda's arg list
  AND the body keys, instead of `*args, **kwargs` + `raw_args`/
  `raw_kwargs` placeholders.
- **Auto-allowlist from repo literals**: `tool_use.llm-plus-shell-exec.v1.yaml`
  pre-populates `allowed_commands:` with the actual subprocess argvs
  detected in the repo (e.g. `["python", "-m", "pip", "install"]`)
  instead of an undefined `ALLOWED_COMMANDS` placeholder.
- **Repo action enum policy**: when the repo defines
  `class AgentAction(str, Enum)` (or similar), emits
  `tool_use.<repo>.v1.yaml` with `allowed_actions: [...]` populated
  from the enum members + `review_actions: [...]` for high-blast
  members (mass_*, deploy_*, escalate_*).
- **Framework signals section**: framework imports (LangChain et al.)
  surface in a dedicated "Agent frameworks detected" section instead
  of polluting "Best place to wrap first" with non-actionable wrap
  points.
- **Single source-of-truth ranking**: START_HERE / SUMMARY / FULL_REPORT
  agree on the top wrap target. Narrator's bucketing now uses the
  same `finding_wrap_rank` as `summary.build_summary`.

### DX — operations

- **`.supervisor-ignore`**: gitignore-shaped file at repo root that
  suppresses findings the dev triaged. Suppressed findings move from
  the priority list to a dedicated "Suppressed" section in
  FULL_REPORT.md with reason + reviewer + date for audit.
- **Stable finding IDs**: every finding carries an `id` (12-char hash
  of scanner + relative path + line + normalized snippet). Survives
  reformatting, comment edits, and repo move-to-different-parent.
- **`findings.json` schema bump** to `"schema_version": "1.0"`.
- **`supervisor-discover diff` subcommand** — compare two
  findings.json files; prints added / removed / severity-changed
  blocks grouped by confidence.
- **`scan --fail-on={any,new-low,new-medium,new-high,never}`** — CI
  gate. Exit 3 with a one-line reason when the budget is exceeded.
  Designed for PR gating: a PR that introduces a new high-confidence
  wrap site without justification fails the build.
- **Stale stub detection**: each stub embeds its finding's
  `stable_id`. On re-scan, stubs whose id no longer matches a current
  finding get renamed to `*.stale.stub.{py,ts}` so the dev sees
  what's pointing at moved/deleted code.
- **Orphan stub filter**: stubs aren't emitted for findings whose
  source file no longer exists.
- **New combos**: `llm-plus-payment` (critical), `llm-plus-account-change`
  (high). Closes the gap on supervincent's Anthropic + Stripe + user
  table writes that no combo previously caught.

### Tests

352 passing (from 124 in 0.3.1). New test modules:
`test_bootstrap.py`, `test_dangerous_patterns.py`, `test_diff.py`,
`test_pipeline_orchestrator.py`, `test_policy_extractors.py`,
`test_reachability_and_noise.py`, `test_stale_stubs.py`,
`test_suppression.py`, `test_taint.py`, `test_wrap_signature.py`,
`test_agent_graph.py`, `test_derived_combos.py`, `test_gate_coverage.py`.

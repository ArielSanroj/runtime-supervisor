#!/usr/bin/env bash
set -u

ROOT="${ROOT:-$PWD}"
WORKDIR="${BENCHMARK_WORKDIR:-$ROOT/.vibefixing-benchmark}"
REPOS_DIR="$WORKDIR/repos"
OUT_DIR="$WORKDIR/results"
LOG_DIR="$WORKDIR/logs"
SUMMARY="$WORKDIR/BENCHMARK_SUMMARY.md"
SCANNER="${SCANNER:-$ROOT/.venv/bin/supervisor-discover}"

mkdir -p "$REPOS_DIR" "$OUT_DIR" "$LOG_DIR"

if [[ ! -x "$SCANNER" ]]; then
  if command -v supervisor-discover >/dev/null 2>&1; then
    SCANNER="$(command -v supervisor-discover)"
  else
    echo "error: supervisor-discover not found. Set SCANNER=/path/to/supervisor-discover" >&2
    exit 127
  fi
fi

repos=(
  "AutoGPT|https://github.com/Significant-Gravitas/AutoGPT"
  "fastapi-realworld|https://github.com/nsidnev/fastapi-realworld-example-app"
  "nextjs-subscription-payments|https://github.com/vercel/nextjs-subscription-payments"
  "open-interpreter|https://github.com/OpenInterpreter/open-interpreter"
  "supabase|https://github.com/supabase/supabase"
  "medusa|https://github.com/medusajs/medusa"
  "chatwoot|https://github.com/chatwoot/chatwoot"
  "erpnext|https://github.com/frappe/erpnext"
  "cal-diy|https://github.com/calcom/cal.com"
  "langchain-ariel|https://github.com/ArielSanroj/langchain"
)

cat > "$SUMMARY" <<'MD'
# Vibefixing scanner benchmark

Goal: test `supervisor-discover scan` across different repo types and identify what the web/app should show after scan.

## Results

| Repo | Clone | Scan | Elapsed | Findings | Priority | Key files |
|---|---:|---:|---:|---:|---:|---|
MD

json_value() {
  local file="$1"
  local expr="$2"
  PYTHONPATH="$ROOT/packages/supervisor-discover/src${PYTHONPATH:+:$PYTHONPATH}" python3 - "$file" "$expr" <<'PY'
import json
import sys
from pathlib import Path

from supervisor_discover.classifier import tier_of
from supervisor_discover.findings import Finding

path = Path(sys.argv[1])
expr = sys.argv[2]
try:
    payload = json.loads(path.read_text())
except Exception:
    print("n/a")
    raise SystemExit(0)

findings = payload.get("findings") or []
summary = payload.get("repo_summary") or {}
if expr == "findings":
    print(len(findings))
elif expr == "priority":
    total = 0
    for item in findings:
        try:
            finding = Finding(
                scanner=item["scanner"],
                file=item["file"],
                line=item["line"],
                snippet=item["snippet"],
                suggested_action_type=item["suggested_action_type"],
                confidence=item["confidence"],
                rationale=item["rationale"],
                extra=item.get("extra") or {},
                id=item.get("id") or "",
            )
        except Exception:
            continue
        if tier_of(finding) != "general":
            total += 1
    print(total)
elif expr == "one_liner":
    print((summary.get("one_liner") or "").replace("\n", " ")[:160])
else:
    print("n/a")
PY
}

key_files_for() {
  local result_dir="$1"
  local files=()
  for rel in START_HERE.md FULL_REPORT.md ROLLOUT.md findings.json combos/README.md; do
    if [[ -f "$result_dir/$rel" ]]; then
      files+=("[$rel]($result_dir/$rel)")
    fi
  done
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "none"
  else
    local joined="${files[0]}"
    local i
    for ((i=1; i<${#files[@]}; i++)); do
      joined+=", ${files[$i]}"
    done
    echo "$joined"
  fi
}

clone_repo() {
  local name="$1"
  local url="$2"
  local repo_dir="$REPOS_DIR/$name"
  local log="$LOG_DIR/$name.clone.log"

  if [[ -d "$repo_dir/.git" ]]; then
    git -C "$repo_dir" pull --ff-only --depth=1 >"$log" 2>&1
  else
    GIT_LFS_SKIP_SMUDGE=1 git clone --depth=1 "$url" "$repo_dir" >"$log" 2>&1
  fi
}

scan_repo() {
  local name="$1"
  local repo_dir="$REPOS_DIR/$name"
  local result_dir="$OUT_DIR/$name"
  local stdout_log="$LOG_DIR/$name.scan.stdout.log"
  local stderr_log="$LOG_DIR/$name.scan.stderr.log"

  rm -rf "$result_dir"
  mkdir -p "$result_dir"
  "$SCANNER" scan \
    --path "$repo_dir" \
    --out "$result_dir" \
    --no-prompt \
    --level 1 \
    >"$stdout_log" 2>"$stderr_log"
}

for item in "${repos[@]}"; do
  IFS='|' read -r name url <<< "$item"
  repo_dir="$REPOS_DIR/$name"
  result_dir="$OUT_DIR/$name"

  printf '[%s] clone/update %s\n' "$name" "$url" >&2
  clone_start="$(date +%s)"
  clone_repo "$name" "$url"
  clone_code=$?

  scan_code="n/a"
  elapsed="n/a"
  findings="n/a"
  priority="n/a"

  if [[ "$clone_code" -eq 0 ]]; then
    printf '[%s] scan\n' "$name" >&2
    scan_start="$(date +%s)"
    scan_repo "$name"
    scan_code=$?
    scan_end="$(date +%s)"
    elapsed="$((scan_end - scan_start))s"

    if [[ -f "$result_dir/findings.json" ]]; then
      findings="$(json_value "$result_dir/findings.json" findings)"
      priority="$(json_value "$result_dir/findings.json" priority)"
    fi
  fi

  key_files="$(key_files_for "$result_dir")"
  printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
    "$name" "$clone_code" "$scan_code" "$elapsed" "$findings" "$priority" "$key_files" >> "$SUMMARY"
done

cat >> "$SUMMARY" <<MD

## Logs

Raw clone and scan logs are in \`$LOG_DIR\`.
MD

printf 'summary: %s\n' "$SUMMARY" >&2

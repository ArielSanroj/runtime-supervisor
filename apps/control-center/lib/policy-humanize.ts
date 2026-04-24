/**
 * Minimal YAML parser for the narrow policy schema we own.
 *
 * Policies follow a strict shape in `runtime-supervisor/policies/*.yaml`:
 *   name, version, description, rules: [ { id, when, action, reason, explanation } ].
 * We don't need a full YAML parser for that — a tiny regex-based splitter that
 * handles quoted strings and folded `>` blocks covers every rule file in the
 * repo and keeps the frontend bundle small.
 */
export type PolicyRule = {
  id: string;
  when: string;
  action: "allow" | "deny" | "review";
  reason: string;
  explanation: string;
};

export function parsePolicyRules(yaml: string): PolicyRule[] {
  const rulesIdx = yaml.indexOf("\nrules:");
  if (rulesIdx === -1) return [];
  const rulesSection = yaml.slice(rulesIdx + 1);
  const blocks = splitRuleBlocks(rulesSection);
  return blocks.map(parseBlock).filter((r): r is PolicyRule => r !== null);
}

function splitRuleBlocks(section: string): string[] {
  const lines = section.split("\n");
  const blocks: string[] = [];
  let current: string[] = [];
  for (const line of lines) {
    if (/^\s*-\s+id:/.test(line)) {
      if (current.length > 0) blocks.push(current.join("\n"));
      current = [line];
    } else if (current.length > 0) {
      if (/^\S/.test(line) && !line.startsWith(" ")) break;
      current.push(line);
    }
  }
  if (current.length > 0) blocks.push(current.join("\n"));
  return blocks;
}

function parseBlock(block: string): PolicyRule | null {
  const id = extractScalar(block, "id");
  const when = extractScalar(block, "when");
  const action = extractScalar(block, "action");
  const reason = extractScalar(block, "reason");
  const explanation = extractFolded(block, "explanation");
  if (!id || !action) return null;
  if (action !== "allow" && action !== "deny" && action !== "review") return null;
  return { id, when: when ?? "", action, reason: reason ?? "", explanation: explanation ?? "" };
}

function extractScalar(block: string, key: string): string | null {
  const re = new RegExp(`(?:^|\\n)\\s*(?:-\\s*)?${key}:\\s*(.+)`);
  const match = block.match(re);
  if (!match) return null;
  let raw = match[1].trim();
  if (raw === ">" || raw === "|") return null;
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    raw = raw.slice(1, -1);
  }
  return raw;
}

function extractFolded(block: string, key: string): string | null {
  const re = new RegExp(`\\n\\s*${key}:\\s*>\\s*\\n([\\s\\S]*?)(?=\\n\\s*(?:-\\s)|\\n\\s*\\w+:\\s|$)`);
  const match = block.match(re);
  if (!match) {
    const scalar = extractScalar(block, key);
    return scalar;
  }
  return match[1]
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .join(" ");
}

/**
 * Human-readable bullet for a rule — leads with the id titleized so the
 * reviewer sees the intent before the YAML expression.
 */
export function humanizeRule(rule: PolicyRule): string {
  const title = titleize(rule.id);
  if (rule.reason && rule.reason !== rule.id) {
    return `${title} — ${humanizePhrase(rule.reason)}`;
  }
  return title;
}

function titleize(slug: string): string {
  return slug
    .split(/[-_]/)
    .filter(Boolean)
    .map((part, i) => (i === 0 ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

function humanizePhrase(slug: string): string {
  return slug.split(/[-_]/).filter(Boolean).join(" ");
}

export type RuleGroups = {
  deny: PolicyRule[];
  review: PolicyRule[];
  allow: PolicyRule[];
};

export function groupRules(rules: PolicyRule[]): RuleGroups {
  const out: RuleGroups = { deny: [], review: [], allow: [] };
  for (const r of rules) out[r.action].push(r);
  return out;
}

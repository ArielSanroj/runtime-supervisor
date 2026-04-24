import { groupRules, humanizeRule, parsePolicyRules } from "@/lib/policy-humanize";

/**
 * Human-first view of a policy: what it blocks, what it sends to review.
 * Sits above the YAML source so reviewers see the intent before the syntax.
 *
 * Derived from the YAML — no drift risk. If parsing fails (malformed YAML,
 * unknown shape) the component renders nothing and the raw YAML below is
 * still visible.
 */
export default function PolicyHumanView({ yamlSource }: { yamlSource: string }) {
  const rules = parsePolicyRules(yamlSource);
  if (rules.length === 0) return null;
  const groups = groupRules(rules);

  return (
    <section className="card" style={{ marginBottom: 16 }}>
      <h2 style={{ marginTop: 0 }}>What this policy does</h2>
      {groups.deny.length > 0 && (
        <Group tone="rejected" label="Blocks" rules={groups.deny} />
      )}
      {groups.review.length > 0 && (
        <Group tone="pending" label="Needs review" rules={groups.review} />
      )}
      {groups.allow.length > 0 && (
        <Group tone="approved" label="Explicitly allows" rules={groups.allow} />
      )}
    </section>
  );
}

function Group({
  tone,
  label,
  rules,
}: {
  tone: "approved" | "rejected" | "pending";
  label: string;
  rules: ReturnType<typeof parsePolicyRules>;
}) {
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row" style={{ gap: 8, marginBottom: 8 }}>
        <span className={`badge ${tone}`}>{label}</span>
        <span className="muted mono" style={{ fontSize: 12 }}>
          {rules.length} rule{rules.length === 1 ? "" : "s"}
        </span>
      </div>
      <ul style={{ margin: 0, paddingLeft: 20 }}>
        {rules.map((r) => (
          <li key={r.id} style={{ marginBottom: 6 }}>
            <strong>{humanizeRule(r)}</strong>
            {r.explanation && (
              <div className="muted" style={{ fontSize: 13, marginTop: 2 }}>
                {r.explanation}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

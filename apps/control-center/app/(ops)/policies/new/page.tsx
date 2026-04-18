import NewPolicyForm from "./NewPolicyForm";

export default function NewPolicyPage() {
  return (
    <div>
      <h1>New policy</h1>
      <p className="muted" style={{ marginBottom: 16 }}>
        Write a policy in YAML, test it against a sample payload, then save as draft or save &amp; promote.
      </p>
      <NewPolicyForm />
    </div>
  );
}

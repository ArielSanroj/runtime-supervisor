import NewIntegrationForm from "./NewIntegrationForm";

export default function NewIntegrationPage() {
  return (
    <div>
      <h1>New integration</h1>
      <p className="muted" style={{ marginBottom: 16 }}>
        Register an external app. The generated shared secret is shown <strong>once</strong> — copy it now and store it securely.
      </p>
      <NewIntegrationForm />
    </div>
  );
}

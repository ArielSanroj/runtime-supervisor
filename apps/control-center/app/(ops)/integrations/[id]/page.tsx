import { integrationsApi, type ActionExecution, type WebhookSubscription } from "@/lib/integrations";
import ExecuteConfigForm from "./ExecuteConfigForm";
import ExecutionsPanel from "./ExecutionsPanel";
import IntegrationActions from "./IntegrationActions";
import WebhooksPanel from "./WebhooksPanel";

export const dynamic = "force-dynamic";

export default async function IntegrationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const integ = await integrationsApi.get(id);
  let webhooks: WebhookSubscription[] = [];
  let executions: ActionExecution[] = [];
  try {
    [webhooks, executions] = await Promise.all([
      integrationsApi.listWebhooks(id),
      integrationsApi.listExecutions(id, 50),
    ]);
  } catch {
    webhooks = [];
    executions = [];
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1 style={{ margin: 0 }}>{integ.name}</h1>
        {integ.active ? (
          <span className="badge approved">active</span>
        ) : (
          <span className="badge rejected">revoked</span>
        )}
      </div>
      <div className="row" style={{ gap: 12, marginTop: 8, marginBottom: 16 }}>
        <span className="muted mono">id {integ.id}</span>
        <span className="muted mono">scopes [{(integ.scopes || []).join(", ")}]</span>
        <span className="muted mono">created {new Date(integ.created_at).toLocaleString()}</span>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <h2>Execute config (action_proxy)</h2>
          <p className="muted" style={{ marginBottom: 8 }}>
            When a decision is <code>allow</code> or an approved review fires, the supervisor POSTs the action
            payload + decision to this URL (HMAC-signed with <code>WEBHOOK_SECRET</code>).
          </p>
          <ExecuteConfigForm id={integ.id} initialUrl={integ.execute_url ?? ""} initialMethod={integ.execute_method ?? "POST"} />
        </div>

        <div className="card">
          <h2>Lifecycle</h2>
          <IntegrationActions id={integ.id} active={integ.active} />
        </div>
      </div>

      <h2>Recent executions (action_proxy)</h2>
      <ExecutionsPanel rows={executions} />

      <h2>Webhook subscriptions</h2>
      <WebhooksPanel id={integ.id} initial={webhooks} />
    </div>
  );
}

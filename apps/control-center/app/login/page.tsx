import LoginForm from "./LoginForm";

export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const sp = await searchParams;
  const next = sp.next ?? "/dashboard";
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "80vh" }}>
      <div className="card" style={{ width: 420 }}>
        <h1 style={{ marginTop: 0 }}>Sign in</h1>
        <p className="muted" style={{ marginBottom: 16 }}>Agentic Internal Controls — ops console</p>
        <LoginForm next={next} />
      </div>
    </div>
  );
}

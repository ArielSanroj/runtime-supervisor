import { getRepoCombos } from "@/lib/repos";
import CombosList from "@/app/scan/CombosList";

export const dynamic = "force-dynamic";

export default async function RepoCombosPage({
  params,
}: {
  params: Promise<{ repo_id: string }>;
}) {
  const { repo_id } = await params;
  const combos = await getRepoCombos(repo_id);

  if (combos.length === 0) {
    return (
      <div className="card" style={{ padding: 24 }}>
        <h2 style={{ marginTop: 0 }}>No combos detected</h2>
        <p className="muted" style={{ marginTop: 8 }}>
          The scanner didn&apos;t find any capability pairs that amplify risk together. That&apos;s
          good — but the individual findings in the Findings tab still need gates.
        </p>
      </div>
    );
  }

  return <CombosList combos={combos} />;
}

import OnboardClient from "./OnboardClient";

export const dynamic = "force-dynamic";

export default async function OnboardPage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;
  return <OnboardClient token={token} />;
}

import { Client, SupervisorError } from "../src/client.js";

const { SUPERVISOR_URL, SUPERVISOR_APP_ID, SUPERVISOR_SECRET } = process.env;
if (!SUPERVISOR_URL || !SUPERVISOR_APP_ID || !SUPERVISOR_SECRET) {
  console.error("set SUPERVISOR_URL, SUPERVISOR_APP_ID, SUPERVISOR_SECRET");
  process.exit(1);
}

const client = new Client({
  baseUrl: SUPERVISOR_URL,
  appId: SUPERVISOR_APP_ID,
  sharedSecret: SUPERVISOR_SECRET,
});

try {
  const types = await client.listActionTypes();
  console.log(`[1/3] action-types: ${types.map((t) => t.id).join(", ")}`);

  const small = await client.evaluate("payment", {
    amount: 50,
    currency: "USD",
    customer_id: "smoke-test",
  });
  console.log(`[2/3] small payment → ${small.decision} (risk=${small.risk_score})`);

  const big = await client.evaluate("payment", {
    amount: 999999,
    currency: "USD",
    customer_id: "smoke-test",
  });
  console.log(
    `[3/3] large payment → ${big.decision} (reasons: ${big.reasons.join("; ") || "none"})`,
  );

  if (small.decision !== "allow") {
    console.error("FAIL — small payment should have been allowed.");
    process.exit(2);
  }
  if (big.decision === "allow") {
    console.error("FAIL — large payment allowed; policy cap not enforced.");
    process.exit(3);
  }
  console.log("OK — supervisor URL, auth, and policy enforcement all live.");
} catch (err) {
  if (err instanceof SupervisorError) {
    console.error(`supervisor error ${err.statusCode}: ${err.detail}`);
  } else {
    console.error(err);
  }
  process.exit(10);
}

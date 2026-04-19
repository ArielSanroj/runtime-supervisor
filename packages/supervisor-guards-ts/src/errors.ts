export class SupervisorBlocked extends Error {
  constructor(
    public decision: "deny" | "review",
    public reasons: string[],
    public actionId?: string,
    public threats: Array<Record<string, unknown>> = [],
  ) {
    super(`supervisor ${decision}: ${reasons.join(", ") || "(no reasons)"}`);
    this.name = "SupervisorBlocked";
  }
}

export class SupervisorReviewPending extends Error {
  constructor(public actionId: string, public reasons: string[]) {
    super(`review pending for action ${actionId}: ${reasons.join(", ")}`);
    this.name = "SupervisorReviewPending";
  }
}

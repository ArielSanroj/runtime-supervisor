import Stripe from "stripe";
import { stripe } from "@/utils/stripe/config";
import { manageSubscriptionStatusChange } from "@/utils/supabase/admin";

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature") as string;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;
  const event = stripe.webhooks.constructEvent(body, sig, webhookSecret);

  if (event.type === "customer.subscription.updated") {
    const subscription = event.data.object as Stripe.Subscription;
    await manageSubscriptionStatusChange(
      subscription.id,
      subscription.customer as string,
      false,
    );
  }
  return new Response(JSON.stringify({ received: true }));
}

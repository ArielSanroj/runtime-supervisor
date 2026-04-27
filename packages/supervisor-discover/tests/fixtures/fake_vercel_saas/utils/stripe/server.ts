"use server";

import { stripe } from "@/utils/stripe/config";

export async function checkoutWithStripe(priceId: string) {
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: "https://example.com/account",
    cancel_url: "https://example.com/",
  });
  return session.id;
}

export async function createPortalSession(customerId: string) {
  const { url } = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: "https://example.com/account",
  });
  return url;
}

export async function cancelSubscription(subscriptionId: string) {
  return stripe.subscriptions.cancel(subscriptionId);
}

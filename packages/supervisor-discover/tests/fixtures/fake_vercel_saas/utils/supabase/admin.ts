import { createClient } from "@supabase/supabase-js";
import type Stripe from "stripe";

// Note: supabaseAdmin uses the SERVICE_ROLE_KEY which has admin privileges
// and bypasses every RLS policy. Server-side only.
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL || "",
  process.env.SUPABASE_SERVICE_ROLE_KEY || "",
);

export const upsertCustomer = async (uuid: string, customerId: string) => {
  await supabaseAdmin
    .from("customers")
    .upsert([{ id: uuid, stripe_customer_id: customerId }]);
};

export const deleteCustomer = async (uuid: string) => {
  await supabaseAdmin.from("customers").delete().eq("id", uuid);
};

export const updateUserBilling = async (uuid: string, address: object) => {
  await supabaseAdmin
    .from("users")
    .update({ billing_address: address })
    .eq("id", uuid);
};

export const manageSubscriptionStatusChange = async (
  subscriptionId: string,
  customerId: string,
  isNew: boolean,
) => {
  await supabaseAdmin
    .from("subscriptions")
    .upsert([{ id: subscriptionId, customer_id: customerId, is_new: isNew }]);
};

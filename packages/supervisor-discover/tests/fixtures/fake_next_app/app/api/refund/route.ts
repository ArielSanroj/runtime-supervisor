import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_KEY!);

export async function POST(request: Request) {
  const { amount, charge } = await request.json();
  const result = await stripe.refunds.create({ amount, charge });
  return Response.json(result);
}

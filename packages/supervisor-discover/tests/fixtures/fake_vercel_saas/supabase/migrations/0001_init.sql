-- USERS: RLS enabled with two policies → fully gated, no finding expected.
create table users (
  id uuid primary key,
  full_name text,
  billing_address jsonb
);
alter table users enable row level security;
create policy "Can view own user data." on users for select using (auth.uid() = id);
create policy "Can update own user data." on users for update using (auth.uid() = id);

-- CUSTOMERS: RLS enabled but no policy → medium-confidence "rls-no-policy".
create table customers (
  id uuid primary key,
  stripe_customer_id text
);
alter table customers enable row level security;

-- AUDIT_EVENTS: no RLS at all → high-confidence "rls-missing".
create table audit_events (
  id bigserial primary key,
  payload jsonb
);

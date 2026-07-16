create table if not exists products (
  product_id text primary key,
  owner_tenant_id text not null,
  app_id text not null unique,
  name text not null,
  description text not null default '',
  status text not null default 'active' check (status in ('draft','active','retired')),
  editions_json jsonb not null default '[]'::jsonb,
  capabilities_json jsonb not null default '[]'::jsonb,
  default_policy_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists customers (
  customer_id text primary key,
  owner_tenant_id text not null,
  company_name text not null,
  contacts_json jsonb not null default '[]'::jsonb,
  notes text not null default '',
  status text not null default 'active' check (status in ('active','suspended','archived')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists core_instances (
  instance_id text primary key,
  owner_tenant_id text not null,
  customer_id text not null references customers(customer_id),
  platform_instance_id text not null unique,
  public_identity_json jsonb not null default '{}'::jsonb,
  callback_url text,
  activation_status text not null default 'registered',
  last_activation_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists commercial_grants (
  grant_id text primary key,
  owner_tenant_id text not null,
  customer_id text not null references customers(customer_id),
  product_id text not null references products(product_id),
  edition text not null,
  capabilities_json jsonb not null default '{}'::jsonb,
  limits_json jsonb not null default '{}'::jsonb,
  maintenance_until timestamptz,
  subscription_until timestamptz,
  offline_allowed boolean not null default false,
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  status text not null default 'draft' check (status in ('draft','active','suspended','expired','revoked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists activation_requests (
  activation_id text primary key,
  owner_tenant_id text not null,
  grant_id text references commercial_grants(grant_id),
  instance_id text references core_instances(instance_id),
  platform_instance_id text,
  tenant_id text not null,
  app_id text not null,
  license_mode text not null check (license_mode in ('portable','instance_bound')),
  channel text not null check (channel in ('online','offline')),
  request_json jsonb not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected','completed','failed')),
  decision_reason text,
  requested_at timestamptz not null default now(),
  decided_at timestamptz,
  decided_by text,
  completed_at timestamptz
);

create table if not exists issued_licenses (
  license_id text primary key,
  serial_number text not null unique,
  owner_tenant_id text not null,
  grant_id text not null references commercial_grants(grant_id),
  activation_id text references activation_requests(activation_id),
  instance_id text references core_instances(instance_id),
  tenant_id text not null,
  jti text not null unique,
  license_jws text not null,
  bundle_json jsonb not null,
  claims_json jsonb not null,
  issued_at timestamptz not null default now(),
  expires_at timestamptz,
  replaces_license_id text references issued_licenses(license_id),
  status text not null default 'active' check (status in ('active','suspended','expired','replaced','revoked')),
  revoked_at timestamptz,
  revoke_reason text
);

create table if not exists signing_certificates (
  id uuid primary key default gen_random_uuid(),
  author_id text not null,
  kid text not null,
  author_cert_jws text not null,
  status text not null default 'active',
  imported_at timestamptz not null default now(),
  replaced_at timestamptz
);

create table if not exists issuer_audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_user_id text not null,
  username text not null,
  tenant_id text not null,
  application_id text not null,
  permission_used text not null,
  operation text not null,
  target_type text not null,
  target_id text,
  outcome text not null,
  ip_address text,
  user_agent text,
  correlation_id text not null,
  metadata_json jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_products_owner on products(owner_tenant_id, status);
create index if not exists idx_customers_owner on customers(owner_tenant_id, status);
create index if not exists idx_instances_customer on core_instances(customer_id, revoked_at);
create index if not exists idx_grants_customer_product on commercial_grants(customer_id, product_id, status);
create index if not exists idx_activations_status on activation_requests(owner_tenant_id, status, requested_at desc);
create index if not exists idx_issued_grant on issued_licenses(grant_id, status, issued_at desc);
create index if not exists idx_issuer_audit_created on issuer_audit_log(tenant_id, created_at desc);

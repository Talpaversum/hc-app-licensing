create extension if not exists pgcrypto;

create table if not exists oauth_clients (
  id uuid primary key default gen_random_uuid(),
  client_id text not null unique,
  client_secret_hash text,
  platform_instance_id text,
  client_name text,
  redirect_uris jsonb not null,
  software_statement_iss text,
  status text not null default 'active',
  created_at timestamptz not null default now()
);

create index if not exists idx_oauth_clients_platform_instance_id on oauth_clients(platform_instance_id);

create table if not exists oauth_codes (
  code text primary key,
  client_id text not null references oauth_clients(client_id) on delete cascade,
  redirect_uri text not null,
  code_challenge text,
  code_challenge_method text,
  scope text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz
);

create table if not exists oauth_tokens (
  id uuid primary key default gen_random_uuid(),
  client_id text not null references oauth_clients(client_id) on delete cascade,
  subject_id text,
  tenant_id text,
  scope text,
  access_token_hash text not null,
  refresh_token_hash text,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz
);

create index if not exists idx_oauth_tokens_tenant_client on oauth_tokens(tenant_id, client_id);
create index if not exists idx_oauth_tokens_expires_at on oauth_tokens(expires_at);
create index if not exists idx_oauth_tokens_revoked_at on oauth_tokens(revoked_at);
create unique index if not exists uq_oauth_tokens_access_token_hash on oauth_tokens(access_token_hash);

create table if not exists license_grants (
  id uuid primary key default gen_random_uuid(),
  jti text not null unique,
  author_id text not null,
  tenant_id text not null,
  platform_instance_id text,
  app_id text not null,
  license_mode text not null,
  license_jws text not null,
  issued_at timestamptz not null,
  not_before timestamptz not null,
  expires_at timestamptz not null,
  status text not null default 'active',
  revoked_at timestamptz,
  customer_ref text,
  features_json jsonb,
  limits_json jsonb
);

create index if not exists idx_license_grants_tenant_app_status on license_grants(tenant_id, app_id, status);
create index if not exists idx_license_grants_platform_instance_id on license_grants(platform_instance_id);
create index if not exists idx_license_grants_expires_at on license_grants(expires_at);

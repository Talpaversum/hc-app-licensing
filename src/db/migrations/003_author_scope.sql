do $$
declare
  table_name text;
begin
  foreach table_name in array array[
    'products', 'customers', 'core_instances', 'commercial_grants',
    'activation_requests', 'issued_licenses', 'issuer_audit_log'
  ] loop
    execute format('alter table %I add column if not exists author_id text', table_name);
    execute format(
      'update %I set author_id=coalesce(author_id, nullif(current_setting(''hc.author_id'', true), ''''), ''legacy-unscoped'') where author_id is null',
      table_name
    );
    execute format('alter table %I alter column author_id set not null', table_name);
  end loop;
end $$;

alter table products drop constraint if exists products_app_id_key;
create unique index if not exists uq_products_author_app on products(author_id, app_id);
create unique index if not exists uq_products_author_id on products(author_id, product_id);
create unique index if not exists uq_customers_author_id on customers(author_id, customer_id);
create unique index if not exists uq_instances_author_id on core_instances(author_id, instance_id);
create unique index if not exists uq_grants_author_id on commercial_grants(author_id, grant_id);
create unique index if not exists uq_activations_author_id on activation_requests(author_id, activation_id);
create unique index if not exists uq_licenses_author_id on issued_licenses(author_id, license_id);

do $$
begin
  if not exists (select 1 from pg_constraint where conname='fk_instances_author_customer') then
    alter table core_instances add constraint fk_instances_author_customer foreign key(author_id, customer_id) references customers(author_id, customer_id);
  end if;
  if not exists (select 1 from pg_constraint where conname='fk_grants_author_customer') then
    alter table commercial_grants add constraint fk_grants_author_customer foreign key(author_id, customer_id) references customers(author_id, customer_id);
  end if;
  if not exists (select 1 from pg_constraint where conname='fk_grants_author_product') then
    alter table commercial_grants add constraint fk_grants_author_product foreign key(author_id, product_id) references products(author_id, product_id);
  end if;
  if not exists (select 1 from pg_constraint where conname='fk_activations_author_grant') then
    alter table activation_requests add constraint fk_activations_author_grant foreign key(author_id, grant_id) references commercial_grants(author_id, grant_id);
  end if;
  if not exists (select 1 from pg_constraint where conname='fk_licenses_author_grant') then
    alter table issued_licenses add constraint fk_licenses_author_grant foreign key(author_id, grant_id) references commercial_grants(author_id, grant_id);
  end if;
end $$;

create table if not exists signing_key_references (
  key_reference text primary key,
  author_id text not null,
  kid text not null,
  provider text not null,
  status text not null default 'active',
  created_at timestamptz not null default now(),
  rotated_at timestamptz,
  unique(author_id, kid)
);

create index if not exists idx_products_author on products(author_id, owner_tenant_id, status);
create index if not exists idx_customers_author on customers(author_id, owner_tenant_id, status);
create index if not exists idx_instances_author on core_instances(author_id, owner_tenant_id, revoked_at);
create index if not exists idx_grants_author on commercial_grants(author_id, owner_tenant_id, status);
create index if not exists idx_activations_author on activation_requests(author_id, owner_tenant_id, status, requested_at desc);
create index if not exists idx_licenses_author on issued_licenses(author_id, owner_tenant_id, status, issued_at desc);
create index if not exists idx_certificates_author on signing_certificates(author_id, status, imported_at desc);
create index if not exists idx_key_references_author on signing_key_references(author_id, status);
create index if not exists idx_audit_author on issuer_audit_log(author_id, tenant_id, created_at desc);

import { randomUUID } from "node:crypto";

import { SignJWT, createLocalJWKSet, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK, type JSONWebKeySet } from "jose";

import { loadConfig } from "./config.js";
import { getPool } from "./db/pool.js";
import { verifyAuthorCertificate, verifyLicenseJwsAgainstAuthorCertificate } from "./issuer-identity.js";

const id = (prefix: string) => `${prefix}_${randomUUID().replace(/-/g, "")}`;

export type ManagementEntity = "products" | "customers" | "instances" | "grants" | "activations" | "licenses" | "audit";

export async function dashboard(tenantId: string) {
  const result = await getPool().query(
    `select
      (select count(*)::int from issued_licenses where owner_tenant_id=$1 and status='active') active_licenses,
      (select count(*)::int from issued_licenses where owner_tenant_id=$1 and status='active' and expires_at < now() + interval '30 days') expiring_licenses,
      (select count(*)::int from activation_requests where owner_tenant_id=$1 and status='failed') failed_activations,
      (select count(*)::int from issued_licenses where owner_tenant_id=$1 and status='revoked') revoked_licenses,
      (select count(*)::int from customers where owner_tenant_id=$1 and status='active') active_customers,
      (select count(*)::int from activation_requests where owner_tenant_id=$1 and status='pending') pending_activations`,
    [tenantId],
  );
  const cfg = loadConfig();
  const key = JSON.parse(cfg.AUTHOR_PRIVATE_JWK_JSON) as JWK;
  const certJws = await activeAuthorCertificate();
  const cert = decodeJwt(certJws);
  return { ...result.rows[0], signing_key_kid: key.kid ?? null, certificate_configured: true,
    certificate_expires_at: typeof cert.exp === "number" ? new Date(cert.exp * 1000).toISOString() : null };
}

export async function activeAuthorCertificate() {
  const found = await getPool().query("select author_cert_jws from signing_certificates where status='active' order by imported_at desc limit 1");
  return found.rowCount ? String(found.rows[0].author_cert_jws) : loadConfig().AUTHOR_CERT_JWS;
}

export async function importAuthorCertificate(authorCertJws: string) {
  const cfg = loadConfig();
  try {
    await verifyAuthorCertificate(authorCertJws, cfg);
  } catch (error) {
    throw Object.assign(error instanceof Error ? error : new Error("Invalid author certificate"), { statusCode: 400 });
  }
  const header = decodeProtectedHeader(authorCertJws);
  const client = await getPool().connect();
  try {
    await client.query("begin");
    await client.query("update signing_certificates set status='replaced',replaced_at=now() where status='active'");
    const result = await client.query(
      "insert into signing_certificates(author_id,kid,author_cert_jws) values($1,$2,$3) returning id,author_id,kid,status,imported_at",
      [cfg.AUTHOR_ID, String(header.kid ?? "unknown"), authorCertJws],
    );
    await client.query("commit"); return result.rows[0];
  } catch (error) { await client.query("rollback"); throw error; } finally { client.release(); }
}

export async function listEntities(entity: ManagementEntity, tenantId: string) {
  const queries: Record<ManagementEntity, string> = {
    products: "select * from products where owner_tenant_id=$1 order by name",
    customers: "select * from customers where owner_tenant_id=$1 order by company_name",
    instances: "select * from core_instances where owner_tenant_id=$1 order by created_at desc",
    grants: `select g.*, p.name product_name, c.company_name customer_name from commercial_grants g
      join products p on p.product_id=g.product_id join customers c on c.customer_id=g.customer_id
      where g.owner_tenant_id=$1 order by g.created_at desc`,
    activations: "select * from activation_requests where owner_tenant_id=$1 order by requested_at desc",
    licenses: `select l.*, p.name product_name, c.company_name customer_name from issued_licenses l
      join commercial_grants g on g.grant_id=l.grant_id join products p on p.product_id=g.product_id
      join customers c on c.customer_id=g.customer_id where l.owner_tenant_id=$1 order by l.issued_at desc`,
    audit: "select * from issuer_audit_log where tenant_id=$1 order by created_at desc limit 500",
  };
  return (await getPool().query(queries[entity], [tenantId])).rows;
}

export async function createProduct(tenantId: string, data: Record<string, unknown>) {
  const productId = id("prd");
  const result = await getPool().query(
    `insert into products (product_id, owner_tenant_id, app_id, name, description, status, editions_json, capabilities_json, default_policy_json)
     values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb) returning *`,
    [productId, tenantId, data["app_id"], data["name"], data["description"] ?? "", data["status"] ?? "active",
      JSON.stringify(data["editions"] ?? []), JSON.stringify(data["capabilities"] ?? []), JSON.stringify(data["default_policy"] ?? {})],
  );
  return result.rows[0];
}

export async function createCustomer(tenantId: string, data: Record<string, unknown>) {
  const customerId = id("cus");
  const result = await getPool().query(
    `insert into customers (customer_id, owner_tenant_id, company_name, contacts_json, notes, status)
     values ($1,$2,$3,$4::jsonb,$5,$6) returning *`,
    [customerId, tenantId, data["company_name"], JSON.stringify(data["contacts"] ?? []), data["notes"] ?? "", data["status"] ?? "active"],
  );
  return result.rows[0];
}

export async function createInstance(tenantId: string, data: Record<string, unknown>) {
  const instanceId = id("ins");
  const result = await getPool().query(
    `insert into core_instances (instance_id, owner_tenant_id, customer_id, platform_instance_id, public_identity_json, callback_url)
     values ($1,$2,$3,$4,$5::jsonb,$6) returning *`,
    [instanceId, tenantId, data["customer_id"], data["platform_instance_id"], JSON.stringify(data["public_identity"] ?? {}), data["callback_url"] ?? null],
  );
  return result.rows[0];
}

export async function createGrant(tenantId: string, data: Record<string, unknown>) {
  const grantId = id("grt");
  const result = await getPool().query(
    `insert into commercial_grants
      (grant_id, owner_tenant_id, customer_id, product_id, edition, capabilities_json, limits_json,
       maintenance_until, subscription_until, offline_allowed, valid_from, valid_until, status)
     values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9,$10,coalesce($11,now()),$12,$13) returning *`,
    [grantId, tenantId, data["customer_id"], data["product_id"], data["edition"],
      JSON.stringify(data["capabilities"] ?? {}), JSON.stringify(data["limits"] ?? {}),
      data["maintenance_until"] ?? null, data["subscription_until"] ?? null, data["offline_allowed"] ?? false,
      data["valid_from"] ?? null, data["valid_until"] ?? null, data["status"] ?? "draft"],
  );
  return result.rows[0];
}

export async function updateEntityStatus(entity: "products" | "customers" | "grants", tenantId: string, entityId: string, status: string) {
  const definitions = {
    products: { table: "products", id: "product_id", allowed: ["draft", "active", "retired"] },
    customers: { table: "customers", id: "customer_id", allowed: ["active", "suspended", "archived"] },
    grants: { table: "commercial_grants", id: "grant_id", allowed: ["draft", "active", "suspended", "expired", "revoked"] },
  } as const;
  const definition = definitions[entity];
  if (!(definition.allowed as readonly string[]).includes(status)) throw Object.assign(new Error("Unsupported status"), { statusCode: 400 });
  const result = await getPool().query(
    `update ${definition.table} set status=$3,updated_at=now() where ${definition.id}=$1 and owner_tenant_id=$2 returning *`,
    [entityId, tenantId, status],
  );
  if (!result.rowCount) throw Object.assign(new Error("Record not found"), { statusCode: 404 });
  return result.rows[0];
}

export async function revokeInstance(tenantId: string, instanceId: string) {
  const result = await getPool().query(
    "update core_instances set revoked_at=now(),activation_status='revoked',updated_at=now() where instance_id=$1 and owner_tenant_id=$2 and revoked_at is null returning *",
    [instanceId, tenantId],
  );
  if (!result.rowCount) throw Object.assign(new Error("Active Core instance not found"), { statusCode: 404 });
  return result.rows[0];
}

export async function createActivation(tenantId: string, data: Record<string, unknown>, channel: "online" | "offline") {
  const activationId = id("act");
  const result = await getPool().query(
    `insert into activation_requests
      (activation_id, owner_tenant_id, grant_id, instance_id, platform_instance_id, tenant_id, app_id, license_mode, channel, request_json)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) returning *`,
    [activationId, tenantId, data["grant_id"] ?? null, data["instance_id"] ?? null, data["platform_instance_id"] ?? null,
      data["tenant_id"], data["app_id"], data["license_mode"], channel, JSON.stringify(data)],
  );
  return result.rows[0];
}

export async function importOfflineActivation(tenantId: string, bundle: Record<string, unknown>) {
  const requestJws = String(bundle["request_jws"] ?? "");
  const publicJwk = bundle["core_public_jwk"] as JWK | undefined;
  if (!requestJws || !publicJwk) throw Object.assign(new Error("Offline request_jws and core_public_jwk are required"), { statusCode: 400 });
  const key = await importJWK(publicJwk, "EdDSA");
  let payload;
  try {
    ({ payload } = await jwtVerify(requestJws, key, { audience: "hc-license-issuer", clockTolerance: 60 }));
  } catch {
    throw Object.assign(new Error("Invalid offline activation request signature"), { statusCode: 400 });
  }
  if (payload["typ"] !== "hc-license-activation-request") throw Object.assign(new Error("Invalid offline activation request type"), { statusCode: 400 });
  const platformInstanceId = String(payload["platform_instance_id"] ?? "");
  const instance = await getPool().query(
    "select instance_id,public_identity_json from core_instances where owner_tenant_id=$1 and platform_instance_id=$2 and revoked_at is null",
    [tenantId, platformInstanceId],
  );
  if (!instance.rowCount) throw Object.assign(new Error("Core instance is not registered"), { statusCode: 403 });
  const registered = instance.rows[0].public_identity_json as Record<string, unknown>;
  if (registered["signing_jwk"] && JSON.stringify(registered["signing_jwk"]) !== JSON.stringify(publicJwk)) {
    throw Object.assign(new Error("Core instance signing key does not match registration"), { statusCode: 403 });
  }
  const productGrant = await getPool().query(
    `select g.grant_id from commercial_grants g join products p on p.product_id=g.product_id
      join core_instances i on i.customer_id=g.customer_id
      where g.owner_tenant_id=$1 and i.instance_id=$2 and p.app_id=$3 and g.status='active'
        and g.offline_allowed=true and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now()) limit 1`,
    [tenantId, instance.rows[0].instance_id, payload["app_id"]],
  );
  if (!productGrant.rowCount) throw Object.assign(new Error("No offline-enabled active grant matches the request"), { statusCode: 403 });
  return createActivation(tenantId, {
    grant_id: productGrant.rows[0].grant_id, instance_id: instance.rows[0].instance_id,
    platform_instance_id: platformInstanceId, tenant_id: payload["tenant_id"], app_id: payload["app_id"],
    license_mode: payload["license_mode"], signed_request: bundle,
  }, "offline");
}

export async function decideActivation(tenantId: string, activationId: string, approved: boolean, userId: string, reason?: string) {
  const result = await getPool().query(
    `update activation_requests set status=$3, decision_reason=$4, decided_at=now(), decided_by=$5
      where activation_id=$1 and owner_tenant_id=$2 and status='pending' returning *`,
    [activationId, tenantId, approved ? "approved" : "rejected", reason ?? null, userId],
  );
  if (!result.rowCount) throw Object.assign(new Error("Pending activation not found"), { statusCode: 404 });
  return result.rows[0];
}

export async function issueApprovedActivation(tenantId: string, activationId: string, replacesLicenseId?: string) {
  const found = await getPool().query(
    `select a.*, g.capabilities_json, g.limits_json, g.valid_until, g.status grant_status, p.app_id product_app_id
       from activation_requests a join commercial_grants g on g.grant_id=a.grant_id
       join products p on p.product_id=g.product_id
      where a.activation_id=$1 and a.owner_tenant_id=$2 and a.status='approved'
        and g.valid_from<=now() and (g.valid_until is null or g.valid_until>now())
        and (g.subscription_until is null or g.subscription_until>now())`,
    [activationId, tenantId],
  );
  if (!found.rowCount) throw Object.assign(new Error("Approved activation with a grant not found"), { statusCode: 409 });
  const row = found.rows[0] as Record<string, unknown>;
  if (row["grant_status"] !== "active" || row["product_app_id"] !== row["app_id"]) {
    throw Object.assign(new Error("Grant is not active for the requested application"), { statusCode: 409 });
  }
  const cfg = loadConfig();
  const now = Math.floor(Date.now() / 1000);
  const configuredExpiration = row["valid_until"] ? Math.floor(new Date(String(row["valid_until"])).getTime() / 1000) : now + 3650 * 86400;
  const jti = id("lic");
  const licenseId = id("isl");
  const serial = `HC-${new Date().getUTCFullYear()}-${randomUUID().slice(0, 8).toUpperCase()}`;
  const mode = String(row["license_mode"]);
  const platformInstanceId = String(row["platform_instance_id"] ?? "");
  const aud = mode === "portable" ? ["*"] : [platformInstanceId];
  const privateJwk = JSON.parse(cfg.AUTHOR_PRIVATE_JWK_JSON) as JWK;
  const key = await importJWK(privateJwk, "EdDSA");
  const claims = {
    typ: "hc-license", v: 1, serial_number: serial,
    subject: { scope_type: "tenant", tenant_id: row["tenant_id"] },
    app: { app_id: row["app_id"] }, license_mode: mode,
    features: row["capabilities_json"] ?? {}, limits: row["limits_json"] ?? {}, grant_id: row["grant_id"],
  };
  const licenseJws = await new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: privateJwk.kid })
    .setIssuer(cfg.AUTHOR_ID).setJti(jti).setAudience(aud).setIssuedAt(now).setNotBefore(now)
    .setExpirationTime(configuredExpiration).sign(key);
  const authorCertJws = await activeAuthorCertificate();
  await verifyLicenseJwsAgainstAuthorCertificate(licenseJws, authorCertJws, cfg);
  const bundle = { bundle_typ: "hc-license-bundle", v: 1, license_jws: licenseJws, author_cert_jws: authorCertJws };
  const client = await getPool().connect();
  try {
    await client.query("begin");
    await client.query(
      `insert into issued_licenses
        (license_id, serial_number, owner_tenant_id, grant_id, activation_id, instance_id, tenant_id, jti,
         license_jws, bundle_json, claims_json, expires_at, replaces_license_id)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,to_timestamp($12),$13)`,
      [licenseId, serial, tenantId, row["grant_id"], activationId, row["instance_id"], row["tenant_id"], jti,
        licenseJws, JSON.stringify(bundle), JSON.stringify(claims), configuredExpiration, replacesLicenseId ?? null],
    );
    await client.query("update activation_requests set status='completed', completed_at=now() where activation_id=$1", [activationId]);
    if (replacesLicenseId) await client.query("update issued_licenses set status='replaced' where license_id=$1 and owner_tenant_id=$2", [replacesLicenseId, tenantId]);
    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
  return { license_id: licenseId, license_jws: licenseJws, author_cert_jws: authorCertJws, bundle };
}

export async function setLicenseStatus(tenantId: string, licenseId: string, status: "suspended" | "revoked", reason?: string) {
  const result = await getPool().query(
    `update issued_licenses set status=$3, revoked_at=case when $3='revoked' then now() else revoked_at end,
       revoke_reason=case when $3='revoked' then $4 else revoke_reason end
     where license_id=$1 and owner_tenant_id=$2 and status in ('active','suspended') returning *`,
    [licenseId, tenantId, status, reason ?? null],
  );
  if (!result.rowCount) throw Object.assign(new Error("Active license not found"), { statusCode: 404 });
  return result.rows[0];
}

export async function renewLicense(tenantId: string, licenseId: string, decidedBy: string) {
  const current = await getPool().query(
    `select l.*,g.product_id,p.app_id,a.platform_instance_id from issued_licenses l join commercial_grants g on g.grant_id=l.grant_id
      join products p on p.product_id=g.product_id left join activation_requests a on a.activation_id=l.activation_id
      where l.license_id=$1 and l.owner_tenant_id=$2 and l.status in ('active','suspended')`,
    [licenseId, tenantId],
  );
  if (!current.rowCount) throw Object.assign(new Error("Renewable license not found"), { statusCode: 404 });
  const row = current.rows[0];
  const activation = await createActivation(tenantId, {
    grant_id: row.grant_id, instance_id: row.instance_id, tenant_id: row.tenant_id,
    app_id: row.app_id, license_mode: row.claims_json.license_mode,
    platform_instance_id: row.platform_instance_id,
    renewal_of: licenseId,
  }, "offline");
  await decideActivation(tenantId, String(activation.activation_id), true, decidedBy, "License renewal");
  return issueApprovedActivation(tenantId, String(activation.activation_id), licenseId);
}

export async function licenseRevocations() {
  const rows = (await getPool().query(
    "select jti, revoked_at, revoke_reason from issued_licenses where status='revoked' order by revoked_at desc",
  )).rows;
  return { version: 1, updated_at: new Date().toISOString(), revoked_license_jtis: rows.map((row) => ({ jti: row.jti, revoked_at: row.revoked_at, reason: row.revoke_reason })) };
}

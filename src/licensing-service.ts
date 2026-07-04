import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SignJWT, createLocalJWKSet, importJWK, jwtVerify, type JWK, type JSONWebKeySet } from "jose";

import { loadConfig } from "./config.js";
import { getPool } from "./db/pool.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

export function discoveryMetadata() {
  const cfg = loadConfig();
  const backchannelBaseUrl = cfg.BACKCHANNEL_BASE_URL ?? cfg.ISSUER_BASE_URL;
  return {
    issuer: cfg.ISSUER_BASE_URL,
    author_id: cfg.AUTHOR_ID,
    authorization_endpoint: `${cfg.ISSUER_BASE_URL}/oauth/authorize`,
    token_endpoint: `${backchannelBaseUrl}/oauth/token`,
    registration_endpoint: `${backchannelBaseUrl}/oauth/register`,
    license_issue_endpoint: `${backchannelBaseUrl}/v1/licenses/issue`,
  };
}

function hashSecret(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

type SoftwareStatementClaims = {
  platform_instance_id?: string;
  iss?: string;
};

export async function registerOAuthClient(payload: { software_statement: string; redirect_uris: string[] }) {
  const cfg = loadConfig();
  const trusted = JSON.parse(cfg.DCR_TRUSTED_CORE_JWKS_JSON) as JSONWebKeySet;
  const trustedSet = createLocalJWKSet(trusted);
  const verified = await jwtVerify(payload.software_statement, trustedSet, { clockTolerance: 60 });
  const claims = verified.payload as SoftwareStatementClaims;
  const platformInstanceId = typeof claims.platform_instance_id === "string" ? claims.platform_instance_id : null;
  const softwareStatementIss = typeof claims.iss === "string" ? claims.iss : null;

  const clientId = `cl_${randomUUID().replace(/-/g, "")}`;
  const clientSecret = `cs_${randomUUID().replace(/-/g, "")}`;
  await getPool().query(
    `insert into oauth_clients (
      client_id,
      client_secret_hash,
      platform_instance_id,
      client_name,
      redirect_uris,
      software_statement_iss,
      status
    ) values ($1,$2,$3,$4,$5::jsonb,$6,'active')`,
    [
      clientId,
      hashSecret(clientSecret),
      platformInstanceId,
      "Hekatoncheiros Core",
      JSON.stringify(payload.redirect_uris),
      softwareStatementIss,
    ],
  );

  return { client_id: clientId, client_secret: clientSecret };
}

export async function issueAuthorizationCode(payload: {
  client_id: string;
  redirect_uri: string;
  scope?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}) {
  const code = `code_${randomUUID().replace(/-/g, "")}`;
  await getPool().query(
    `insert into oauth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at)
     values ($1,$2,$3,$4,$5,$6, now() + interval '10 minutes')`,
    [code, payload.client_id, payload.redirect_uri, payload.code_challenge ?? null, payload.code_challenge_method ?? null, payload.scope ?? null],
  );
  return { code };
}

export async function exchangeAuthorizationCode(payload: {
  code: string;
  client_id: string;
  client_secret?: string;
  code_verifier?: string;
}) {
  const pool = getPool();
  const found = await pool.query(
    `select c.code, c.client_id, c.code_challenge, c.code_challenge_method, c.scope, c.expires_at, c.used_at, cl.client_secret_hash
     from oauth_codes c
     join oauth_clients cl on cl.client_id = c.client_id
     where c.code = $1 and c.client_id = $2
     limit 1`,
    [payload.code, payload.client_id],
  );
  if ((found.rowCount ?? 0) === 0) {
    throw new Error("invalid_grant");
  }
  const row = found.rows[0] as Record<string, unknown>;
  if (row["used_at"]) {
    throw new Error("invalid_grant");
  }
  if (new Date(String(row["expires_at"])).getTime() < Date.now()) {
    throw new Error("invalid_grant");
  }

  const secretHash = String(row["client_secret_hash"] ?? "");
  if (secretHash && hashSecret(payload.client_secret ?? "") !== secretHash) {
    throw new Error("invalid_client");
  }

  const challenge = row["code_challenge"] ? String(row["code_challenge"]) : null;
  if (challenge) {
    const method = row["code_challenge_method"] ? String(row["code_challenge_method"]) : "S256";
    if (method === "S256") {
      const verifier = payload.code_verifier ?? "";
      const computed = createHash("sha256").update(verifier).digest("base64url");
      if (computed !== challenge) {
        throw new Error("invalid_grant");
      }
    }
  }

  const token = `at_${randomUUID().replace(/-/g, "")}`;
  const tokenHash = sha256Hex(token);
  await pool.query("update oauth_codes set used_at = now() where code = $1", [payload.code]);
  await pool.query(
    `insert into oauth_tokens (
      client_id,
      subject_id,
      tenant_id,
      scope,
      access_token_hash,
      issued_at,
      expires_at
    ) values ($1,$2,$3,$4,$5, now(), now() + interval '1 hour')`,
    [
      payload.client_id,
      "tenant-admin",
      "tnt_default",
      row["scope"] ? String(row["scope"]) : null,
      tokenHash,
    ],
  );
  return { access_token: token, token_type: "Bearer", expires_in: 3600 };
}

async function requireValidAccessToken(token: string): Promise<void> {
  const tokenHash = sha256Hex(token);
  const result = await getPool().query(
    "select 1 from oauth_tokens where access_token_hash = $1 and revoked_at is null and expires_at > now() limit 1",
    [tokenHash],
  );
  if ((result.rowCount ?? 0) === 0) {
    throw new Error("invalid_token");
  }
}

export async function issueLicense(payload: {
  access_token: string;
  tenant_id: string;
  app_id: string;
  license_mode: "portable" | "instance_bound";
  platform_instance_id?: string;
  term_days?: number;
  customer_ref?: string;
  features?: Record<string, unknown>;
  limits?: Record<string, unknown>;
}) {
  await requireValidAccessToken(payload.access_token);
  const cfg = loadConfig();
  const now = nowUnix();
  const exp = now + Math.max(1, payload.term_days ?? 365) * 86400;
  const jti = `lic_${randomUUID().replace(/-/g, "")}`;
  const aud =
    payload.license_mode === "portable"
      ? ["*"]
      : [payload.platform_instance_id && payload.platform_instance_id.startsWith("hcpi_") ? payload.platform_instance_id : `hcpi_${payload.platform_instance_id ?? ""}`];

  const privateJwk = JSON.parse(cfg.AUTHOR_PRIVATE_JWK_JSON) as JWK;
  const signingKey = await importJWK(privateJwk, "EdDSA");
  const licenseJws = await new SignJWT({
    typ: "hc-license",
    v: 1,
    subject: { scope_type: "tenant", tenant_id: payload.tenant_id },
    app: { app_id: payload.app_id },
    license_mode: payload.license_mode,
    features: payload.features ?? {},
    limits: payload.limits ?? {},
  })
    .setProtectedHeader({ alg: "EdDSA", kid: privateJwk.kid })
    .setIssuer(cfg.AUTHOR_ID)
    .setJti(jti)
    .setAudience(aud)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(exp)
    .sign(signingKey);

  await getPool().query(
    `insert into license_grants (
      jti,
      author_id,
      tenant_id,
      platform_instance_id,
      app_id,
      license_mode,
      license_jws,
      issued_at,
      not_before,
      expires_at,
      status,
      customer_ref,
      features_json,
      limits_json
    )
    values ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),to_timestamp($9),to_timestamp($10),'active',$11,$12::jsonb,$13::jsonb)`,
    [
      jti,
      cfg.AUTHOR_ID,
      payload.tenant_id,
      payload.platform_instance_id ?? null,
      payload.app_id,
      payload.license_mode,
      licenseJws,
      now,
      now,
      exp,
      payload.customer_ref ?? null,
      JSON.stringify(payload.features ?? {}),
      JSON.stringify(payload.limits ?? {}),
    ],
  );

  const bundle = {
    bundle_typ: "hc-license-bundle",
    v: 1,
    license_jws: licenseJws,
    author_cert_jws: cfg.AUTHOR_CERT_JWS,
    root_kid: "root_2026_01",
  };

  return {
    license_jws: licenseJws,
    author_cert_jws: cfg.AUTHOR_CERT_JWS,
    bundle,
  };
}

export async function listMigrationManifests(): Promise<Array<{ id: string; sha256: string }>> {
  const migrationPath = path.resolve(__dirname, "db", "migrations", "001_init.sql");
  const sql = await readFile(migrationPath, "utf8");
  return [{ id: "001_init", sha256: sha256Hex(sql) }];
}

export async function getMigrationSqlById(id: string): Promise<string | null> {
  if (id !== "001_init") {
    return null;
  }
  const migrationPath = path.resolve(__dirname, "db", "migrations", "001_init.sql");
  return readFile(migrationPath, "utf8");
}

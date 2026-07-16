import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";

import { loadConfig } from "./config.js";
import { getPool } from "./db/pool.js";
import { createActivation, issueApprovedActivation } from "./management-service.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
  const client = await getPool().query("select redirect_uris,status from oauth_clients where client_id=$1 limit 1", [payload.client_id]);
  if (!client.rowCount || client.rows[0].status !== "active") throw new Error("invalid_client");
  const redirectUris = Array.isArray(client.rows[0].redirect_uris) ? client.rows[0].redirect_uris : [];
  if (!redirectUris.includes(payload.redirect_uri)) throw new Error("invalid_redirect_uri");
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

async function requireValidAccessToken(token: string): Promise<{ clientId: string; platformInstanceId: string | null }> {
  const tokenHash = sha256Hex(token);
  const result = await getPool().query(
    `select t.client_id, c.platform_instance_id from oauth_tokens t
      join oauth_clients c on c.client_id=t.client_id
      where t.access_token_hash = $1 and t.revoked_at is null and t.expires_at > now() limit 1`,
    [tokenHash],
  );
  if ((result.rowCount ?? 0) === 0) {
    throw new Error("invalid_token");
  }
  return { clientId: String(result.rows[0].client_id), platformInstanceId: result.rows[0].platform_instance_id ? String(result.rows[0].platform_instance_id) : null };
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
  const token = await requireValidAccessToken(payload.access_token);
  const platformInstanceId = payload.platform_instance_id ?? token.platformInstanceId;
  const pool = getPool();
  const approved = await pool.query(
    `select activation_id, owner_tenant_id from activation_requests
      where tenant_id=$1 and app_id=$2 and license_mode=$3
        and platform_instance_id is not distinct from $4 and status='approved'
      order by decided_at asc limit 1`,
    [payload.tenant_id, payload.app_id, payload.license_mode, platformInstanceId],
  );
  if (approved.rowCount) {
    return issueApprovedActivation(String(approved.rows[0].owner_tenant_id), String(approved.rows[0].activation_id));
  }
  const grant = await pool.query(
    `select g.grant_id, g.owner_tenant_id, i.instance_id from core_instances i
      join commercial_grants g on g.customer_id=i.customer_id and g.status='active'
      join products p on p.product_id=g.product_id and p.app_id=$2 and p.status='active'
      where i.platform_instance_id=$1 and i.revoked_at is null
        and g.valid_from <= now() and (g.valid_until is null or g.valid_until > now())
      order by g.created_at asc limit 1`,
    [platformInstanceId, payload.app_id],
  );
  if (!grant.rowCount) {
    throw Object.assign(new Error("No active grant matches this Core instance and application"), { statusCode: 403 });
  }
  const row = grant.rows[0];
  const activation = await createActivation(String(row.owner_tenant_id), {
    grant_id: row.grant_id, instance_id: row.instance_id, platform_instance_id: platformInstanceId,
    tenant_id: payload.tenant_id, app_id: payload.app_id, license_mode: payload.license_mode,
    oauth_client_id: token.clientId,
  }, "online");
  throw Object.assign(new Error("Activation approval is pending"), { statusCode: 409, activationId: activation.activation_id });
}

export async function listMigrationManifests(): Promise<Array<{ id: string; sha256: string }>> {
  return Promise.all(["001_init", "002_management"].map(async (id) => {
    const sql = await readFile(path.resolve(__dirname, "db", "migrations", `${id}.sql`), "utf8");
    return { id, sha256: sha256Hex(sql) };
  }));
}

export async function getMigrationSqlById(id: string): Promise<string | null> {
  if (id !== "001_init" && id !== "002_management") {
    return null;
  }
  const migrationPath = path.resolve(__dirname, "db", "migrations", "001_init.sql");
  return readFile(migrationPath, "utf8");
}

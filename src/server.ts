import Fastify from "fastify";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { jwtVerify } from "jose";
import { z } from "zod";

import { loadConfig } from "./config.js";
import { validateSigningKeyProvider } from "./signing-key-provider.js";
import {
  discoveryMetadata,
  exchangeAuthorizationCode,
  getMigrationSqlById,
  issueAuthorizationCode,
  issueLicense,
  listMigrationManifests,
  registerOAuthClient,
} from "./licensing-service.js";
import { registerManagementRoutes } from "./management-routes.js";

const app = Fastify({ logger: true });
const config = loadConfig();
await validateSigningKeyProvider(config);

app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_request, body, done) => {
  try {
    done(null, Object.fromEntries(new URLSearchParams(String(body))));
  } catch (error) {
    done(error as Error);
  }
});

const dcrSchema = z.object({
  software_statement: z.string().min(20),
  redirect_uris: z.array(z.string().url()).min(1),
});

const authorizeSchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(3),
  redirect_uri: z.string().url(),
  scope: z.string().optional(),
  state: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.string().optional(),
});

const tokenSchema = z.object({
  grant_type: z.literal("authorization_code"),
  code: z.string().min(3),
  client_id: z.string().min(3),
  client_secret: z.string().optional(),
  code_verifier: z.string().optional(),
});

const issueSchema = z.object({
  author_id: z.string().min(3).optional(),
  tenant_id: z.string().min(1),
  app_id: z.string().min(3),
  license_mode: z.enum(["portable", "instance_bound"]),
  platform_instance_id: z.string().optional(),
  term_days: z.number().int().positive().max(3650).optional(),
  features: z.record(z.string(), z.unknown()).optional(),
  limits: z.record(z.string(), z.unknown()).optional(),
  customer_ref: z.string().optional(),
});

app.get("/health", async () => ({ status: "ok", identity_mode: config.ISSUER_IDENTITY_MODE, operation_mode: config.ISSUER_OPERATION_MODE }));

app.get("/internal/ui/plugin.js", async (request, reply) => {
  const authHeader = String(request.headers["authorization"] ?? "");
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(config.INSTALLATION_TOKEN_SECRET), { issuer: config.INSTALLATION_TOKEN_ISSUER });
    if (payload.purpose !== "ui-artifact-fetch") throw new Error("invalid purpose");
  } catch {
    return reply.code(403).send({ message: "invalid UI artifact token" });
  }
  reply.type("text/javascript; charset=utf-8");
  return reply.send(await readFile(path.resolve(process.cwd(), "dist-plugin", "plugin.js"), "utf8"));
});

app.get("/.well-known/hc-licensing", async () => discoveryMetadata());

app.get("/.well-known/hc/migrations", async () => {
  const items = await listMigrationManifests();
  return { version: 1, items };
});

app.get("/.well-known/hc/migrations/:id", async (request, reply) => {
  const id = String((request.params as { id: string }).id ?? "");
  const sql = await getMigrationSqlById(id);
  if (!sql) {
    return reply.code(404).send({ message: "migration not found" });
  }
  reply.header("content-type", "text/plain; charset=utf-8");
  return reply.send(sql);
});

app.post("/.well-known/hc/installation/complete", async (request, reply) => {
  const authHeader = String(request.headers["authorization"] ?? "");
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    return reply.code(401).send({ message: "missing installation bearer token" });
  }

  const secret = new TextEncoder().encode(config.INSTALLATION_TOKEN_SECRET);
  try {
    const { payload } = await jwtVerify(token, secret, {
      issuer: config.INSTALLATION_TOKEN_ISSUER,
    });
    if (payload.purpose !== "installation-complete") {
      return reply.code(403).send({ message: "invalid installation token purpose" });
    }
  } catch {
    return reply.code(403).send({ message: "invalid installation token" });
  }

  return reply.send({ status: "ok" });
});

app.post("/oauth/register", async (request) => {
  const payload = dcrSchema.parse(request.body ?? {});
  return registerOAuthClient(payload);
});

app.get("/oauth/authorize", async (request, reply) => {
  const query = authorizeSchema.parse(request.query ?? {});
  const { code } = await issueAuthorizationCode(query);

  const redirect = new URL(query.redirect_uri);
  redirect.searchParams.set("code", code);
  if (query.state) {
    redirect.searchParams.set("state", query.state);
  }

  return reply.redirect(redirect.toString());
});

app.post("/oauth/token", async (request) => {
  const payload = tokenSchema.parse(request.body ?? {});
  return exchangeAuthorizationCode(payload);
});

app.post("/v1/licenses/issue", async (request) => {
  const authHeader = String(request.headers["authorization"] ?? "");
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    throw new Error("Missing bearer token");
  }

  const payload = issueSchema.parse(request.body ?? {});
  const authorId = config.ISSUER_OPERATION_MODE === "single_author" ? config.AUTHOR_ID : payload.author_id;
  if (!authorId) throw Object.assign(new Error("author_id is required in managed_multi_author mode"), { statusCode: 400 });
  return issueLicense({
    access_token: token,
    author_id: authorId,
    ...payload,
  });
});

app.post("/v1/licenses/revoke", async () => {
  return { status: "deprecated", message: "Use the delegated management API." };
});

await registerManagementRoutes(app);

app.listen({ port: config.PORT, host: "0.0.0.0" }).catch((error) => {
  app.log.error(error);
  process.exitCode = 1;
});

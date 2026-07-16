import type { FastifyRequest } from "fastify";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";

import { loadConfig } from "./config.js";

export type DelegatedUser = {
  userId: string;
  effectiveUserId: string;
  username: string;
  tenantId: string;
  privileges: string[];
  correlationId: string;
  ipAddress: string | null;
  userAgent: string | null;
};

export async function requireDelegatedUser(request: FastifyRequest, permission: string): Promise<DelegatedUser> {
  const token = String(request.headers["x-hc-user-delegation"] ?? "");
  if (!token) {
    throw Object.assign(new Error("Core user delegation is required"), { statusCode: 401 });
  }
  const config = loadConfig();
  let payload;
  try {
    ({ payload } = await jwtVerify(token, createLocalJWKSet(JSON.parse(config.CORE_DELEGATION_JWKS_JSON) as JSONWebKeySet), {
      issuer: config.CORE_JWT_ISSUER,
      audience: `hc-app:${config.APP_ID}`,
    }));
  } catch {
    throw Object.assign(new Error("Invalid Core user delegation"), { statusCode: 401 });
  }
  const privileges = Array.isArray(payload["privileges"])
    ? payload["privileges"].filter((item): item is string => typeof item === "string")
    : [];
  if (!privileges.includes("platform.superadmin") && !privileges.includes(permission)) {
    throw Object.assign(new Error(`Missing permission: ${permission}`), { statusCode: 403 });
  }
  if (payload["typ"] !== "hc-user-delegation" || typeof payload.sub !== "string" || typeof payload["tenant_id"] !== "string") {
    throw Object.assign(new Error("Incomplete Core user delegation"), { statusCode: 401 });
  }
  return {
    userId: payload.sub,
    effectiveUserId: typeof payload["effective_user_id"] === "string" ? payload["effective_user_id"] : payload.sub,
    username: typeof payload["username"] === "string" ? payload["username"] : payload.sub,
    tenantId: payload["tenant_id"],
    privileges,
    correlationId: typeof payload["correlation_id"] === "string" ? payload["correlation_id"] : request.id,
    ipAddress: String(request.headers["x-forwarded-for"] ?? request.ip ?? "") || null,
    userAgent: String(request.headers["x-forwarded-user-agent"] ?? request.headers["user-agent"] ?? "") || null,
  };
}

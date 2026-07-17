import { SignJWT, importJWK } from "jose";
import { describe, expect, it } from "vitest";

import { requireDelegatedUser } from "../src/delegated-auth.js";

describe("delegated issuer authorization", () => {
  it("accepts an app-bound Core user with the required privilege", async () => {
    process.env.DATABASE_URL = "postgres://unused";
    process.env.ISSUER_BASE_URL = "http://localhost:4030";
    process.env.AUTHOR_ID = "talpaversum";
    process.env.AUTHOR_PRIVATE_JWK_JSON = "{}";
    process.env.AUTHOR_CERT_JWS = "certificate-placeholder";
    process.env.AUTHOR_REGISTRY_ID = "hekatoncheiros-test";
    process.env.DCR_TRUSTED_CORE_JWKS_JSON = '{"keys":[]}';
    process.env.CORE_DELEGATION_JWKS_JSON = '{"keys":[{"crv":"Ed25519","x":"yX9arOMjShM8hvqmwg7B1abzkyAQYyfYPieQaTIh5Lk","kty":"OKP","kid":"core-delegation-dev-1"}]}';
    process.env.CORE_JWT_ISSUER = "hekatoncheiros-core";
    process.env.APP_ID = "talpaversum/licensing";
    const signingKey = await importJWK({ crv: "Ed25519", d: "2zZRDOPRk5kGWJ77q4781dtzvZ6epsJfQpzvPHD7mwU", x: "yX9arOMjShM8hvqmwg7B1abzkyAQYyfYPieQaTIh5Lk", kty: "OKP", kid: "core-delegation-dev-1" }, "EdDSA");
    const token = await new SignJWT({ typ: "hc-user-delegation", tenant_id: "tnt_default", username: "admin@example.com", privileges: ["licensing.products.manage"], correlation_id: "req-1" })
      .setProtectedHeader({ alg: "EdDSA", kid: "core-delegation-dev-1" }).setSubject("usr_admin").setIssuer("hekatoncheiros-core")
      .setAudience("hc-app:talpaversum/licensing").setIssuedAt().setExpirationTime("1m")
      .sign(signingKey);
    const user = await requireDelegatedUser({ id: "fallback", ip: "127.0.0.1", headers: { "x-hc-user-delegation": token } } as never, "licensing.products.manage");
    expect(user).toMatchObject({ userId: "usr_admin", tenantId: "tnt_default", username: "admin@example.com" });
  });
});

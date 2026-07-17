import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import { describe, expect, it } from "vitest";

import type { EnvConfig } from "../src/config.js";
import { validateIssuerIdentity, verifyLicenseJwsAgainstAuthorCertificate } from "../src/issuer-identity.js";

async function identity(mode: EnvConfig["ISSUER_IDENTITY_MODE"] = "test") {
  const prefix = mode === "production" ? "prod" : mode === "development" ? "dev" : "test";
  const registryId = mode === "production" ? "hekatoncheiros-official" : `hekatoncheiros-${mode}`;
  const root = await generateKeyPair("EdDSA", { extractable: true });
  const author = await generateKeyPair("EdDSA", { extractable: true });
  const rootPublic = { ...(await exportJWK(root.publicKey)), kid: `${prefix}-root-1`, alg: "EdDSA", use: "sig" } as JWK;
  const authorPublic = { ...(await exportJWK(author.publicKey)), kid: `${prefix}-author-1`, alg: "EdDSA", use: "sig" } as JWK;
  const authorPrivate = { ...(await exportJWK(author.privateKey)), kid: `${prefix}-author-1`, alg: "EdDSA", use: "sig" } as JWK;
  const now = Math.floor(Date.now() / 1000);
  const certificate = await new SignJWT({
    typ: "hc-author-cert",
    v: 1,
    jwks: { keys: [authorPublic] },
    registry_id: registryId,
    trust_policy_version: 1,
  })
    .setProtectedHeader({ alg: "EdDSA", kid: `${prefix}-root-1` })
    .setIssuer("hc-author-registry")
    .setSubject("talpaversum")
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(now + 3600)
    .sign(root.privateKey);
  const config = {
    ISSUER_IDENTITY_MODE: mode,
    AUTHOR_ID: "talpaversum",
    AUTHOR_PRIVATE_JWK_JSON: JSON.stringify(authorPrivate),
    AUTHOR_CERT_JWS: certificate,
    AUTHOR_REGISTRY_ROOT_JWKS_JSON: JSON.stringify({ keys: [rootPublic] }),
    AUTHOR_REGISTRY_ID: registryId,
    AUTHOR_REGISTRY_ISSUER: "hc-author-registry",
  } as EnvConfig;
  return { config, certificate, author, now };
}

describe("issuer identity", () => {
  it("validates a test-only Registry to author to license chain", async () => {
    const material = await identity();
    await expect(validateIssuerIdentity(material.config)).resolves.toMatchObject({ payload: { sub: "talpaversum" } });
    const license = await new SignJWT({ typ: "hc-license", app: { app_id: "talpaversum/inventory" } })
      .setProtectedHeader({ alg: "EdDSA", kid: "test-author-1" })
      .setIssuer("talpaversum")
      .setSubject("tenant-1")
      .setIssuedAt(material.now)
      .setExpirationTime(material.now + 1800)
      .sign(material.author.privateKey);
    await expect(verifyLicenseJwsAgainstAuthorCertificate(license, material.certificate, material.config)).resolves.toMatchObject({
      typ: "hc-license",
      iss: "talpaversum",
    });
  });

  it("rejects a certificate signed by an untrusted Registry root", async () => {
    const trusted = await identity();
    const foreign = await identity();
    await expect(validateIssuerIdentity({ ...trusted.config, AUTHOR_CERT_JWS: foreign.certificate })).rejects.toThrow(
      "not signed by the configured Registry root",
    );
  });

  it("rejects a missing identity and an uncertified author private key", async () => {
    const material = await identity();
    await expect(validateIssuerIdentity({ ...material.config, AUTHOR_CERT_JWS: "REPLACE_ME" })).rejects.toThrow("placeholder");
    const foreign = await identity();
    await expect(
      validateIssuerIdentity({ ...material.config, AUTHOR_PRIVATE_JWK_JSON: foreign.config.AUTHOR_PRIVATE_JWK_JSON }),
    ).rejects.toThrow("not certified");
  });

  it("rejects explicitly marked development identity in production mode", async () => {
    const material = await identity("development");
    await expect(validateIssuerIdentity({ ...material.config, ISSUER_IDENTITY_MODE: "production" })).rejects.toThrow(
      "Production issuer refuses development or test identity material",
    );
  });

  it("rejects a license signed by a different author key", async () => {
    const material = await identity();
    const foreign = await generateKeyPair("EdDSA");
    const license = await new SignJWT({ typ: "hc-license" })
      .setProtectedHeader({ alg: "EdDSA", kid: "foreign-author" })
      .setIssuer("talpaversum")
      .setIssuedAt(material.now)
      .setExpirationTime(material.now + 1800)
      .sign(foreign.privateKey);
    await expect(verifyLicenseJwsAgainstAuthorCertificate(license, material.certificate, material.config)).rejects.toThrow(
      "not signed by a certified author key",
    );
  });
});

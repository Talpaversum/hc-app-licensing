import {
  createLocalJWKSet,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  type JWK,
  type JSONWebKeySet,
  type JWTPayload,
} from "jose";

import type { EnvConfig } from "./config.js";

export type VerifiedAuthorCertificate = {
  headerKid: string;
  payload: JWTPayload;
  authorJwks: JSONWebKeySet;
};

function parseJson<T>(value: string, name: string): T {
  if (!value || value.includes("REPLACE_ME")) throw new Error(`${name} is missing or contains placeholder material`);
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new Error(`${name} must be valid JSON`);
  }
}

function assertPublicEd25519Jwks(jwks: JSONWebKeySet, name: string): JWK[] {
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) throw new Error(`${name} must contain at least one key`);
  const kids = new Set<string>();
  for (const key of jwks.keys as JWK[]) {
    if (key.kty !== "OKP" || key.crv !== "Ed25519" || typeof key.kid !== "string" || !key.kid || typeof key.x !== "string" || !key.x) {
      throw new Error(`${name} must contain Ed25519 public keys with kid and x`);
    }
    if (key.d) throw new Error(`${name} must contain public keys only`);
    if (kids.has(key.kid)) throw new Error(`${name} contains duplicate kid ${key.kid}`);
    kids.add(key.kid);
  }
  return jwks.keys as JWK[];
}

function assertIdentityMode(config: EnvConfig, rootKids: string[], authorKid: string): void {
  const isDev = (value: string) => /^dev[-_]/i.test(value);
  const isTest = (value: string) => /^test[-_]/i.test(value);
  if (config.ISSUER_IDENTITY_MODE === "production") {
    if ([...rootKids, authorKid].some((value) => isDev(value) || isTest(value)) || /development|test/i.test(config.AUTHOR_REGISTRY_ID)) {
      throw new Error("Production issuer refuses development or test identity material");
    }
    return;
  }
  const expected = config.ISSUER_IDENTITY_MODE === "development" ? isDev : isTest;
  if (!rootKids.every(expected) || !expected(authorKid) || !new RegExp(config.ISSUER_IDENTITY_MODE, "i").test(config.AUTHOR_REGISTRY_ID)) {
    throw new Error(`${config.ISSUER_IDENTITY_MODE} issuer identity must be explicitly marked as non-production`);
  }
}

export async function verifyAuthorCertificate(authorCertJws: string, config: EnvConfig): Promise<VerifiedAuthorCertificate> {
  if (!authorCertJws || authorCertJws.includes("REPLACE_ME")) throw new Error("AUTHOR_CERT_JWS is missing or contains placeholder material");
  const roots = parseJson<JSONWebKeySet>(config.AUTHOR_REGISTRY_ROOT_JWKS_JSON, "AUTHOR_REGISTRY_ROOT_JWKS_JSON");
  const rootKeys = assertPublicEd25519Jwks(roots, "AUTHOR_REGISTRY_ROOT_JWKS_JSON");
  let verified;
  try {
    verified = await jwtVerify(authorCertJws, createLocalJWKSet(roots), { issuer: config.AUTHOR_REGISTRY_ISSUER });
  } catch {
    throw new Error("Author certificate is not signed by the configured Registry root");
  }
  const header = decodeProtectedHeader(authorCertJws);
  if (header.alg !== "EdDSA" || typeof header.kid !== "string" || !header.kid) throw new Error("Author certificate has an invalid protected header");
  if (verified.payload["typ"] !== "hc-author-cert") throw new Error("Author certificate has an invalid type");
  if (verified.payload.sub !== config.AUTHOR_ID) throw new Error("Author certificate does not belong to the configured author");
  if (verified.payload["registry_id"] !== config.AUTHOR_REGISTRY_ID) throw new Error("Author certificate belongs to a different Registry identity");
  const authorJwks = verified.payload["jwks"] as JSONWebKeySet | undefined;
  if (!authorJwks) throw new Error("Author certificate does not contain an author JWKS");
  assertPublicEd25519Jwks(authorJwks, "Author certificate JWKS");

  const privateJwk = parseJson<JWK>(config.AUTHOR_PRIVATE_JWK_JSON, "AUTHOR_PRIVATE_JWK_JSON");
  if (privateJwk.kty !== "OKP" || privateJwk.crv !== "Ed25519" || typeof privateJwk.kid !== "string" || !privateJwk.kid || !privateJwk.d || !privateJwk.x) {
    throw new Error("AUTHOR_PRIVATE_JWK_JSON must contain an Ed25519 private signing key with kid and x");
  }
  try {
    await importJWK(privateJwk, "EdDSA");
  } catch {
    throw new Error("AUTHOR_PRIVATE_JWK_JSON is not a valid Ed25519 private key");
  }
  const certified = (authorJwks.keys as JWK[]).find((key) => key.kid === privateJwk.kid);
  if (!certified || certified.x !== privateJwk.x) throw new Error("Issuer private key is not certified by AUTHOR_CERT_JWS");
  assertIdentityMode(config, rootKeys.map((key) => String(key.kid)), privateJwk.kid);
  return { headerKid: header.kid, payload: verified.payload, authorJwks };
}

export async function validateIssuerIdentity(config: EnvConfig): Promise<VerifiedAuthorCertificate> {
  return verifyAuthorCertificate(config.AUTHOR_CERT_JWS, config);
}

export async function verifyLicenseJwsAgainstAuthorCertificate(licenseJws: string, authorCertJws: string, config: EnvConfig) {
  const certificate = await verifyAuthorCertificate(authorCertJws, config);
  let verified;
  try {
    verified = await jwtVerify(licenseJws, createLocalJWKSet(certificate.authorJwks));
  } catch {
    throw new Error("License JWS is not signed by a certified author key");
  }
  if (verified.payload["typ"] !== "hc-license") throw new Error("License JWS has an invalid type");
  if (verified.payload.iss !== config.AUTHOR_ID) throw new Error("License issuer does not match the certified author identity");
  return verified.payload;
}

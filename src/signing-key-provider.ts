import type { JWK } from "jose";

import { loadConfig, type EnvConfig } from "./config.js";
import { verifyAuthorCertificate } from "./issuer-identity.js";

export type AuthorSigningIdentity = {
  authorId: string;
  privateJwk: JWK;
  authorCertJws: string;
  keyReference: string;
};

export interface SigningKeyProvider {
  get(authorId: string): Promise<AuthorSigningIdentity>;
}

type ManagedIdentity = {
  author_id: string;
  private_jwk: JWK;
  author_cert_jws: string;
  key_reference?: string;
};

function managedIdentities(config: EnvConfig): ManagedIdentity[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(config.MANAGED_AUTHOR_IDENTITIES_JSON);
  } catch {
    throw new Error("MANAGED_AUTHOR_IDENTITIES_JSON must be valid JSON");
  }
  const authors = (parsed as { authors?: unknown }).authors;
  if (!Array.isArray(authors)) throw new Error("MANAGED_AUTHOR_IDENTITIES_JSON must contain an authors array");
  return authors as ManagedIdentity[];
}

export class EnvironmentSigningKeyProvider implements SigningKeyProvider {
  constructor(private readonly config: EnvConfig = loadConfig()) {}

  async get(authorId: string): Promise<AuthorSigningIdentity> {
    const source = this.config.ISSUER_OPERATION_MODE === "single_author"
      ? {
          author_id: this.config.AUTHOR_ID,
          private_jwk: JSON.parse(this.config.AUTHOR_PRIVATE_JWK_JSON) as JWK,
          author_cert_jws: this.config.AUTHOR_CERT_JWS,
          key_reference: `env:${this.config.AUTHOR_ID}`,
        }
      : managedIdentities(this.config).find((item) => item.author_id === authorId);

    if (!source || source.author_id !== authorId) {
      throw Object.assign(new Error("Signing identity is not configured for this author"), { statusCode: 409 });
    }

    const identityConfig: EnvConfig = {
      ...this.config,
      AUTHOR_ID: source.author_id,
      AUTHOR_PRIVATE_JWK_JSON: JSON.stringify(source.private_jwk),
      AUTHOR_CERT_JWS: source.author_cert_jws,
    };
    await verifyAuthorCertificate(source.author_cert_jws, identityConfig);
    return {
      authorId,
      privateJwk: source.private_jwk,
      authorCertJws: source.author_cert_jws,
      keyReference: source.key_reference ?? `managed:${authorId}:${String(source.private_jwk.kid ?? "unknown")}`,
    };
  }
}

export class CoreSigningKeyProvider implements SigningKeyProvider {
  constructor(private readonly config: EnvConfig = loadConfig()) {}

  async get(authorId: string): Promise<AuthorSigningIdentity> {
    if (!this.config.CORE_SIGNING_KEY_PROVIDER_URL || !this.config.CORE_SIGNING_KEY_PROVIDER_TOKEN) {
      throw new Error("Core signing key provider is not fully configured");
    }
    const url = new URL(`/api/v1/internal/hosted-licensing/authors/${encodeURIComponent(authorId)}/signing-identity`, this.config.CORE_SIGNING_KEY_PROVIDER_URL);
    const response = await fetch(url, { headers: { authorization: `Bearer ${this.config.CORE_SIGNING_KEY_PROVIDER_TOKEN}` } });
    if (!response.ok) throw Object.assign(new Error("Core signing identity is unavailable for this author"), { statusCode: response.status === 404 ? 409 : 503 });
    const source = await response.json() as ManagedIdentity & { key_reference: string };
    if (source.author_id !== authorId) throw new Error("Core signing provider returned a mismatched author identity");
    const identityConfig: EnvConfig = {
      ...this.config,
      AUTHOR_ID: authorId,
      AUTHOR_PRIVATE_JWK_JSON: JSON.stringify(source.private_jwk),
      AUTHOR_CERT_JWS: source.author_cert_jws,
    };
    await verifyAuthorCertificate(source.author_cert_jws, identityConfig);
    return { authorId, privateJwk: source.private_jwk, authorCertJws: source.author_cert_jws, keyReference: source.key_reference };
  }
}

let provider: SigningKeyProvider | null = null;

export function getSigningKeyProvider(): SigningKeyProvider {
  const config = loadConfig();
  provider ??= config.ISSUER_OPERATION_MODE === "managed_multi_author" && config.CORE_SIGNING_KEY_PROVIDER_URL
    ? new CoreSigningKeyProvider(config)
    : new EnvironmentSigningKeyProvider(config);
  return provider;
}

export function setSigningKeyProviderForTests(value: SigningKeyProvider | null): void {
  provider = value;
}

export async function validateSigningKeyProvider(config: EnvConfig): Promise<void> {
  if (config.ISSUER_OPERATION_MODE === "managed_multi_author" && config.CORE_SIGNING_KEY_PROVIDER_URL) {
    if (!config.CORE_SIGNING_KEY_PROVIDER_TOKEN) throw new Error("CORE_SIGNING_KEY_PROVIDER_TOKEN is required with CORE_SIGNING_KEY_PROVIDER_URL");
    return;
  }
  const configured = new EnvironmentSigningKeyProvider(config);
  const authorIds = config.ISSUER_OPERATION_MODE === "single_author"
    ? [config.AUTHOR_ID]
    : managedIdentities(config).map((item) => item.author_id);
  if (authorIds.length === 0) throw new Error("managed_multi_author mode requires at least one configured author identity");
  if (new Set(authorIds).size !== authorIds.length) throw new Error("Managed author identities must have unique author_id values");
  await Promise.all(authorIds.map((authorId) => configured.get(authorId)));
}

import { randomUUID } from "node:crypto";

import { SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

function compactJson(value) {
  return JSON.stringify(value);
}

function line(name, value) {
  return `${name}=${value}`;
}

const authorId = process.argv.find((arg) => arg.startsWith("--author-id="))?.slice("--author-id=".length) ?? "talpaversum";
const issuerBaseUrl =
  process.argv.find((arg) => arg.startsWith("--issuer-base-url="))?.slice("--issuer-base-url=".length) ??
  "http://localhost:4030";
const rootIssuer = "hc-author-registry";
const rootKid = "root_2026_01";
const authorKid = `${authorId}_author_2026_01`;
const coreKid = "core_dcr_2026_01";

const rootKeys = await generateKeyPair("EdDSA", { extractable: true });
const authorKeys = await generateKeyPair("EdDSA", { extractable: true });
const coreKeys = await generateKeyPair("EdDSA", { extractable: true });

const rootPublicJwk = { ...(await exportJWK(rootKeys.publicKey)), kid: rootKid, alg: "EdDSA", use: "sig" };
const rootPrivateJwk = { ...(await exportJWK(rootKeys.privateKey)), kid: rootKid, alg: "EdDSA", use: "sig" };
const authorPublicJwk = { ...(await exportJWK(authorKeys.publicKey)), kid: authorKid, alg: "EdDSA", use: "sig" };
const authorPrivateJwk = { ...(await exportJWK(authorKeys.privateKey)), kid: authorKid, alg: "EdDSA", use: "sig" };
const corePublicJwk = { ...(await exportJWK(coreKeys.publicKey)), kid: coreKid, alg: "EdDSA", use: "sig" };
const corePrivateJwk = { ...(await exportJWK(coreKeys.privateKey)), kid: coreKid, alg: "EdDSA", use: "sig" };

const now = nowUnix();
const rootSigningKey = await importJWK(rootPrivateJwk, "EdDSA");
const authorCertJws = await new SignJWT({
  typ: "hc-author-cert",
  v: 1,
  jwks: { keys: [authorPublicJwk] },
})
  .setProtectedHeader({ alg: "EdDSA", kid: rootKid })
  .setIssuer(rootIssuer)
  .setSubject(authorId)
  .setIssuedAt(now)
  .setNotBefore(now)
  .setExpirationTime(now + 365 * 86400)
  .sign(rootSigningKey);

console.log("# Generated development material. Do not use in production.");
console.log("# Copy the hc-app-licensing section to hc-app-licensing/.env.");
console.log("# Copy the hekatoncheiros-core section to hekatoncheiros-core/.env.");
console.log("");
console.log("# hc-app-licensing");
console.log(line("PORT", "4030"));
console.log(line("DATABASE_URL", "postgres://hc_licensing:hc_licensing_password@postgres:5432/hc_app_licensing"));
console.log(line("ISSUER_BASE_URL", issuerBaseUrl));
console.log(line("BACKCHANNEL_BASE_URL", "http://host.docker.internal:4030"));
console.log(line("AUTHOR_ID", authorId));
console.log(line("AUTHOR_PRIVATE_JWK_JSON", compactJson(authorPrivateJwk)));
console.log(line("AUTHOR_CERT_JWS", authorCertJws));
console.log(line("DCR_TRUSTED_CORE_JWKS_JSON", compactJson({ keys: [corePublicJwk] })));
console.log(line("INSTALLATION_TOKEN_SECRET", "installersecretinstallersecret"));
console.log(line("INSTALLATION_TOKEN_ISSUER", "hekatoncheiros-core-installer"));
console.log("");
console.log("# hekatoncheiros-core");
console.log(line("LICENSING_ROOT_JWKS_JSON", compactJson({ keys: [rootPublicJwk] })));
console.log(line("LICENSING_DCR_SIGNING_PRIVATE_JWK_JSON", compactJson(corePrivateJwk)));
console.log(line("LICENSING_DCR_SIGNING_PUBLIC_JWK_JSON", compactJson(corePublicJwk)));
console.log(line("LICENSING_OAUTH_CALLBACK_BASE_URL", "http://localhost:8080"));
console.log("");
console.log(`# run_id=${randomUUID()}`);

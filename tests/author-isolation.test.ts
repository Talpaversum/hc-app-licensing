import { exportJWK, generateKeyPair, SignJWT, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { getPool } from "../src/db/pool.js";
import {
  createActivation,
  createCustomer,
  createGrant,
  createProduct,
  decideActivation,
  issueApprovedActivation,
  listEntities,
  updateEntityStatus,
} from "../src/management-service.js";
import { setSigningKeyProviderForTests } from "../src/signing-key-provider.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const suite = databaseUrl ? describe : describe.skip;
const suffix = Date.now().toString(36);
const tenantId = `tenant-shared-${suffix}`;
const authorA = `author-a-${suffix}`;
const authorB = `author-b-${suffix}`;

async function signingMaterial(authorId: string, rootPrivate: CryptoKey, rootKid: string) {
  const pair = await generateKeyPair("EdDSA", { extractable: true });
  const privateJwk = { ...(await exportJWK(pair.privateKey)), kid: `test_${authorId}` } as JWK;
  const publicJwk = { ...(await exportJWK(pair.publicKey)), kid: privateJwk.kid } as JWK;
  const authorCertJws = await new SignJWT({ typ: "hc-author-cert", registry_id: "test-registry", jwks: { keys: [publicJwk] } })
    .setProtectedHeader({ alg: "EdDSA", kid: rootKid }).setIssuer("hc-author-registry").setSubject(authorId)
    .setIssuedAt().setExpirationTime("1h").sign(rootPrivate);
  return { author_id: authorId, private_jwk: privateJwk, author_cert_jws: authorCertJws, key_reference: `test:${authorId}` };
}

suite("managed licensing author isolation", () => {
  beforeAll(async () => {
    process.env.DATABASE_URL = databaseUrl;
    process.env.ISSUER_OPERATION_MODE = "managed_multi_author";
    process.env.ISSUER_IDENTITY_MODE = "test";
    process.env.AUTHOR_REGISTRY_ID = "test-registry";
    process.env.AUTHOR_REGISTRY_ISSUER = "hc-author-registry";
    process.env.CORE_DELEGATION_JWKS_JSON = '{"keys":[]}';
    const root = await generateKeyPair("EdDSA", { extractable: true });
    const rootKid = "test_root_isolation";
    const rootPublic = { ...(await exportJWK(root.publicKey)), kid: rootKid };
    const identities = await Promise.all([
      signingMaterial(authorA, root.privateKey, rootKid),
      signingMaterial(authorB, root.privateKey, rootKid),
    ]);
    process.env.AUTHOR_REGISTRY_ROOT_JWKS_JSON = JSON.stringify({ keys: [rootPublic] });
    process.env.MANAGED_AUTHOR_IDENTITIES_JSON = JSON.stringify({ authors: identities });
    setSigningKeyProviderForTests(null);
  });

  afterAll(async () => {
    const pool = getPool();
    for (const table of ["issuer_audit_log", "issued_licenses", "activation_requests", "commercial_grants", "core_instances", "customers", "products", "signing_certificates", "signing_key_references"]) {
      await pool.query(`delete from ${table} where author_id=any($1::text[])`, [[authorA, authorB]]);
    }
    await pool.end();
  });

  it("isolates records and signs each license with its own author key", async () => {
    const customerA = await createCustomer(authorA, tenantId, { company_name: "Customer A" });
    const customerB = await createCustomer(authorB, tenantId, { company_name: "Customer B" });
    const productA = await createProduct(authorA, tenantId, { app_id: `${authorA}/app`, name: "Product A" });
    const productB = await createProduct(authorB, tenantId, { app_id: `${authorB}/app`, name: "Product B" });
    const grantA = await createGrant(authorA, tenantId, { customer_id: customerA.customer_id, product_id: productA.product_id, edition: "pro", status: "active" });
    const grantB = await createGrant(authorB, tenantId, { customer_id: customerB.customer_id, product_id: productB.product_id, edition: "pro", status: "active" });

    const activationA = await createActivation(authorA, tenantId, { grant_id: grantA.grant_id, tenant_id: tenantId, app_id: productA.app_id, license_mode: "portable" }, "offline");
    const activationB = await createActivation(authorB, tenantId, { grant_id: grantB.grant_id, tenant_id: tenantId, app_id: productB.app_id, license_mode: "portable" }, "offline");
    await decideActivation(authorA, tenantId, activationA.activation_id, true, "tester");
    await decideActivation(authorB, tenantId, activationB.activation_id, true, "tester");
    const licenseA = await issueApprovedActivation(authorA, tenantId, activationA.activation_id);
    const licenseB = await issueApprovedActivation(authorB, tenantId, activationB.activation_id);

    expect((await listEntities("products", authorA, tenantId)).map((row) => row.author_id)).toEqual([authorA]);
    expect((await listEntities("customers", authorB, tenantId)).map((row) => row.author_id)).toEqual([authorB]);
    expect((await listEntities("grants", authorA, tenantId)).map((row) => row.author_id)).toEqual([authorA]);
    await expect(updateEntityStatus("products", authorA, tenantId, productB.product_id, "retired")).rejects.toMatchObject({ statusCode: 404 });

    expect(decodeProtectedHeader(licenseA.license_jws).kid).toBe(`test_${authorA}`);
    expect(decodeProtectedHeader(licenseB.license_jws).kid).toBe(`test_${authorB}`);
    const identityA = JSON.parse(process.env.MANAGED_AUTHOR_IDENTITIES_JSON!).authors[0];
    const verifiedA = await jwtVerify(licenseA.license_jws, await importJWK({ ...identityA.private_jwk, d: undefined }, "EdDSA"));
    expect(verifiedA.payload.iss).toBe(authorA);
  });
});

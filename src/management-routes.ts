import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { audit } from "./audit.js";
import { loadConfig } from "./config.js";
import { requireDelegatedUser } from "./delegated-auth.js";
import {
  createActivation, createCustomer, createGrant, createInstance, createProduct, dashboard,
  decideActivation, issueApprovedActivation, licenseRevocations, listEntities, setLicenseStatus,
  importOfflineActivation,
  importAuthorCertificate,
  renewLicense,
  revokeInstance,
  updateEntityStatus,
  type ManagementEntity,
} from "./management-service.js";

const productSchema = z.object({
  app_id: z.string().min(3), name: z.string().min(2), description: z.string().optional(),
  status: z.enum(["draft", "active", "retired"]).optional(), editions: z.array(z.string()).optional(),
  capabilities: z.array(z.string()).optional(), default_policy: z.record(z.string(), z.unknown()).optional(),
});
const customerSchema = z.object({
  company_name: z.string().min(2), contacts: z.array(z.record(z.string(), z.unknown())).optional(),
  notes: z.string().optional(), status: z.enum(["active", "suspended", "archived"]).optional(),
});
const instanceSchema = z.object({
  customer_id: z.string().min(3), platform_instance_id: z.string().min(3), callback_url: z.string().url().optional(),
  public_identity: z.record(z.string(), z.unknown()).optional(),
});
const grantSchema = z.object({
  customer_id: z.string().min(3), product_id: z.string().min(3), edition: z.string().min(1),
  capabilities: z.record(z.string(), z.unknown()).optional(), limits: z.record(z.string(), z.unknown()).optional(),
  offline_allowed: z.boolean().optional(), maintenance_until: z.string().datetime().optional(),
  subscription_until: z.string().datetime().optional(), valid_from: z.string().datetime().optional(),
  valid_until: z.string().datetime().optional(), status: z.enum(["draft", "active", "suspended", "expired", "revoked"]).optional(),
});
const activationSchema = z.object({
  grant_id: z.string().min(3), instance_id: z.string().min(3).optional(), platform_instance_id: z.string().min(3).optional(),
  tenant_id: z.string().min(1), app_id: z.string().min(3), license_mode: z.enum(["portable", "instance_bound"]),
});

const permissions: Record<ManagementEntity, string> = {
  products: "licensing.products.manage", customers: "licensing.customers.manage",
  instances: "licensing.instances.manage", grants: "licensing.grants.manage",
  activations: "licensing.activations.approve", licenses: "licensing.licenses.issue",
  audit: "licensing.audit.read",
};

export async function registerManagementRoutes(app: FastifyInstance) {
  const config = loadConfig();
  const root = config.ISSUER_OPERATION_MODE === "managed_multi_author" ? "/v1/admin/authors/:authorId" : "/v1/admin";
  const scope = (request: { params: unknown }) => config.ISSUER_OPERATION_MODE === "managed_multi_author"
    ? z.string().min(3).parse((request.params as { authorId?: string }).authorId)
    : config.AUTHOR_ID;
  const authorize = (request: Parameters<typeof requireDelegatedUser>[0], authorId: string, permission: string, authorPermission: string) =>
    requireDelegatedUser(request, permission, authorId, authorPermission);

  app.get(`${root}/dashboard`, async (request) => {
    const authorId = scope(request); const user = await authorize(request, authorId, "licensing.audit.read", "author.licensing.manage");
    return dashboard(authorId, user.tenantId);
  });
  app.post(`${root}/security/certificate`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, "licensing.licenses.issue", "author.licensing.issue");
    const body = z.object({ author_cert_jws: z.string().min(20) }).parse(request.body);
    const item = await importAuthorCertificate(authorId, body.author_cert_jws);
    await audit(user, authorId, { permission: "author.licensing.issue", operation: "security.certificate.imported", targetType: "author_certificate", targetId: String(item.id) });
    return reply.code(201).send(item);
  });

  app.get(`${root}/:entity`, async (request) => {
    const entity = z.enum(["products", "customers", "instances", "grants", "activations", "licenses", "audit"])
      .parse((request.params as { entity: string }).entity) as ManagementEntity;
    const authorId = scope(request); const user = await authorize(request, authorId, permissions[entity], entity === "licenses" ? "author.licensing.issue" : "author.licensing.manage");
    return { items: await listEntities(entity, authorId, user.tenantId) };
  });

  app.post(`${root}/products`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.products, "author.licensing.manage");
    const item = await createProduct(authorId, user.tenantId, productSchema.parse(request.body));
    await audit(user, authorId, { permission: "author.licensing.manage", operation: "product.created", targetType: "product", targetId: item.product_id });
    return reply.code(201).send(item);
  });
  app.post(`${root}/customers`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.customers, "author.licensing.manage");
    const item = await createCustomer(authorId, user.tenantId, customerSchema.parse(request.body));
    await audit(user, authorId, { permission: "author.licensing.manage", operation: "customer.created", targetType: "customer", targetId: item.customer_id });
    return reply.code(201).send(item);
  });
  app.post(`${root}/instances`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.instances, "author.licensing.manage");
    const item = await createInstance(authorId, user.tenantId, instanceSchema.parse(request.body));
    await audit(user, authorId, { permission: "author.licensing.manage", operation: "instance.created", targetType: "core_instance", targetId: item.instance_id });
    return reply.code(201).send(item);
  });
  app.post(`${root}/grants`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.grants, "author.licensing.manage");
    const item = await createGrant(authorId, user.tenantId, grantSchema.parse(request.body));
    await audit(user, authorId, { permission: "author.licensing.manage", operation: "grant.created", targetType: "license_grant", targetId: item.grant_id });
    return reply.code(201).send(item);
  });
  app.post(`${root}/activations/offline`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.activations, "author.licensing.manage");
    const raw = z.record(z.string(), z.unknown()).parse(request.body);
    const item = raw["request_jws"]
      ? await importOfflineActivation(authorId, user.tenantId, raw)
      : await createActivation(authorId, user.tenantId, activationSchema.parse(raw), "offline");
    await audit(user, authorId, { permission: "author.licensing.manage", operation: "activation.offline_imported", targetType: "activation", targetId: item.activation_id });
    return reply.code(201).send(item);
  });
  app.post(`${root}/activations/:id/decision`, async (request) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.activations, "author.licensing.manage");
    const body = z.object({ approved: z.boolean(), reason: z.string().max(500).optional() }).parse(request.body);
    const activationId = (request.params as { id: string }).id;
    const item = await decideActivation(authorId, user.tenantId, activationId, body.approved, user.userId, body.reason);
    await audit(user, authorId, { permission: "author.licensing.manage", operation: body.approved ? "activation.approved" : "activation.rejected", targetType: "activation", targetId: activationId, metadata: { reason: body.reason } });
    return item;
  });
  app.post(`${root}/activations/:id/issue`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.licenses, "author.licensing.issue");
    const activationId = (request.params as { id: string }).id;
    const issued = await issueApprovedActivation(authorId, user.tenantId, activationId);
    await audit(user, authorId, { permission: "author.licensing.issue", operation: "license.issued", targetType: "license", targetId: issued.license_id, metadata: { activation_id: activationId } });
    return reply.code(201).send(issued);
  });
  app.get(`${root}/licenses/:id/bundle`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.licenses, "author.licensing.issue");
    const rows = await listEntities("licenses", authorId, user.tenantId);
    const item = rows.find((row) => String(row.license_id) === (request.params as { id: string }).id);
    if (!item) return reply.code(404).send({ message: "License not found" });
    reply.header("content-disposition", `attachment; filename=${String(item.serial_number)}.json`);
    return item.bundle_json;
  });
  app.post(`${root}/licenses/:id/status`, async (request) => {
    const authorId = scope(request); const user = await authorize(request, authorId, permissions.licenses.replace("issue", "revoke"), "author.licensing.revoke");
    const body = z.object({ status: z.enum(["suspended", "revoked"]), reason: z.string().max(500).optional() }).parse(request.body);
    const licenseId = (request.params as { id: string }).id;
    const item = await setLicenseStatus(authorId, user.tenantId, licenseId, body.status, body.reason);
    await audit(user, authorId, { permission: "author.licensing.revoke", operation: `license.${body.status}`, targetType: "license", targetId: licenseId, metadata: { reason: body.reason } });
    return item;
  });
  app.post(`${root}/licenses/:id/renew`, async (request, reply) => {
    const authorId = scope(request); const user = await authorize(request, authorId, "licensing.licenses.issue", "author.licensing.issue");
    const licenseId = (request.params as { id: string }).id;
    const issued = await renewLicense(authorId, user.tenantId, licenseId, user.userId);
    await audit(user, authorId, { permission: "author.licensing.issue", operation: "license.renewed", targetType: "license", targetId: issued.license_id, metadata: { replaces: licenseId } });
    return reply.code(201).send(issued);
  });
  app.post(`${root}/instances/:id/revoke`, async (request) => {
    const authorId = scope(request); const user = await authorize(request, authorId, "licensing.instances.manage", "author.licensing.manage");
    const instanceId = (request.params as { id: string }).id;
    const item = await revokeInstance(authorId, user.tenantId, instanceId);
    await audit(user, authorId, { permission: "author.licensing.manage", operation: "instance.revoked", targetType: "core_instance", targetId: instanceId });
    return item;
  });
  app.post(`${root}/:entity/:id/status`, async (request) => {
    const entity = z.enum(["products", "customers", "grants"]).parse((request.params as { entity: string }).entity);
    const authorId = scope(request); const user = await authorize(request, authorId, permissions[entity], "author.licensing.manage");
    const body = z.object({ status: z.string().min(3).max(20) }).parse(request.body);
    const entityId = (request.params as { id: string }).id;
    const item = await updateEntityStatus(entity, authorId, user.tenantId, entityId, body.status);
    await audit(user, authorId, { permission: "author.licensing.manage", operation: `${entity}.status.updated`, targetType: entity, targetId: entityId, metadata: { status: body.status } });
    return item;
  });

  const revocationsPath = config.ISSUER_OPERATION_MODE === "managed_multi_author" ? "/v1/authors/:authorId/revocations" : "/v1/revocations";
  app.get(revocationsPath, async (request) => licenseRevocations(scope(request)));
}

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { audit } from "./audit.js";
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
  app.get("/v1/admin/dashboard", async (request) => {
    const user = await requireDelegatedUser(request, "licensing.audit.read");
    return dashboard(user.tenantId);
  });
  app.post("/v1/admin/security/certificate", async (request, reply) => {
    const user = await requireDelegatedUser(request, "licensing.licenses.issue");
    const body = z.object({ author_cert_jws: z.string().min(20) }).parse(request.body);
    const item = await importAuthorCertificate(body.author_cert_jws);
    await audit(user, { permission: "licensing.licenses.issue", operation: "security.certificate.imported", targetType: "author_certificate", targetId: String(item.id) });
    return reply.code(201).send(item);
  });

  app.get("/v1/admin/:entity", async (request) => {
    const entity = z.enum(["products", "customers", "instances", "grants", "activations", "licenses", "audit"])
      .parse((request.params as { entity: string }).entity) as ManagementEntity;
    const user = await requireDelegatedUser(request, permissions[entity]);
    return { items: await listEntities(entity, user.tenantId) };
  });

  app.post("/v1/admin/products", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.products);
    const item = await createProduct(user.tenantId, productSchema.parse(request.body));
    await audit(user, { permission: permissions.products, operation: "product.created", targetType: "product", targetId: item.product_id });
    return reply.code(201).send(item);
  });
  app.post("/v1/admin/customers", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.customers);
    const item = await createCustomer(user.tenantId, customerSchema.parse(request.body));
    await audit(user, { permission: permissions.customers, operation: "customer.created", targetType: "customer", targetId: item.customer_id });
    return reply.code(201).send(item);
  });
  app.post("/v1/admin/instances", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.instances);
    const item = await createInstance(user.tenantId, instanceSchema.parse(request.body));
    await audit(user, { permission: permissions.instances, operation: "instance.created", targetType: "core_instance", targetId: item.instance_id });
    return reply.code(201).send(item);
  });
  app.post("/v1/admin/grants", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.grants);
    const item = await createGrant(user.tenantId, grantSchema.parse(request.body));
    await audit(user, { permission: permissions.grants, operation: "grant.created", targetType: "license_grant", targetId: item.grant_id });
    return reply.code(201).send(item);
  });
  app.post("/v1/admin/activations/offline", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.activations);
    const raw = z.record(z.string(), z.unknown()).parse(request.body);
    const item = raw["request_jws"]
      ? await importOfflineActivation(user.tenantId, raw)
      : await createActivation(user.tenantId, activationSchema.parse(raw), "offline");
    await audit(user, { permission: permissions.activations, operation: "activation.offline_imported", targetType: "activation", targetId: item.activation_id });
    return reply.code(201).send(item);
  });
  app.post("/v1/admin/activations/:id/decision", async (request) => {
    const user = await requireDelegatedUser(request, permissions.activations);
    const body = z.object({ approved: z.boolean(), reason: z.string().max(500).optional() }).parse(request.body);
    const activationId = (request.params as { id: string }).id;
    const item = await decideActivation(user.tenantId, activationId, body.approved, user.userId, body.reason);
    await audit(user, { permission: permissions.activations, operation: body.approved ? "activation.approved" : "activation.rejected", targetType: "activation", targetId: activationId, metadata: { reason: body.reason } });
    return item;
  });
  app.post("/v1/admin/activations/:id/issue", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.licenses);
    const activationId = (request.params as { id: string }).id;
    const issued = await issueApprovedActivation(user.tenantId, activationId);
    await audit(user, { permission: permissions.licenses, operation: "license.issued", targetType: "license", targetId: issued.license_id, metadata: { activation_id: activationId } });
    return reply.code(201).send(issued);
  });
  app.get("/v1/admin/licenses/:id/bundle", async (request, reply) => {
    const user = await requireDelegatedUser(request, permissions.licenses);
    const rows = await listEntities("licenses", user.tenantId);
    const item = rows.find((row) => String(row.license_id) === (request.params as { id: string }).id);
    if (!item) return reply.code(404).send({ message: "License not found" });
    reply.header("content-disposition", `attachment; filename=${String(item.serial_number)}.json`);
    return item.bundle_json;
  });
  app.post("/v1/admin/licenses/:id/status", async (request) => {
    const user = await requireDelegatedUser(request, permissions.licenses.replace("issue", "revoke"));
    const body = z.object({ status: z.enum(["suspended", "revoked"]), reason: z.string().max(500).optional() }).parse(request.body);
    const licenseId = (request.params as { id: string }).id;
    const item = await setLicenseStatus(user.tenantId, licenseId, body.status, body.reason);
    await audit(user, { permission: "licensing.licenses.revoke", operation: `license.${body.status}`, targetType: "license", targetId: licenseId, metadata: { reason: body.reason } });
    return item;
  });
  app.post("/v1/admin/licenses/:id/renew", async (request, reply) => {
    const user = await requireDelegatedUser(request, "licensing.licenses.issue");
    const licenseId = (request.params as { id: string }).id;
    const issued = await renewLicense(user.tenantId, licenseId, user.userId);
    await audit(user, { permission: "licensing.licenses.issue", operation: "license.renewed", targetType: "license", targetId: issued.license_id, metadata: { replaces: licenseId } });
    return reply.code(201).send(issued);
  });
  app.post("/v1/admin/instances/:id/revoke", async (request) => {
    const user = await requireDelegatedUser(request, "licensing.instances.manage");
    const instanceId = (request.params as { id: string }).id;
    const item = await revokeInstance(user.tenantId, instanceId);
    await audit(user, { permission: "licensing.instances.manage", operation: "instance.revoked", targetType: "core_instance", targetId: instanceId });
    return item;
  });
  app.post("/v1/admin/:entity/:id/status", async (request) => {
    const entity = z.enum(["products", "customers", "grants"]).parse((request.params as { entity: string }).entity);
    const user = await requireDelegatedUser(request, permissions[entity]);
    const body = z.object({ status: z.string().min(3).max(20) }).parse(request.body);
    const entityId = (request.params as { id: string }).id;
    const item = await updateEntityStatus(entity, user.tenantId, entityId, body.status);
    await audit(user, { permission: permissions[entity], operation: `${entity}.status.updated`, targetType: entity, targetId: entityId, metadata: { status: body.status } });
    return item;
  });

  app.get("/v1/revocations", async () => licenseRevocations());
}

import { getPool } from "./db/pool.js";
import type { DelegatedUser } from "./delegated-auth.js";

export async function audit(user: DelegatedUser, authorId: string, event: {
  permission: string;
  operation: string;
  targetType: string;
  targetId?: string | null;
  outcome?: "success" | "denied" | "failed";
  metadata?: Record<string, unknown>;
}) {
  await getPool().query(
    `insert into issuer_audit_log
      (actor_user_id, username, tenant_id, author_id, application_id, permission_used, operation,
       target_type, target_id, outcome, ip_address, user_agent, correlation_id, metadata_json)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)`,
    [user.userId, user.username, user.tenantId, authorId, loadAppId(), event.permission, event.operation,
      event.targetType, event.targetId ?? null, event.outcome ?? "success", user.ipAddress,
      user.userAgent, user.correlationId, JSON.stringify(event.metadata ?? {})],
  );
}

function loadAppId() {
  return process.env.APP_ID ?? "talpaversum/licensing";
}

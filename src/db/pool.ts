import { Pool } from "pg";

import { loadConfig } from "../config.js";

let pool: Pool | null = null;

export function getPool(): Pool {
  if (!pool) {
    pool = new Pool({ connectionString: loadConfig().DATABASE_URL });
  }
  return pool;
}

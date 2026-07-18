import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "pg";

import { loadConfig } from "../config.js";

import { getPool } from "./pool.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function ensureDatabaseExists(): Promise<void> {
  const config = loadConfig();
  const probeClient = new Client({ connectionString: config.DATABASE_URL });
  try {
    await probeClient.connect();
  } catch (error) {
    const pgError = error as { code?: string };
    if (pgError.code === "3D000") {
      throw new Error(
        "Target database does not exist. Database provisioning is core responsibility (Database Policy).",
      );
    }
    throw error;
  } finally {
    await probeClient.end().catch(() => undefined);
  }
}

async function run() {
  await ensureDatabaseExists();

  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query("select set_config('hc.author_id', $1, false)", [loadConfig().AUTHOR_ID]);
    for (const migration of ["001_init.sql", "002_management.sql", "003_author_scope.sql"]) {
      const sql = await readFile(path.resolve(__dirname, "migrations", migration), "utf8");
      await client.query(sql);
    }
    console.log("hc-app-licensing migrations applied");
  } finally {
    client.release();
    await pool.end();
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

import dotenv from "dotenv";
import { z } from "zod";

const envSchema = z.object({
  PORT: z.coerce.number().default(4030),
  DATABASE_URL: z.string().min(1),
  ISSUER_BASE_URL: z.string().url(),
  BACKCHANNEL_BASE_URL: z.string().url().optional(),
  AUTHOR_ID: z.string().min(3),
  AUTHOR_PRIVATE_JWK_JSON: z.string().min(2),
  AUTHOR_CERT_JWS: z.string().min(5),
  DCR_TRUSTED_CORE_JWKS_JSON: z.string().min(2),
  INSTALLATION_TOKEN_SECRET: z.string().min(16).default("installersecretinstallersecret"),
  INSTALLATION_TOKEN_ISSUER: z.string().default("hekatoncheiros-core-installer"),
});

export type EnvConfig = z.infer<typeof envSchema>;

export function loadConfig(): EnvConfig {
  dotenv.config();
  return envSchema.parse(process.env);
}

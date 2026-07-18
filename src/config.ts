import dotenv from "dotenv";
import { z } from "zod";

const envSchema = z.object({
  PORT: z.coerce.number().default(4030),
  DATABASE_URL: z.string().min(1),
  ISSUER_BASE_URL: z.string().url(),
  BACKCHANNEL_BASE_URL: z.string().url().optional(),
  ISSUER_IDENTITY_MODE: z.enum(["production", "development", "test"]).default("production"),
  ISSUER_OPERATION_MODE: z.enum(["single_author", "managed_multi_author"]).default("single_author"),
  MANAGED_AUTHOR_IDENTITIES_JSON: z.string().default('{"authors":[]}'),
  CORE_SIGNING_KEY_PROVIDER_URL: z.union([z.literal(""), z.string().url()]).default(""),
  CORE_SIGNING_KEY_PROVIDER_TOKEN: z.union([z.literal(""), z.string().min(32)]).default(""),
  AUTHOR_ID: z.string().min(3),
  AUTHOR_PRIVATE_JWK_JSON: z.string().min(2),
  AUTHOR_CERT_JWS: z.string().min(5),
  AUTHOR_REGISTRY_ROOT_JWKS_JSON: z.string().default('{"keys":[]}'),
  AUTHOR_REGISTRY_ID: z.string().min(3),
  AUTHOR_REGISTRY_ISSUER: z.string().default("hc-author-registry"),
  DCR_TRUSTED_CORE_JWKS_JSON: z.string().min(2),
  INSTALLATION_TOKEN_SECRET: z.string().min(16).default("installersecretinstallersecret"),
  INSTALLATION_TOKEN_ISSUER: z.string().default("hekatoncheiros-core-installer"),
  APP_ID: z.string().default("talpaversum/licensing"),
  CORE_DELEGATION_JWKS_JSON: z.string().min(10),
  CORE_JWT_ISSUER: z.string().default("hekatoncheiros-core"),
});

export type EnvConfig = z.infer<typeof envSchema>;

export function loadConfig(): EnvConfig {
  dotenv.config();
  return envSchema.parse(process.env);
}

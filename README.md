# hc-app-licensing

Author-hosted licensing issuer for Hekatoncheiros apps.

This service issues tenant licenses for apps owned by one author identity. It is
not the app catalog, not the author registry, and not a normal customer Core
service. It should be operated by the app author/vendor.

## Role

`hc-app-licensing` is the online and offline license issuer:

- exposes `/.well-known/hc-licensing`
- registers Core instances via OAuth Dynamic Client Registration
- runs OAuth authorization code activation
- issues signed `hc-license` tokens at `/v1/licenses/issue`
- returns offline-compatible bundles with `license_jws` and `author_cert_jws`

Core then verifies the chain offline:

`hc-author-registry root JWKS -> author_cert_jws -> license_jws`

## Required Identity Material

The issuer needs:

- `AUTHOR_ID`: the author namespace, for example `talpaversum`
- `AUTHOR_PRIVATE_JWK_JSON`: private signing key for licenses
- `AUTHOR_CERT_JWS`: root-signed author certificate issued by `hc-author-registry`
- `DCR_TRUSTED_CORE_JWKS_JSON`: public key set trusted for Core software statements

Core needs the matching trust material:

- `LICENSING_ROOT_JWKS_JSON`
- `LICENSING_DCR_SIGNING_PRIVATE_JWK_JSON`
- `LICENSING_DCR_SIGNING_PUBLIC_JWK_JSON`
- `LICENSING_OAUTH_CALLBACK_BASE_URL`

## Development Material

For local development only:

```bash
npm run dev:material -- --author-id=talpaversum --issuer-base-url=http://localhost:4030
```

Copy the `hc-app-licensing` section into `hc-app-licensing/.env`.
Copy the `hekatoncheiros-core` section into `hekatoncheiros-core/.env`.

Do not use generated development material in production.

## Local Compose

```bash
docker compose up -d --build
```

The issuer listens on:

- `http://localhost:4030`

For local Docker Desktop activation, use:

- public/browser issuer URL: `http://localhost:4030`
- Core-to-issuer backchannel URL: `http://host.docker.internal:4030`
- app manifest/catalog `license_issuer_url`: `http://host.docker.internal:4030`

Health check:

```bash
curl http://localhost:4030/health
```

Discovery:

```bash
curl http://localhost:4030/.well-known/hc-licensing
```

## Activation Flow

1. The app manifest declares:

   ```json
   {
     "licensing": {
       "required": true,
       "issuer_url": "https://licensing.example.com"
     }
   }
   ```

2. Core starts activation with:

   `GET /api/v1/tenants/{tenantId}/licenses/oauth/start`

3. The browser is redirected to the issuer OAuth endpoint.
4. The issuer returns to Core callback.
5. Core imports, verifies, stores, and optionally selects the issued license.

## Local Docker Networking Note

The `issuer_url` must be reachable by both Core and the browser. In production
this is a public HTTPS URL. In local Docker Desktop setups, `localhost` from the
Core container is not the host machine, so use a URL that Core can reach, such
as a reverse proxy or Docker Desktop host address, and keep the manifest/catalog
issuer URL aligned with that value.

## Current Limitations

- The OAuth authorize endpoint is a development stub and does not perform real
  user login or consent yet.
- `/v1/licenses/revoke` is a stub.
- Product/customer/grant administration UI is not implemented yet.
- The service is single-author per deployment.

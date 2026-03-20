# CLAUDE.md

## Project

Akamai SIEM Analyzer — a Harper component that ingests Akamai security events and runs tiered AI analysis (Haiku → Sonnet → Opus). Deployed on Harper Fabric.

## Commands

- `npm run dev` — start local dev server (port 9926)
- `npm test` — run all tests (`node --test test/**/*.test.js`)
- `npm run deploy` — deploy to Fabric (loads `.env` via dotenv)
- `npm run login` — interactive `.env` setup for Fabric credentials
- `npm run lint` — ESLint
- `npm run format` — Prettier

## Architecture

### Harper Resource URL Routing

Resource URLs are **case-sensitive** and match the **exported class name**, not a `static path` property:
- `export class Api extends Resource` → `/Api/{id}`
- `export class Analysis extends Resource` → `/Analysis/{id}`

### File Layout

- `resources/api.js` — Custom Resource classes (`Api`, `Analysis`, `Events`, `EventBatch`, `ExportStatus`, `Config`, `UserPicture`)
- `resources/tables.js` — Table resource classes with `allowRead`/`allowCreate`/etc. access control
- `resources/auth.js` — OAuth `onLogin` hook (user provisioning, avatar blob)
- `schemas/schema.graphql` — All table definitions
- `src/ingestion/` — Akamai SIEM API poller, decoder, normalizer, accumulator
- `src/analysis/` — Batch, summary, and strategic analyzers
- `src/utils/` — Cost tracker, config loader
- `web/` — Static dashboard (login widget pattern)
- `config.yaml` — Harper component config

### Authentication

- Google OAuth via `@harperfast/oauth` plugin
- Session check: `context.session?.oauth` (truthy = authenticated)
- User ID from session: `context.session?.user` (set by `onLogin` return value)
- Static files are NOT protected by OAuth — dashboard uses a login widget pattern (shows login card, hides dashboard until `/Api/me` confirms auth)

### Harper Globals

These are available as globals in the Harper runtime — do NOT import them:
- `Resource` — base class for custom resources
- `tables` — access to all table classes
- `createBlob(buffer)` — create a blob from a Buffer (no options object needed)
- `databases` — low-level database access

### Blob Handling

- `User.create()` for new records (triggers `@createdTime`)
- `User.put(id, data)` for updates with blob fields (blobs require `put`, not `update`)
- `put()` does NOT trigger `@createdTime` or `@updatedTime` — set timestamps manually if needed
- `createBlob(buffer)` — just pass the Buffer, no `{ type }` option

### Table Resource Search

Use array format for search criteria:
```js
Table.search([{ attribute: 'email', value: 'user@example.com' }])
```

## Environment Variables

Required in `.env`:
- `AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`, `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN`, `AKAMAI_CONFIG_ID`
- `ANTHROPIC_API_KEY`
- `OAUTH_GOOGLE_CLIENT_ID`, `OAUTH_GOOGLE_CLIENT_SECRET`, `OAUTH_REDIRECT_URI`
- `CLI_TARGET`, `CLI_TARGET_USERNAME`, `CLI_TARGET_PASSWORD` (Fabric deploy)

`OAUTH_REDIRECT_URI` must NOT include a port number on Fabric (just `https://...`).

## Deployment

- `.env` is always deployed (even if gitignored)
- Deploy: `npm run deploy` (rolling restart, replicated)
- Fabric ports: `:9925` deploy, `:9926` app, no port for public HTTPS
- `harperdb-config.yaml` settings (`authorizeLocal: false`, `enableSessions: true`) are already set on Fabric by default — don't add them to `config.yaml`

## Testing

Tests use Node.js built-in test runner. 23 tests covering decoder, normalizer, and accumulator. No API/auth integration tests yet.

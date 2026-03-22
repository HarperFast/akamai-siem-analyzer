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
- `resources/simulation.js` — Simulation mode REST API (`/Simulation/{action}`)
- `resources/lifecycle.js` — Background process startup (chooses sim-poller or real poller)
- `resources/tables.js` — Table resource classes with `allowRead`/`allowCreate`/etc. access control
- `resources/auth.js` — OAuth `onLogin` hook (user provisioning, avatar blob)
- `schemas/schema.graphql` — All table definitions
- `src/ingestion/` — Akamai SIEM API poller, decoder, normalizer, accumulator
- `src/analysis/` — Batch, summary, and strategic analyzers
- `src/simulation/` — Simulation mode: event generator, auto-generator, sim-poller
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

### Harper Records

- Do NOT spread Harper records (`{ ...record }`) — they are proxy objects and spread will lose data
- Always explicitly read each field you need: `{ field: record.field, ... }`
- Use `Table.get(id)` for single record, `Table.patch(id, partial)` for partial updates

### Table Resource Search

Use array format for search criteria:
```js
Table.search([{ attribute: 'email', value: 'user@example.com' }])
```

## Simulation Mode

Run without Akamai credentials for demos/testing. Set `SIMULATION_MODE=true` in `.env`.

### Starting simulation

1. Set `SIMULATION_MODE=true` in `.env` and start/deploy
2. POST `/Simulation/auto-start` to begin event generation (requires auth)
3. Events flow automatically: auto-generator → `siem_simulated_events` → sim-poller → normalizer → `siem_events` → accumulator → batch analyzer

### Simulation API endpoints (`/Simulation/{action}`)

- `GET /Simulation/status` — auto-generator state, pending event count
- `POST /Simulation/auto-start` — start continuous generation (params: `intervalSeconds`, `eventsPerCycle`, `scenario`)
- `POST /Simulation/auto-stop` — stop auto-generator
- `POST /Simulation/generate` — one-shot batch (params: `count`, `scenario`)
- `POST /Simulation/clear` — delete pending simulated events

### Scenarios

`credential_stuffing` (default), `sqli`, `xss`, `path_traversal`, `bot_scanner`, `clean`, `mixed`, `light`, `heavy`, `peak`

The `credential_stuffing` scenario auto-escalates through 5 phases over ~20 minutes (light → mixed → heavy → peak → taper).

### Config overrides in sim mode

- `timeCeilingSeconds` reduced from 300s to 30s for faster analysis cadence
- `configId` is `'simulation'` instead of `AKAMAI_CONFIG_ID`
- Health endpoint reports `simulationMode: true`

### Key files

- `src/simulation/generator.js` — event generation with 6 attack scenarios
- `src/simulation/auto-generator.js` — timed escalation (5 phases)
- `src/simulation/sim-poller.js` — polls simulated events, feeds standard pipeline
- `resources/simulation.js` — REST API endpoints
- `resources/lifecycle.js` — conditional startup (sim vs real poller)

## Environment Variables

Required in `.env`:
- `AKAMAI_HOST`, `AKAMAI_CLIENT_TOKEN`, `AKAMAI_CLIENT_SECRET`, `AKAMAI_ACCESS_TOKEN`, `AKAMAI_CONFIG_ID`
- `ANTHROPIC_API_KEY`
- `OAUTH_GOOGLE_CLIENT_ID`, `OAUTH_GOOGLE_CLIENT_SECRET`, `OAUTH_REDIRECT_URI`
- `CLI_TARGET`, `CLI_TARGET_USERNAME`, `CLI_TARGET_PASSWORD` (Fabric deploy)
- `SIMULATION_MODE=true` (optional — enables simulation mode, no Akamai credentials needed)

`OAUTH_REDIRECT_URI` must NOT include a port number on Fabric (just `https://...`).

## Deployment

- `.env` is always deployed (even if gitignored)
- Deploy: `npm run deploy` (rolling restart, replicated)
- Fabric ports: `:9925` deploy, `:9926` app, no port for public HTTPS
- `harperdb-config.yaml` settings (`authorizeLocal: false`, `enableSessions: true`) are already set on Fabric by default — don't add them to `config.yaml`

## Testing

Tests use Node.js built-in test runner (`node:test` + `node:assert/strict`). 53 tests covering decoder, normalizer, accumulator, simulation generator, auto-generator escalation, and cost calculation. No API/auth integration tests yet.

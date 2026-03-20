# Akamai SIEM Analyzer - Implementation Plan

## Context

We're building a new Harper component that ingests Akamai SIEM security event logs (Account Protector + Bot Manager Premier), stores them with configurable TTL, runs tiered AI analysis (Haiku/Sonnet/Opus) with adaptive triggering, and serves a streaming dashboard for security analysts. The project uses the Harper OAuth plugin with Google OIDC for authentication.

---

## Phase 0: Project Scaffolding

- Scaffold with `npm create harper@latest . -- --template vanilla`
- Install dependencies: `@harperfast/oauth`, `akamai-edgegrid`, `@anthropic-ai/sdk`
- Initialize git repo, create private GitHub remote at `HarperFast/akamai-siem-analyzer`

---

## Phase 1: Schema & Config Foundation

### GraphQL Schema (`schemas/schema.graphql`)

8 tables defined:

| Table | Expiration | Purpose |
|-------|-----------|---------|
| `User` | none | OAuth-provisioned user profiles (Blob picture) |
| `siem_events` | 7 days | Raw decoded Akamai security events |
| `siem_analysis_batch` | 90 days | Tier 1 per-batch AI analysis |
| `siem_analysis_strategic` | 180 days | Tier 2/3 summary and strategic analysis |
| `siem_offsets` | none | Polling state with lease-based leader election |
| `siem_config` | none (audited) | Runtime configuration |
| `siem_cost_tracking` | none | Daily AI cost tracking |
| `siem_exports` | 24 hours | Event export files (Blob data) |

**Key schema decisions:**
- `Date` type for all timestamps with `@createdTime`/`@updatedTime` auto-population
- `@table(expiration: N)` for automatic TTL-based eviction
- `Blob` type for binary data (profile pictures, export files)
- `@relationship(from:)` for unidirectional User lookups
- `@indexed` on frequently queried fields
- `@table(audit: true)` only on `siem_config`

### Configuration

- `config.yaml`: Harper config with OAuth plugin, schema, resources, static files
- `config/default.json`: Runtime defaults (poll intervals, analysis thresholds, cost budgets)
- `.env.example`: Akamai EdgeGrid, Anthropic, Google OAuth, Harper Fabric credentials

---

## Phase 2: Authentication (OAuth + `allow*` pattern)

- `resources/auth.js`: `onLogin` hook via `@harperfast/oauth` — find-or-create User, fetch profile picture as Blob on every login
- `resources/tables.js`: Table extensions with `allowRead`/`allowCreate`/`allowUpdate`/`allowDelete` checking OAuth session
- Two roles: `analyst` (read events/analysis) and `admin` (+ trigger analysis, modify config, view costs)
- No HarperDB user provisioning needed — `User` table is application-level

---

## Phase 3: Ingestion Pipeline

- `src/ingestion/akamai-client.js`: EdgeGrid auth, offset-mode polling, rate limiting, timeout handling
- `src/ingestion/decoder.js`: URL-decode → semicolon split → base64-decode, preserving `+` characters
- `src/ingestion/normalizer.js`: Field mapping, epoch→Date conversion, deterministic SHA-256 IDs
- `src/ingestion/poller.js`: Poll loop with lease-based leader election, batch inserts, offset persistence

**Cluster-safe polling:**
- Each node generates unique ID on startup
- Lease acquisition via `siem_offsets` table (`leaseHolder` + `leaseExpiresAt`)
- Deterministic event IDs provide idempotent upsert safety

---

## Phase 4: Analysis Engine

- `src/analysis/accumulator.js`: Buffers metadata across poll cycles, adaptive trigger logic (event count, time ceiling, severity escalation)
- `src/analysis/model-router.js`: Haiku default → Sonnet escalation → Opus strategic, with budget check
- `src/analysis/batch-analyzer.js`: Pre-prompt statistics, event sampling (deny/high-risk/high-bot/random), Anthropic API call
- `src/analysis/summary-analyzer.js`: Hourly cross-batch trend analysis via Sonnet
- `src/analysis/strategic-analyzer.js`: Daily or on-demand strategic assessment via Opus
- `src/analysis/prompts/`: Batch, summary, and strategic prompts with JSON response format
- `src/utils/cost-tracker.js`: Per-model token tracking, daily budget warning/hard cap
- `resources/lifecycle.js`: Wires accumulator→batch analyzer, starts poller and schedulers

---

## Phase 5: API Routes

Custom Resource classes in `resources/api.js` with `allow*` auth:

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/analysis/stream` | GET | analyst+ | Recent analyses |
| `/api/analysis/on-demand` | POST | admin | Trigger strategic analysis |
| `/api/analysis/{id}` | GET | analyst+ | Analysis detail |
| `/api/events/{id}` | GET | analyst+ | Event detail |
| `/api/events/batch/{batchId}` | GET | analyst+ | Events by batch |
| `/api/events/query` | POST | analyst+ | Query by IP/path/country/action |
| `/api/events/export` | POST | analyst+ | Export events (NDJSON/CSV) |
| `/api/events/export/{id}` | GET | analyst+ | Export status |
| `/api/health` | GET | analyst+ | System health |
| `/api/cost` | GET | admin | Daily cost breakdown |
| `/api/config/{key}` | PUT | admin | Update runtime config |
| `/api/me` | GET | analyst+ | Current user profile |
| `/api/user/{id}/picture` | GET | analyst+ | User profile picture |

---

## Phase 6: UI Dashboard

- `web/index.html`: Single-page layout with header, split panels, footer, lightbox
- `web/index.js`: App initialization, auth check, health polling, event handlers
- `web/stream.js`: Polling-based analysis stream with severity-colored cards
- `web/lightbox.js`: Event detail view and IP drilldown
- `web/styles.css`: Dark SOC theme with severity color palette, responsive layout
- User avatar with first-initial placeholder when picture unavailable

---

## Phase 7: Testing

- Test fixtures: raw and decoded sample events
- `test/ingestion/decoder.test.js`: Base64 decoding, `+` preservation, malformed input
- `test/ingestion/normalizer.test.js`: Field mapping, deterministic IDs, missing fields
- `test/analysis/accumulator.test.js`: Trigger logic, escalation, reset, accumulation

---

## Phase 8: Hardening & Deployment

- Customer-facing `README.md` with Mermaid architecture diagram
- `PLAN.md` (this file) committed to repo
- Security: credentials never in logs/responses/prompts, input validation
- Deploy via `npm run deploy` to Harper Fabric

---

## Opportunities for Improvement

1. **Anthropic Batch API**: 50% discount for non-time-critical summary/strategic analysis
2. **Extended prompt caching**: Optimize cache hit rates for batch analysis system prompt
3. **Event compression**: Compress less-critical fields for storage efficiency
4. **Grafana integration**: Prometheus-compatible metrics for existing monitoring stacks

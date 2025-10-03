Vercel Edge Cloaker (Next.js 14) – Hardened Bot Filter

Overview
- Edge Middleware runs a multi-layer bot filter: UA/ASN/IP, reverse DNS, behavior, fingerprint, threat intel (IPQualityScore), rate limiting, and adaptive scoring. Bots → `public/safe.html`; humans → OFFER_URL or `public/offer.html` fallback.
- Hardened modules:
  - `utils/botCheck.ts`: adaptive ensemble scoring, IPQS integration, Edge Config–driven thresholds/weights, KV-backed rate limits and honeypot boosts.
  - Multi-honeypot: hidden traps in `public/safe.html` and `public/offer.html` link to `/api/honeytrap`, `/api/decoy/feed`, and a pixel `/api/px?hp=1`.
  - `utils/nonce.ts`: HMAC-signed nonces/cookies with TTL and optional IP/TLS/fingerprint binding.
  - `utils/rateLimiter.ts`: Edge-friendly counters on Redis (Upstash) with in-memory fallback.
  - Middleware: issues a lightweight JS+PoW challenge for medium-risk sessions and fast-path for signed sessions.
  - `pages/api/verify-challenge.ts`: verifies signed nonce, PoW, CIDR binding; sets `human_signed` cookie.
  - `pages/api/logs.ts`: protected logging sink (Authorization: Bearer), no public read.
  - ASN watchlist escalation: honeypot hits promote ASN to a temporary watchlist that increases bot score.

Security Defaults
- Secrets and thresholds read from Vercel Edge Config (preferred) or environment. Never use `NEXT_PUBLIC_*` for secrets.
- All challenge/session tokens are HMAC-signed server-side with TTL.
- Optional KV (Upstash Redis REST) used for counters/bindings; graceful in-memory fallback.
- Provider trust model: Cloudflare (`req.cf.*`) and Vercel (`req.ip`/`req.geo`) are treated as trusted IP sources. Requests with only generic headers (`x-forwarded-for`) are penalized and more likely to receive a challenge.
- Cloudflare Bot/TLS signals (if available):
  - Consumes Cloudflare Bot Management score (`request.cf.botManagement.score`) when present.
  - Consumes `cf-ja3-hash` header (Enterprise) and compares against optional `JA3_BAD_LIST`.
  - These signals have strong influence (harder to spoof vs generic headers).

Local Development
- `npm install`
- `npm run dev`
- Visit `/` → humans go to OFFER_URL (if configured) or `public/offer.html`; bots go to `public/safe.html`.
- Edge Config local: `vercel env pull .env.local` (populates `EDGE_CONFIG` signed URL for SDK).

Edge Config Keys (add these items in your Edge Config store)
- `OFFER_URL` (string): destination for human redirects (https://...).
- `IPQS_API_KEY` (string): IPQualityScore API key.
- `SIGN_KEY` (string): long random HMAC secret for nonces/cookies.
- `LOGS_API_TOKEN` (string): Bearer token to authorize POST /api/logs.
- `BOT_THRESHOLD` (string number, default 0.45): challenge threshold.
- `BOT_THRESHOLD_STRICT` (string number, default 0.65): block threshold.
- Optional:
  - `RATE_LIMIT_CONFIG` (JSON): {"windowSec":10,"perIp":20,"perFp":15,"perAsn":50}
  - `WEIGHT_TABLE` (JSON): override feature weights.
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`: enable KV for counters.
- Optional logs:
  - `LOGS_LIST_KEY` (string, default `logs`): KV list key for redacted logs.
  - `LOGS_WEBHOOK_URL` (string) and `LOGS_WEBHOOK_TOKEN` (string): outbound alert/webhook.
 - Optional CF TLS/JA3:
   - `JA3_BAD_LIST` (JSON array of strings): JA3 hashes to penalize.
 - Optional A/B:
   - `EXPERIMENT_MODE` ('off'|'ab'), `EXPERIMENT_SALT`, `EXPERIMENT_SPLIT_A`, `EXPERIMENT_SPLIT_B`.
   - `BOT_THRESHOLD_A/B`, `BOT_THRESHOLD_STRICT_A/B`, `WEIGHT_TABLE_A/B`.
 - Optional analytics:
   - `ANALYTICS_API_TOKEN` bearer token for mark-conversion/mark-fraud endpoints.

Offer Configuration
- Preferred (and default): set `OFFER_URL` in Edge Config; changes take effect without redeploy after initial binding.
- Optional server-only fallback: environment variable `OFFER_URL` (no `NEXT_PUBLIC_*`).
- `public/offer.html` is a neutral, noindex placeholder. Actual redirects are server-side.

Challenge Flow
1) Middleware computes adaptive score via `utils/botCheck.isBot(req)`.
2) If score ≥ `BOT_THRESHOLD_STRICT`: rewrite to `/safe.html`.
3) If `BOT_THRESHOLD` ≤ score < `BOT_THRESHOLD_STRICT`: serve a minimal HTML challenge with PoW + WebGL probe, posting `{ token, solution, webgl, fpHash }` to `/api/verify-challenge`.
4) `/api/verify-challenge` verifies the HMAC nonce, checks the /24 CIDR binding and PoW, and enforces provider binding (Cloudflare vs Vercel) before setting `human_signed` cookie (HMAC with TTL). Future requests fast-path to offer. On Cloudflare, the nonce also carries a TLS signature hint (cipher/version) for stronger binding (verification depends on platform APIs).
5) Requests from untrusted IP sources (only generic headers) receive an extra penalty and are more likely to be challenged.

Logging
- Middleware POSTs to `/api/logs` with Authorization: `Bearer ${LOGS_API_TOKEN}`.
- Endpoint writes redacted events to KV (Upstash REST) as a capped list (LPUSH+LTRIM):
  - IP redacted to /24 (`ip_cidr`), UA hashed (`ua_hash`), decisions, reasons, score.
  - Optional webhook fanout via `LOGS_WEBHOOK_URL` (+ `LOGS_WEBHOOK_TOKEN`).

Deployment on Vercel
- Connect your Edge Config store to the project (Edge Config → Connect to Project) and add items above. Redeploy once to bind; subsequent Edge Config changes do not require redeploy.
- Optionally configure Upstash Redis (REST URL + TOKEN) in Edge Config.
- Start: `vercel` or push to main.
- Verify:
  - Add `greeting` item → visit `/welcome` → should return greeting JSON (connectivity test).
  - Visit `/` and inspect response headers `x-cloak-decision` and `x-cloak-reasons`.

Cloudflare Pages (optional)
- This repo targets Vercel Edge; CF Pages can serve the static output with reduced functionality. For full features, adapt KV and headers accordingly.

Tuning & Extensibility
- Adjust UA/ASN/CIDR lists in `utils/botCheck.ts`.
- Override weights/thresholds via Edge Config items (`WEIGHT_TABLE`, `BOT_THRESHOLD*`).
- Improve KV persistence/analytics by replacing the minimal `/api/logs` sink.
- A/B & Adaptive Scoring:
  - Experiment assignment via `utils/experiments.ts` using `EXPERIMENT_MODE=ab`, `EXPERIMENT_SALT`, and split vars `EXPERIMENT_SPLIT_A/B`.
  - Variant overrides: `BOT_THRESHOLD_{VAR}`, `BOT_THRESHOLD_STRICT_{VAR}`, `WEIGHT_TABLE_{VAR}`.
  - Telemetry endpoints to record outcomes: POST `/api/mark-conversion` and `/api/mark-fraud` (Authorization: `Bearer ${ANALYTICS_API_TOKEN}`) with `{ exp, score }`.
  - Metrics stored in KV under `metrics:exp:<VAR>:bucket:<0-9>:{conv|fraud}` for offline tuning and dashboards.

Tests
- Jest stubs provided:
  - `__tests__/nonce.test.ts` (sign/verify HMAC tokens)
  - `__tests__/botCheck.test.ts` (basic scoring expectations)
- To run tests, add Jest devDeps then `npx jest`.

Troubleshooting
- Still seeing `inactive:env-missing` in logs/headers: `OFFER_URL` is not being read. Ensure Edge Config store is connected and item exists; as a fallback set `NEXT_PUBLIC_OFFER_URL`.
- If `/welcome` returns edge-config-unavailable: connect store to project and redeploy once, or run `vercel env pull .env.local` locally.

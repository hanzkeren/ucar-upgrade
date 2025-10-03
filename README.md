Vercel Edge Cloaker (Next.js 14) – Hardened Bot Filter

Overview
- Edge Middleware runs a multi-layer bot filter: UA/ASN/IP, reverse DNS, behavior, fingerprint, threat intel (IPQualityScore), rate limiting, and adaptive scoring. Bots → `public/safe.html`; humans → OFFER_URL or `public/offer.html` fallback.
- Hardened modules:
  - `utils/botCheck.ts`: adaptive ensemble scoring, IPQS integration, Edge Config–driven thresholds/weights, KV-backed rate limits and honeypot boosts.
  - `utils/nonce.ts`: HMAC-signed nonces/cookies with TTL and optional IP/TLS/fingerprint binding.
  - `utils/rateLimiter.ts`: Edge-friendly counters on Redis (Upstash) with in-memory fallback.
  - Middleware: issues a lightweight JS+PoW challenge for medium-risk sessions and fast-path for signed sessions.
  - `pages/api/verify-challenge.ts`: verifies signed nonce, PoW, CIDR binding; sets `human_signed` cookie.
  - `pages/api/logs.ts`: protected logging sink (Authorization: Bearer), no public read.

Security Defaults
- Secrets and thresholds read from Vercel Edge Config (preferred) or environment. Never use `NEXT_PUBLIC_*` for secrets.
- All challenge/session tokens are HMAC-signed server-side with TTL.
- Optional KV (Upstash Redis REST) used for counters/bindings; graceful in-memory fallback.

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

Offer Configuration
- Preferred: set `OFFER_URL` in Edge Config; changes take effect without redeploy after initial binding.
- Fallback: env var `NEXT_PUBLIC_OFFER_URL` (server reads it if Edge Config unset).
- `public/offer.html` is a neutral, noindex placeholder. Actual redirects are server-side.

Challenge Flow
1) Middleware computes adaptive score via `utils/botCheck.isBot(req)`.
2) If score ≥ `BOT_THRESHOLD_STRICT`: rewrite to `/safe.html`.
3) If `BOT_THRESHOLD` ≤ score < `BOT_THRESHOLD_STRICT`: serve a minimal HTML challenge with PoW + WebGL probe, posting `{ token, solution, webgl, fpHash }` to `/api/verify-challenge`.
4) `/api/verify-challenge` verifies the HMAC nonce, checks the /24 CIDR binding and PoW, then sets `human_signed` cookie (HMAC with TTL). Future requests fast-path to offer.

Logging
- Middleware POSTs to `/api/logs` with Authorization: `Bearer ${LOGS_API_TOKEN}`.
- Endpoint stores a minimal presence marker in KV; adapt to persist detailed events if needed.

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

Tests
- Jest stubs provided:
  - `__tests__/nonce.test.ts` (sign/verify HMAC tokens)
  - `__tests__/botCheck.test.ts` (basic scoring expectations)
- To run tests, add Jest devDeps then `npx jest`.

Troubleshooting
- Still seeing `inactive:env-missing` in logs/headers: `OFFER_URL` is not being read. Ensure Edge Config store is connected and item exists; as a fallback set `NEXT_PUBLIC_OFFER_URL`.
- If `/welcome` returns edge-config-unavailable: connect store to project and redeploy once, or run `vercel env pull .env.local` locally.

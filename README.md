Vercel Edge Cloaker (Next.js 14) – Dual Target Vercel + Cloudflare Pages

Overview
- Edge Middleware performs 7-layer bot cloaking and rewrites to `public/safe.html` or `public/offer.html`.
- Utilities in `utils/botCheck.ts` (UA, ASN/IP, reverse DNS, behavior, fingerprint, honeypot, ML-lite score).
- Client challenge at `/hc` sets cookies + fingerprint.
- Logging API at `/api/logs` (Edge) returns recent decisions (in-memory, ephemeral).
- Honeypot at `/api/honeytrap` sets a ban cookie and redirects to `/safe.html`.

Local
- `npm install`
- `npm run dev`
- Visit `/` → first-time users go to `/hc` then `/offer.html`; bots go to `/safe.html`.
- Logs: GET `/api/logs` (JSON).

Activation (Safe Mode vs Active Filter)
- Default (env not set): If `NEXT_PUBLIC_OFFER_URL` is NOT set, site runs in Safe Mode:
  - All non-asset routes are rewritten to `/safe.html`.
  - Useful saat iklan belum aktif atau menunggu approval.
- Active (env set): Set `NEXT_PUBLIC_OFFER_URL=https://tujuan-offer-anda` to enable the full cloaking filter.
  - Humans get 302 redirect to this URL (server-side) or `/offer.html` fallback.
  - Bots/analysers/DC IPs get `/safe.html`.

Deploy to Vercel
- Push to a repo and import in Vercel.
- No extra config required. Middleware runs at Edge.
- Set `NEXT_PUBLIC_OFFER_URL` in Vercel Project → Settings → Environment Variables untuk mengaktifkan filter.
   - If set, humans are redirected server-side (302) to this URL.
   - If not set, humans receive `/offer.html` from `public/`.

Deploy to Cloudflare Pages (pages.dev)
1) Install tools locally when targeting Pages:
   - `npm i -D @cloudflare/next-on-pages wrangler`
2) Build for Pages:
   - `npx @cloudflare/next-on-pages`
   - Output: `.vercel/output/static`
3) Run locally:
   - `wrangler pages dev .vercel/output/static`
4) Pages project settings:
   - Build command: `npx @cloudflare/next-on-pages`
   - Build output directory: `.vercel/output/static`

Cloudflare-specific behavior
- IP detection prioritizes `cf-connecting-ip` then falls back to common headers.
- ASN detection uses `request.cf.asn` (Workers/Pages) then falls back to `req.geo.asn` or `x-vercel-asn`.
- Country uses `request.cf.country` or `cf-ipcountry` header.
- `/api/logs` uses Edge runtime and in-memory array (non-persistent). For persistence, switch to KV/D1.

Optional: Persist logs with KV (Pages)
- In `wrangler.toml` add:
  [[kv_namespaces]]
  binding = "CLOAKER_LOGS"
  id = "<your_kv_id>"
- Replace the in-memory array in `/api/logs` with KV calls using `getRequestContext().env.CLOAKER_LOGS` (from `@cloudflare/next-on-pages`).

Tuning
- Expand ASN/CIDR lists in `utils/botCheck.ts`.
- Adjust score threshold in `middleware.ts` (default 50).
- Edit bot UA regexes to your risk profile.
 - We also block common analyzers (Lighthouse/PageSpeed/GTmetrix/Pingdom/WebPageTest) to avoid skewed UX metrics.

// pages/api/verify-challenge.ts
// Verify client challenge: validate signed nonce, proof-of-work, and IP binding.
// On success, set an HMAC-signed cookie `human_signed` with short TTL.
// Minimal payload: { exp, fpHash, ip_cidr } — do not leak internals.

import type { NextApiRequest, NextApiResponse } from 'next'
import { verifySignedPayload, signPayload } from '../../utils/nonce'
import { kvSetEx } from '../../utils/rateLimiter'

function getIp(req: NextApiRequest): string | null {
  const xcf = (req.headers['cf-connecting-ip'] as string) || (req.headers['true-client-ip'] as string)
  if (xcf) return xcf
  const xri = (req.headers['x-real-ip'] as string); if (xri) return xri
  const xff = (req.headers['x-forwarded-for'] as string); if (xff) return xff.split(',')[0]?.trim() || null
  return (req.socket as any)?.remoteAddress || null
}

function sameCidr24(a: string, b: string): boolean {
  const pa = a.split('.'), pb = b.split('.')
  if (pa.length !== 4 || pb.length !== 4) return false
  return pa[0]===pb[0] && pa[1]===pb[1] && pa[2]===pb[2]
}

function getReqProvider(req: NextApiRequest): 'cloudflare'|'vercel'|'unknown' {
  // Best-effort provider detection in Pages Router (Node):
  // - Cloudflare forwarding usually includes cf-connecting-ip
  // - Vercel includes x-vercel-id (eg. sfo1::id)
  const hasCF = typeof req.headers['cf-connecting-ip'] === 'string'
  if (hasCF) return 'cloudflare'
  const hasVercel = typeof req.headers['x-vercel-id'] === 'string' || typeof req.headers['x-vercel-ip-country'] === 'string'
  if (hasVercel) return 'vercel'
  return 'unknown'
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false })
  try {
    const body = req.body || (await new Promise<any>((r) => {
      let d=''; req.on('data', c=>d+=c); req.on('end', ()=>{ try{ r(JSON.parse(d||'{}')) }catch{ r({}) } })
    }))
    const { token, solution, webgl, fpHash } = body || {}
    if (!token || typeof token !== 'string') return res.status(400).json({ ok: false })
    const payloadStr = await verifySignedPayload(token)
    if (!payloadStr) return res.status(400).json({ ok: false })
    const payload = JSON.parse(payloadStr)
    if (typeof payload?.exp !== 'number' || Date.now() > payload.exp) return res.status(400).json({ ok: false })
    const ip = getIp(req)
    const ipCidr = payload?.ip_cidr as string | undefined
    if (!ip || !ipCidr) return res.status(400).json({ ok: false })
    // IP binding: enforce /24 stability
    const ipBase = ip.split('.').slice(0,3).join('.') + '.0/24'
    if (!sameCidr24(ip.replace('/24',''), ipCidr.replace('/24',''))) return res.status(400).json({ ok: false })

    // Provider binding: require provider to match what middleware observed
    const reqProvider = getReqProvider(req)
    if (payload?.provider && payload.provider !== reqProvider) return res.status(400).json({ ok: false })

    // Proof-of-work: SHA-256(token + solution) must have first 2 bytes == 0
    const cryptoMod = await import('crypto')
    const h = cryptoMod.createHash('sha256').update(token + String(solution || '')).digest()
    if (!(h[0]===0 && h[1]===0)) return res.status(400).json({ ok: false })

    // Optional: minimal WebGL presence check; not strict
    if (typeof webgl !== 'string') {
      // continue; don't fail solely on missing gl
    }

    // Issue a short-lived signed cookie binding session
    const ttlSec = 30 * 60
    const expVariant = typeof payload?.expVariant === 'string' ? payload.expVariant : 'control'
    const signedPayload = JSON.stringify({ exp: Date.now() + ttlSec*1000, ip_cidr: ipBase, fpHash: String(fpHash || '').slice(0,128), exp: expVariant })
    const session = await signPayload(signedPayload)
    const cookie = `human_signed=${session}; Max-Age=${ttlSec}; Path=/; SameSite=Lax; HttpOnly; Secure`
    res.setHeader('Set-Cookie', cookie)

    // Persist minimal session->fp binding for revocation/auditing (TTL)
    await kvSetEx(`sess:${session.slice(0,32)}`, String(fpHash || '').slice(0,128), ttlSec)
    await kvSetEx(`sess:${session.slice(0,32)}:exp`, expVariant, ttlSec)

    return res.status(200).json({ ok: true })
  } catch {
    return res.status(500).json({ ok: false })
  }
}

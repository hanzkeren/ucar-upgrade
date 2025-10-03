import type { NextApiRequest, NextApiResponse } from 'next'
import { signPayload } from '../../utils/nonce'

function getIp(req: NextApiRequest): string | null {
  const xcf = (req.headers['cf-connecting-ip'] as string) || (req.headers['true-client-ip'] as string)
  if (xcf) return xcf
  const xri = (req.headers['x-real-ip'] as string); if (xri) return xri
  const xff = (req.headers['x-forwarded-for'] as string); if (xff) return xff.split(',')[0]?.trim() || null
  return (req.socket as any)?.remoteAddress || null
}

function getReqProvider(req: NextApiRequest): 'cloudflare'|'vercel'|'unknown' {
  const hasCF = typeof req.headers['cf-connecting-ip'] === 'string'
  if (hasCF) return 'cloudflare'
  const hasVercel = typeof req.headers['x-vercel-id'] === 'string' || typeof req.headers['x-vercel-ip-country'] === 'string'
  if (hasVercel) return 'vercel'
  return 'unknown'
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') return res.status(405).json({ ok: false })
  const ip = getIp(req)
  const provider = getReqProvider(req)
  if (!ip) return res.status(400).json({ ok: false })
  const cidr = ip.split('.').slice(0,3).join('.') + '.0/24'
  const payload = JSON.stringify({ exp: Date.now() + 2 * 60 * 1000, ip_cidr: cidr, provider })
  const token = await signPayload(payload)
  return res.status(200).json({ ok: true, token })
}


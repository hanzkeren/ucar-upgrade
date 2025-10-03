// pages/api/logs.ts
// Protected logging endpoint: requires Authorization: Bearer <LOGS_API_TOKEN>
// Stores logs in KV/Redis (Upstash REST) with trimming; does not expose reads.

import type { NextApiRequest, NextApiResponse } from 'next'
import { appendLog } from '../../utils/logStore'
import { kvSetEx } from '../../utils/rateLimiter'

async function edgeConfigGet<T = unknown>(key: string): Promise<T | null> {
  try {
    const mod = await import('@vercel/edge-config').catch(() => null as any)
    if (mod && typeof (mod as any).get === 'function') {
      const v = await (mod as any).get(key)
      return (v ?? null) as T | null
    }
  } catch {}
  return null
}

async function getLogsToken(): Promise<string | null> {
  const v = await edgeConfigGet<string>('LOGS_API_TOKEN')
  if (typeof v === 'string' && v.length) return v
  const env = (process.env as any)?.LOGS_API_TOKEN
  return typeof env === 'string' ? env : null
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false })
  const token = await getLogsToken()
  const auth = req.headers['authorization'] || ''
  if (!token || auth !== `Bearer ${token}`) return res.status(401).json({ ok: false })
  try {
    const body = req.body || (await new Promise<any>((r) => {
      let d=''; req.on('data', c=>d+=c); req.on('end', ()=>{ try{ r(JSON.parse(d||'{}')) }catch{ r({}) } })
    }))
    await appendLog(body)
    // Side-channel: store last score and experiment for the session if provided
    try {
      const sidPrefix = (body && typeof body.sidPrefix === 'string') ? body.sidPrefix : null
      let exp = (body && typeof body.exp === 'string') ? body.exp : null
      if (!exp && Array.isArray(body?.reasons)) {
        const ex = (body.reasons as string[]).find((r)=> r.startsWith('exp:'))
        if (ex) exp = ex.split(':',2)[1]
      }
      if (sidPrefix && typeof body.score === 'number') {
        await kvSetEx(`sid:${sidPrefix}:score`, String(body.score), 60*60)
      }
      if (sidPrefix && exp) {
        await kvSetEx(`sid:${sidPrefix}:exp`, exp, 60*60)
      }
    } catch {}
    return res.status(200).json({ ok: true })
  } catch {
    return res.status(500).json({ ok: false })
  }
}

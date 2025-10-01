import { NextRequest } from 'next/server'

type LogEntry = {
  ts: number
  path: string
  ip: string | null
  ua: string
  asn: number | string | null
  country: string | null
  decision: 'offer' | 'safe' | 'challenge' | 'bypass'
  reasons: string[]
  score: number | null
}

// Simple in-memory log store (volatile in serverless/edge)
const globalAny = globalThis as any
if (!globalAny.__LOGS) {
  globalAny.__LOGS = [] as LogEntry[]
}

export const dynamic = 'force-dynamic'
export const runtime = 'edge'

export async function GET() {
  const logs: LogEntry[] = globalAny.__LOGS
  return new Response(JSON.stringify({ count: logs.length, logs }), {
    headers: { 'content-type': 'application/json' },
  })
}

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as LogEntry
    const logs: LogEntry[] = globalAny.__LOGS
    logs.push(body)
    // cap size
    if (logs.length > 1000) logs.splice(0, logs.length - 1000)
    return new Response(JSON.stringify({ ok: true }), { headers: { 'content-type': 'application/json' } })
  } catch (e) {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: { 'content-type': 'application/json' } })
  }
}

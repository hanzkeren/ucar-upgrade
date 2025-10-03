// This public logs endpoint is disabled. Use pages/api/logs.ts with
// Authorization: Bearer <LOGS_API_TOKEN> for logging.

export const dynamic = 'force-dynamic'
export const runtime = 'edge'

export async function GET() {
  return new Response(JSON.stringify({ ok: false, error: 'disabled' }), {
    status: 410,
    headers: { 'content-type': 'application/json' },
  })
}

export async function POST() {
  return new Response(JSON.stringify({ ok: false, error: 'disabled' }), {
    status: 410,
    headers: { 'content-type': 'application/json' },
  })
}

import { NextRequest } from 'next/server'
import { isBot } from '../utils/botCheck'

function makeReq(headers: Record<string,string>, cookies: Record<string,string>, ip: string = '1.2.3.4') {
  const url = 'https://example.com/'
  const h = new Headers(headers as any)
  if (ip) h.set('x-forwarded-for', ip)
  const req = new Request(url, { headers: h }) as any
  req.cookies = {
    get(k: string){ return cookies[k] ? { name:k, value:cookies[k] } : undefined },
  }
  return req as unknown as NextRequest
}

describe('isBot scoring', () => {
  it('classifies obvious good UA as not bot (low score expected)', async () => {
    const req = makeReq({ 'user-agent':'Mozilla/5.0 Chrome/120 Safari','accept':'text/html' }, {}, '8.8.8.8')
    const out = await isBot(req)
    expect(out.score).toBeGreaterThanOrEqual(0)
    expect(out.score).toBeLessThan(0.65)
  })

  it('classifies blocked UA as bot (high score expected)', async () => {
    const req = makeReq({ 'user-agent':'curl/7.64.1','accept':'*/*' }, {}, '34.1.2.3')
    const out = await isBot(req)
    expect(out.score).toBeGreaterThanOrEqual(0.45)
  })
})


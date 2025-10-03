import { signPayload, verifySignedPayload } from '../utils/nonce'

describe('nonce sign/verify', () => {
  it('signs and verifies payload', async () => {
    const payload = JSON.stringify({ exp: Date.now() + 10000, ip_cidr: '1.2.3.0/24', fingerprintHash: 'abc' })
    const token = await signPayload(payload)
    const out = await verifySignedPayload(token)
    expect(out).toBe(payload)
  })

  it('rejects expired payload', async () => {
    const payload = JSON.stringify({ exp: Date.now() - 1, ip_cidr: '1.2.3.0/24', fingerprintHash: 'abc' })
    const token = await signPayload(payload)
    const out = await verifySignedPayload(token)
    expect(out).toBeNull()
  })
})


export async function getOfferUrlRuntime(): Promise<string | null> {
  // 1) Try Vercel Edge Config (no redeploy needed to change values)
  try {
    // Dynamically import to avoid issues on non-Vercel platforms
    const mod = await import('@vercel/edge-config').catch(() => null as any)
    if (mod && typeof (mod as any).get === 'function') {
      const v = await (mod as any).get('OFFER_URL') as unknown
      if (typeof v === 'string' && /^https?:\/\//i.test(v)) return v
    }
  } catch {
    // ignore
  }
  // 2) Fallback to environment variable (requires redeploy on Vercel)
  const env = (process.env as any)?.NEXT_PUBLIC_OFFER_URL as string | undefined
  if (env && /^https?:\/\//i.test(env)) return env
  return null
}

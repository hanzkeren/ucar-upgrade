// utils/experiments.ts
// Lightweight A/B experiment assignment and config overrides for scoring.
// - Reads EXPERIMENT_MODE ('off'|'ab'), EXPERIMENT_SALT, EXPERIMENT_SPLIT_A/B
// - Variant-specific overrides: BOT_THRESHOLD_{VAR}, BOT_THRESHOLD_STRICT_{VAR}, WEIGHT_TABLE_{VAR}

type Variant = 'control' | 'A' | 'B'

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

async function getCfgString(key: string): Promise<string | null> {
  const v = await edgeConfigGet<string>(key)
  if (typeof v === 'string' && v.length) return v
  const env = (process.env as any)?.[key]
  return typeof env === 'string' && env.length ? env : null
}

async function getCfgNumber(key: string): Promise<number | null> {
  const v = await getCfgString(key)
  if (!v) return null
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

async function getCfgJSON<T = any>(key: string): Promise<T | null> {
  const v = await getCfgString(key)
  if (!v) return null
  try { return JSON.parse(v) as T } catch { return null }
}

function hashStr(s: string): number {
  let h = 2166136261 >>> 0
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619) >>> 0
  }
  return h >>> 0
}

export async function getExperimentConfig(seed: string) : Promise<{
  variant: Variant,
  botThreshold: number,
  botThresholdStrict: number,
  weightOverride: Record<string, number> | null,
}> {
  const mode = (await getCfgString('EXPERIMENT_MODE')) || 'off'
  let variant: Variant = 'control'
  if (mode === 'ab') {
    const salt = (await getCfgString('EXPERIMENT_SALT')) || 'salt'
    const aP = Number((await getCfgString('EXPERIMENT_SPLIT_A')) || '50')
    const bP = Number((await getCfgString('EXPERIMENT_SPLIT_B')) || '0')
    const r = (hashStr(seed + ':' + salt) % 100)
    if (r < aP) variant = 'A'
    else if (r < aP + bP) variant = 'B'
    else variant = 'control'
  }
  const vt = variant.toUpperCase()
  const botThreshold = (await getCfgNumber(`BOT_THRESHOLD_${vt}`)) ?? (await getCfgNumber('BOT_THRESHOLD')) ?? 0.45
  const botThresholdStrict = (await getCfgNumber(`BOT_THRESHOLD_STRICT_${vt}`)) ?? (await getCfgNumber('BOT_THRESHOLD_STRICT')) ?? 0.65
  const weightOverride = (await getCfgJSON<Record<string, number>>(`WEIGHT_TABLE_${vt}`)) || (await getCfgJSON<Record<string, number>>('WEIGHT_TABLE')) || null
  return { variant, botThreshold, botThresholdStrict, weightOverride }
}


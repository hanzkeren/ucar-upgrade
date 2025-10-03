"use client"

import { useEffect, useRef, useState } from "react"

function canvasFingerprint(): string {
  try {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    if (!ctx) return 'noctx'
    ctx.textBaseline = 'top'
    ctx.font = '14px "Arial"'
    ctx.textBaseline = 'alphabetic'
    ctx.fillStyle = '#f60'
    ctx.fillRect(125, 1, 62, 20)
    ctx.fillStyle = '#069'
    ctx.fillText('fp-test-🙂', 2, 15)
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)'
    ctx.fillText('fp-test-🙂', 4, 17)
    const str = canvas.toDataURL()
    let hash = 0
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i)
      hash |= 0
    }
    return String(hash)
  } catch {
    return 'err'
  }
}

export default function HumanChallenge() {
  const [done, setDone] = useState(false)
  const activityRef = useRef(false)

  useEffect(() => {
    let alive = true
    ;(async () => {
      try {
        // Build a short-lived fingerprint (not stored long-term client-side)
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'unk'
        const fp = `${canvasFingerprint()}-${tz}-${navigator.language || 'n/a'}`.slice(0, 128)
        // Request server-signed nonce bound to IP/provider
        const init = await fetch('/api/challenge-nonce', { credentials: 'include' })
        const jsn = await init.json()
        if (!jsn?.ok || !jsn?.token) throw new Error('nonce')
        const token = jsn.token as string
        // Lightweight PoW: first 2 bytes of SHA-256(token+n) == 0
        const enc = new TextEncoder()
        let n = 0; let ok=false
        while(!ok && n < 200000){
          const d = enc.encode(token + String(n))
          const h = await crypto.subtle.digest('SHA-256', d)
          const b = new Uint8Array(h)
          if (b[0]===0 && b[1]===0){ ok=true; break }
          n++
        }
        const glInfo = (function(){try{const c=document.createElement('canvas');const gl=c.getContext('webgl')||c.getContext('experimental-webgl'); if(!gl) return 'nogl'; const dbg=gl.getExtension('WEBGL_debug_renderer_info'); const v=dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):'unk'; const r=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):'unk'; return (v+'|'+r).slice(0,128)}catch(e){return 'err'}})();
        const resp = await fetch('/api/verify-challenge', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ token, solution: String(n), webgl: glInfo, fpHash: fp }), credentials: 'include' })
        const out = await resp.json().catch(()=>({ok:false}))
        if (!alive) return
        setDone(true)
        if (out?.ok) window.location.replace('/')
        else window.location.replace('/safe.html')
      } catch {
        if (!alive) return
        window.location.replace('/safe.html')
      }
    })()
    return () => { alive = false }
  }, [])

  return (
    <main style={{display:'grid',placeItems:'center',minHeight:'100dvh',fontFamily:'system-ui, sans-serif'}}>
      <div style={{textAlign:'center'}}>
        <h1>Verifying you’re human…</h1>
        <p>Please wait a moment.</p>
        {done ? <p>Redirecting…</p> : null}
      </div>
    </main>
  )
}

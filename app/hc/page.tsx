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
    const markActivity = () => {
      activityRef.current = true
      document.cookie = `act=1; Max-Age=1800; Path=/; SameSite=Lax`
    }

    const onMove = () => markActivity()
    const onScroll = () => markActivity()
    const onClick = () => markActivity()

    window.addEventListener('mousemove', onMove)
    window.addEventListener('scroll', onScroll)
    window.addEventListener('click', onClick)

    // viewport check
    try {
      const vw = Math.max(document.documentElement.clientWidth, window.innerWidth || 0)
      const vh = Math.max(document.documentElement.clientHeight, window.innerHeight || 0)
      if (vw > 0 && vh > 0) markActivity()
    } catch {}

    const t = setTimeout(() => {
      // Set fingerprint + cookies and bounce back
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'unk'
      const fp = `${canvasFingerprint()}-${tz}-${navigator.language || 'n/a'}`.slice(0, 128)
      document.cookie = `fp=${encodeURIComponent(fp)}; Max-Age=1800; Path=/; SameSite=Lax`
      document.cookie = `hc=1; Max-Age=3600; Path=/; SameSite=Lax`
      setDone(true)
      // Redirect back to root
      window.location.replace('/')
    }, 1800)

    return () => {
      clearTimeout(t)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('click', onClick)
    }
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


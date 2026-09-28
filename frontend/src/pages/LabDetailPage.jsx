import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'

const ACTIVE = ['queued', 'building', 'running']

function useCountdown(deadline) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    if (!deadline) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [deadline])
  return deadline ? Math.max(0, Math.floor((deadline - now) / 1000)) : null
}

export default function LabDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [lab, setLab] = useState(null)
  const [err, setErr] = useState('')
  const [deleting, setDeleting] = useState(false)

  const refresh = () => api.lab(id).then(setLab).catch((e) => setErr(e.message))

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 2500)
    return () => clearInterval(t)
  }, [id])

  const deadline = useMemo(() => {
    if (lab?.started_at) return new Date(lab.started_at).getTime() + lab.ttl_minutes * 60000
    return null
  }, [lab?.started_at, lab?.ttl_minutes])
  const remaining = useCountdown(deadline)

  async function destroy() {
    setDeleting(true)
    try {
      await api.deleteLab(id)
      navigate('/labs')
    } catch (e) {
      setErr(e.message)
      setDeleting(false)
    }
  }

  if (err) return <div className="error-box">{err}</div>
  if (!lab) return <div className="muted pulse">loading…</div>

  const building = ACTIVE.includes(lab.status)
  const mm = Math.floor((remaining ?? 0) / 60)
  const ss = (remaining ?? 0) % 60

  return (
    <div className="lab-detail">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <h1 style={{ fontFamily: 'var(--mono)', fontSize: 22, margin: 0 }}>Lab L{String(lab.id).padStart(3, '0')} · {lab.name}</h1>
        <span className={`status ${lab.status}`}>{lab.status}</span>
      </div>

      <div className="muted small">
        {lab.source === 'ai' ? 'AI-generated' : 'default lab'} {lab.vuln_slug && <>· vuln: <span className="mono">{lab.vuln_slug}</span></>}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }} className="metric">
          <div><div className="n" style={{ color: 'var(--accent)' }}>{lab.ttl_minutes}</div><div className="l">TTL (min)</div></div>
          <div><div className="n" style={{ color: lab.status === 'running' ? 'var(--blue)' : 'var(--muted)' }}>{remaining === null ? '—' : `${mm}:${String(ss).padStart(2, '0')}`}</div><div className="l">auto-teardown in</div></div>
          <div><div className="n">{lab.container_id ? lab.container_id.slice(0, 12) : '—'}</div><div className="l">container</div></div>
      </div>)

      {lab.description && <p className="muted">{lab.description}</p>}

      {lab.error && lab.status === 'error' && (
        <div className="error-box">
          <b>This lab failed to launch.</b>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{lab.error}</pre>
        </div>
      )}

      {lab.status === 'queued' || lab.status === 'building' ? (
        <div className="card pulse">
          <div className="muted mono">building &amp; sandboxing the target…</div>
          <div className="small muted" style={{ marginTop: 8 }}>
            pulling base image, copying your app, dockerizing, binding to a random localhost port.
          </div>
        </div>
      ) : null}

      {lab.status === 'running' && (
        <>
          <a className="url-box" href={lab.url} target="_blank" rel="noreferrer">
            <span className="dot" />
            <span>live target → <span className="mono">{lab.url}</span></span>
            <span className="muted small">(open in new tab / attack with Burp or curl)</span>
          </a>

          <div className="msg">
            🎯 <b>Objective:</b>{' '}
            {lab.description || 'Find and exploit the intended vulnerability, then retrieve the flag. The flag is only reachable through the intended attack.'}
          </div>
          <div className="hint">
            You attack from <span className="mono">http://127.0.0.1:{lab.port}</span>. The container has no internet
            egress, runs unprivileged with capped RAM/CPU, and is destroyed automatically{' '}
            {lab.ttl_minutes} minutes after it boots — or when you click destroy.
          </div>
        </>
      )}

      {lab.status === 'stopped' && (
        <div className="msg">☠️ This lab has been destroyed. Create a new one from the topic or the lab console.</div>
      )}

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <Link to="/labs" className="btn">← lab console</Link>
        {ACTIVE.includes(lab.status) && (
          <button className="btn danger" onClick={destroy} disabled={deleting}>
            {deleting ? 'Destroying…' : '☠️ Destroy lab'}
          </button>
        )}
      </div>
    </div>
  )
}
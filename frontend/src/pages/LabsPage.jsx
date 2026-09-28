import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'

export default function LabsPage() {
  const [labs, setLabs] = useState([])
  const [err, setErr] = useState('')
  const [prompt, setPrompt] = useState('')
  const [busy, setBusy] = useState(false)

  const refresh = () => api.labs().then(setLabs).catch((e) => setErr(e.message))

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 4000)
    return () => clearInterval(t)
  }, [])

  async function aiCreate() {
    if (prompt.trim().length < 5 || busy) return
    setBusy(true)
    try {
      const lab = await api.createAiLab(prompt.trim())
      setPrompt('')
      window.location.href = `/lab/${lab.id}`
    } catch (e) {
      setErr(e.message)
      setBusy(false)
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <h1 style={{ fontFamily: 'var(--mono)', fontSize: 24, margin: 0 }}>
          🔥 Lab console <span className="muted small">— live targets, auto-destroyed</span>
        </h1>
        <Link to="/" className="small muted">← roadmap</Link>
      </div>

      <div className="card" style={{ margin: '20px 0' }}>
        <div className="progress-card">
          <h3>⚡ AI-generate a lab</h3>
        </div>
        <textarea
          className="ai-prompt"
          placeholder='e.g. "Flask app with a file upload vulnerable to path traversal, flag in /etc/lab-flag.txt"'
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
        <div style={{ display: 'flex', gap: 12, marginTop: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <button className="btn primary" onClick={aiCreate} disabled={busy || prompt.trim().length < 5}>
            {busy ? 'AI is building…' : '⚡ AI create + dockerize'}
          </button>
          <span className="small muted">
            Code → Dockerfile → image → sandboxed container on <span className="mono">127.0.0.1:random</span>
          </span>
        </div>
        {err && <div className="error-box" style={{ marginTop: 12 }}>{err}</div>}
      </div>

      <div className="card">
        <table className="lab-table">
          <thead>
            <tr>
              <th>#</th><th>Lab</th><th>Type</th><th>Status</th><th>URL</th><th></th>
            </tr>
          </thead>
          <tbody>
            {labs.length === 0 && (
              <tr><td colSpan={6} className="muted small">No labs yet. Launch one from a topic, or AI-generate one above.</td></tr>
            )}
            {labs.map((l) => (
              <tr key={l.id}>
                <td className="mono muted">L{String(l.id).padStart(3, '0')}</td>
                <td>
                  <Link to={`/lab/${l.id}`}>{l.name}</Link>
                  <div className="small muted">{l.source}</div>
                </td>
                <td><span className="badge">{l.source === 'ai' ? 'AI' : 'default'}</span></td>
                <td><span className={`status ${l.status}`}>{l.status}</span></td>
                <td className="mono small">{l.status === 'running' ? l.url : '—'}</td>
                <td>
                  {l.status === 'running' && (
                    <button className="btn danger small" onClick={async () => { await api.deleteLab(l.id); refresh() }}>
                      destroy
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
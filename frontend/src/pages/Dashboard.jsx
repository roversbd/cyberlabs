import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'

export default function Dashboard() {
  const [topics, setTopics] = useState([])
  const [stats, setStats] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api.topics().then(setTopics).catch((e) => setErr(e.message))
    api.stats().then(setStats).catch(() => {})
  }, [])

  return (
    <div>
      <div className="hero">
        <h1>
          learn bug bounty &amp; pentesting <span className="accent">by attacking</span>
        </h1>
        <p>
          Pick a topic, read the theory for each vulnerability, then <b>attack a real lab</b>.
          Launch a ready-made default lab, or let AI generate + dockerize a brand new target
          from a one-line prompt. When you're done, the machine is destroyed.
        </p>
      </div>

      {err && <div className="error-box">{err}</div>}

      {stats && (
        <div className="stats">
          <div className="stat card"><div className="num">{stats.total_topics}</div><div className="lbl">Topics</div></div>
          <div className="stat card"><div className="num">{stats.total_vulns}</div><div className="lbl">Vulns to learn</div></div>
          <div className="stat card"><div className="num">{stats.learned}</div><div className="lbl">Learned</div></div>
          <div className="stat card"><div className="num">{stats.wins}</div><div className="lbl">Lab wins</div></div>
          <div className="stat card"><div className="num">{stats.xp_total}</div><div className="lbl">XP</div></div>
          <div className="stat card"><div className="num" style={stats.active_labs ? { color: 'var(--orange)' } : {}}>{stats.active_labs}</div><div className="lbl">Active labs</div></div>
        </div>
      )}

      <div className="topics">
        {topics.length === 0 && (
          <div className="card" style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '40px 20px' }}>
            <h3 style={{ margin: '0 0 8px' }}>No topics yet</h3>
            <p className="muted small" style={{ margin: 0 }}>
              Content is empty on purpose. Add topics and vulnerabilities to
              <span className="mono"> backend/app/seed.py</span>, then reset the
              database.
            </p>
          </div>
        )}
        {topics.map((t) => {
          const pct = t.total_vulns ? Math.round((t.completed_vulns / t.total_vulns) * 100) : 0
          return (
            <Link to={`/topic/${t.slug}`} key={t.id} className="topic-card" style={{ ['--tcolor']: t.color }}>
              <div className="icon">{t.icon}</div>
              <h3>{t.name}</h3>
              <p>{t.tagline}</p>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }} className="small">
                <span className="muted">{t.completed_vulns}/{t.total_vulns} vulns</span>
                <span className="muted">{pct}%</span>
              </div>
              <div className="bar"><div style={{ width: `${pct}%` }} /></div>
            </Link>
          )
        })}
      </div>
    </div>
  )
}
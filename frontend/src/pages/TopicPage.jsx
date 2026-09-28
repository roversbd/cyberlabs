import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api } from '../api'

const DIFF = {
  apprentice: 'Apprentice',
  practitioner: 'Practitioner',
  expert: 'Expert',
}

export default function TopicPage() {
  const { slug } = useParams()
  const [topic, setTopic] = useState(null)
  const [err, setErr] = useState('')
  const [showMap, setShowMap] = useState(false)
  const [tab, setTab] = useState('all')

  useEffect(() => {
    api.topic(slug).then(setTopic).catch((e) => setErr(e.message))
  }, [slug])

  if (err) return <div className="error-box">{err}</div>
  if (!topic) return <div className="muted pulse">loading…</div>

  const theory = topic.vulns.filter((v) => !v.default_lab_slug)
  const labs = topic.vulns.filter((v) => v.default_lab_slug)

  const shown =
    tab === 'theory' ? theory : tab === 'labs' ? labs : topic.vulns

  // Labs carry the learner's catalogue number in sort_order; theory modules
  // sort ahead of them with negative values and are not numbered.
  const rowIndex = (v) => (v.default_lab_slug ? v.sort_order : null)

  const byDifficulty = (list) =>
    ['apprentice', 'practitioner', 'expert']
      .map((d) => [d, list.filter((v) => v.difficulty === d)])
      .filter(([, group]) => group.length)

  return (
    <div>
      <Link to="/" className="small muted">← roadmap</Link>

      <div className="hero" style={{ marginTop: 10 }}>
        <h1 style={{ fontFamily: 'var(--mono)' }}>{topic.icon} {topic.name}</h1>
        {topic.description && (
          <div className="markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{topic.description}</ReactMarkdown>
          </div>
        )}
        <div className="muted small">
          {labs.length} labs &nbsp;·&nbsp; {theory.length} theory modules &nbsp;·&nbsp;{' '}
          progress: {topic.completed_vulns}/{topic.total_vulns}
          {topic.total_vulns
            ? ` (${Math.round((topic.completed_vulns / topic.total_vulns) * 100)}%)`
            : ''}
        </div>
      </div>

      {topic.learning_map && (
        <section className="map-block">
          <button className="btn toggle" onClick={() => setShowMap((s) => !s)}>
            {showMap ? '▾' : '▸'} Learning map
          </button>
          {showMap && (
            <div className="card markdown" style={{ marginTop: 10 }}>
              <ReactMarkdown remarkPlugins={[remarkGfm]}>
                {topic.learning_map}
              </ReactMarkdown>
            </div>
          )}
        </section>
      )}

      <div className="tabs">
        {[
          ['all', `All ${topic.vulns.length}`],
          ['theory', `Theory ${theory.length}`],
          ['labs', `Labs ${labs.length}`],
        ].map(([k, label]) => (
          <button
            key={k}
            className={`tab ${tab === k ? 'on' : ''}`}
            onClick={() => setTab(k)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'all'
        ? ['theory', 'labs'].map((group) => {
            const list = group === 'theory' ? theory : labs
            if (!list.length) return null
            return (
              <section key={group} className="lesson-group">
                <h2 className="group-title">
                  {group === 'theory' ? 'Theory' : 'Labs'}
                </h2>
                {byDifficulty(list).map(([diff, group2]) => (
                  <div key={diff} className="difficulty-group">
                    <h3 className="difficulty-title">
                      <span className={`badge ${diff}`}>{DIFF[diff]}</span>
                    </h3>
                    <div className="vuln-list">
                      {group2.map((v) => (
                        <Link to={`/vuln/${v.id}`} key={v.id} className="vuln-row">
                          <span className="idx">
                            {rowIndex(v) ?? '·'}
                          </span>
                          <div className="grow">
                            <h4>
                              {v.name}{' '}
                              {v.default_lab_slug && (
                                <span className="badge" style={{ color: 'var(--blue)', borderColor: 'var(--blue)' }}>
                                  lab
                                </span>
                              )}
                              {v.category && !v.default_lab_slug && (
                                <span className="badge cat">{v.category}</span>
                              )}
                            </h4>
                            <p>{v.summary}</p>
                          </div>
                          <span className="xp">+{v.xp} xp</span>
                        </Link>
                      ))}
                    </div>
                  </div>
                ))}
              </section>
            )
          })
        : (
          <div className="vuln-list">
            {shown.map((v) => (
              <Link to={`/vuln/${v.id}`} key={v.id} className="vuln-row">
                <span className="idx">{rowIndex(v) ?? '·'}</span>
                <div className="grow">
                  <h4>{v.name}</h4>
                  <p>{v.summary}</p>
                </div>
                <span className={`badge ${v.difficulty}`}>
                  {DIFF[v.difficulty] || v.difficulty}
                </span>
                <span className="xp">+{v.xp} xp</span>
              </Link>
            ))}
          </div>
        )}
    </div>
  )
}

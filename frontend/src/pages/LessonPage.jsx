import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { api } from '../api'

const DIFF_LABEL = {
  apprentice: 'Apprentice',
  practitioner: 'Practitioner',
  expert: 'Expert',
}

const DIFF_HINT = {
  apprentice: 'Foundational. One weakness, one clear signal.',
  practitioner: 'Needs two or more steps, or reading past the obvious.',
  expert: 'Chained, multi-request, or requires understanding the architecture.',
}

// The learner's own words must never be read as evidence by the server, so this
// is a client-side guard, not a security control.
function HintStack({ hints }) {
  const [open, setOpen] = useState(0)
  if (!hints?.length) return null
  return (
    <div className="hint-stack">
      {hints.map((h, i) => (
        <div key={i} className={`hint-step ${i < open ? 'open' : ''}`}>
          {i < open ? (
            <>
              <div className="hint-step-label">Hint {i + 1}</div>
              <div className="hint-step-body">{h}</div>
            </>
          ) : (
            <button className="hint-reveal" onClick={() => setOpen(i + 1)}>
              {i === 0 ? 'Need a nudge?' : `Reveal hint ${i + 1} of ${hints.length}`}
            </button>
          )}
        </div>
      ))}
    </div>
  )
}

function Solution({ vulnId }) {
  const [text, setText] = useState(null)
  const [asking, setAsking] = useState(false)
  const [confirming, setConfirming] = useState(false)

  async function load() {
    setAsking(true)
    try {
      const r = await api.solution(vulnId)
      setText(r.solution)
    } catch (e) {
      setText(`Could not load the walkthrough: ${e.message}`)
    } finally {
      setAsking(false)
      setConfirming(false)
    }
  }

  if (text) {
    return (
      <div className="card markdown solution-body">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
      </div>
    )
  }
  if (confirming) {
    return (
      <div className="card solution-confirm">
        <p>
          <b>This is the full answer.</b> Read the theory, the remediation and the
          detection notes first — the walkthrough is the last step, not the first.
        </p>
        <div className="row gap">
          <button className="btn primary" onClick={load} disabled={asking}>
            {asking ? 'Loading…' : 'Show the walkthrough'}
          </button>
          <button className="btn" onClick={() => setConfirming(false)}>
            Not yet
          </button>
        </div>
      </div>
    )
  }
  return (
    <button className="btn solution-btn" onClick={() => setConfirming(true)}>
      ⚠ Show the full solution
    </button>
  )
}

function Field({ label, children, wide }) {
  if (!children) return null
  return (
    <div className={`field ${wide ? 'wide' : ''}`}>
      <div className="field-label">{label}</div>
      <div className="field-body">{children}</div>
    </div>
  )
}

export default function LessonPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [vuln, setVuln] = useState(null)
  const [progress, setProgress] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [methodologyOpen, setMethodologyOpen] = useState(false)

  useEffect(() => {
    api.vuln(id).then(setVuln).catch((e) => setErr(e.message))
    api.progress(id).then(setProgress).catch(() => {})
  }, [id])

  async function launchDefault() {
    setBusy('default')
    setErr('')
    try {
      const lab = await api.createDefaultLab(vuln.slug)
      navigate(`/lab/${lab.id}`)
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy('')
    }
  }

  async function markLearned() {
    const p = await api.updateProgress(vuln.id, { completed: true })
    setProgress(p)
  }

  if (err && !vuln) return <div className="error-box">{err}</div>
  if (!vuln) return <div className="muted pulse">loading…</div>

  const learned = progress?.completed
  const hasLab = !!vuln.default_lab_slug
  const solved = progress?.lab_win

  return (
    <div className="lesson">
      <Link to={`/topic/${vuln.topic_slug}`} className="small muted">← topic</Link>

      {/* 1 · Title  2 · Difficulty  3 · Category */}
      <div className="lesson-head">
        {hasLab && <div className="lab-number">Lab {vuln.sort_order}</div>}
        <h1>{vuln.name}</h1>
        <div className="lesson-meta">
          <span className={`badge ${vuln.difficulty}`}>
            {DIFF_LABEL[vuln.difficulty] || vuln.difficulty}
          </span>
          {vuln.category && <span className="badge cat">{vuln.category}</span>}
          <span className="badge">+{vuln.xp} xp</span>
          {learned && <span className="badge done">✓ learned</span>}
          {solved && <span className="badge solved">🚩 solved</span>}
        </div>
        {vuln.difficulty && (
          <div className="small muted" style={{ marginTop: 8 }}>
            {DIFF_HINT[vuln.difficulty]}
          </div>
        )}
        <p className="lesson-summary">{vuln.summary}</p>
      </div>

      {err && <div className="error-box">{err}</div>}

      {/* 4 · Scenario  5 · Objective */}
      {(vuln.scenario || vuln.objectives?.length > 0) && (
        <div className="lesson-grid">
          <Field label="Scenario" wide>
            <p>{vuln.scenario}</p>
          </Field>
          {vuln.objectives?.length > 0 && (
            <Field label="What you will practise" wide>
              <ul>
                {vuln.objectives.map((o, i) => (
                  <li key={i}>{o}</li>
                ))}
              </ul>
            </Field>
          )}
        </div>
      )}

      {/* Lab block: 6 URL, 7 credentials, 8 start, 9 testing, 10 success, 11 reset */}
      {hasLab ? (
        <section className="lab-block">
          <h2>Lab</h2>

          <Field label="Application URL">
            Launch the lab, then open the URL it gives you. Each lab runs in its own
            isolated container and is torn down when you stop it or when its TTL expires.
          </Field>

          <Field label="Credentials" wide>
            <pre className="kv">{vuln.starting_credentials || 'None required — see the scenario.'}</pre>
          </Field>

          <Field label="Endpoints in scope" wide>
            <pre className="kv">{vuln.endpoints}</pre>
          </Field>

          <Field label="Application behaviour" wide>
            <p>{vuln.application_behaviour}</p>
          </Field>

          <button
            className="btn primary big"
            onClick={launchDefault}
            disabled={busy === 'default'}
          >
            {busy === 'default' ? 'Launching…' : '▶ Start Lab'}
          </button>

          <Field label="Testing with Burp" wide>
            <p>
              Point a browser at the lab, then configure Burp's proxy to
              <code> 127.0.0.1:8080</code> and browse to the application URL. Every
              request and response will land in the Proxy → HTTP history, so you can send
              interesting ones to Repeater, vary parameters, and compare responses. Drive
              the wordlist attacks from <code>Intruder</code>. Keep the lab running while
              you work — it stops automatically after its TTL.
            </p>
          </Field>

          <Field label="Success condition" wide>
            <p className="success-line">🚩 {vuln.success_condition || vuln.lab_objective}</p>
          </Field>

          <Field label="Reset Lab" wide>
            <p>
              Your state lives in the container, not in the shared database, so a lab run is
              already clean when you start it. To get a fresh copy, stop the lab and launch
              it again — that destroys the container and its SQLite file and seeds a new
              flag. Nothing you did to one run carries into the next.
            </p>
          </Field>
        </section>
      ) : (
        <section className="lab-block theory-only">
          <h2>Lab</h2>
          <p className="muted">
            This is a theory module. It has no runnable application — the labs that follow
            put it into practice.
          </p>
        </section>
      )}

      {/* 12 · Progressive hints */}
      {vuln.hints?.length > 0 && (
        <section className="hints-block">
          <h2>Hints</h2>
          <p className="small muted">
            Work the problem before you open these. Each one is more explicit than the last,
            and the last is very close to the answer.
          </p>
          <HintStack hints={vuln.hints} />
        </section>
      )}

      {/* 13 · Theory */}
      <section className="theory-block">
        <h2>Theory</h2>
        <div className="card markdown">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{vuln.theory}</ReactMarkdown>
        </div>
      </section>

      {/* Method + references live with the theory, not as a separate answer key */}
      {vuln.methodology && (
        <section className="method-block">
          <button
            className="btn toggle"
            onClick={() => setMethodologyOpen((o) => !o)}
          >
            {methodologyOpen ? '▾' : '▸'} How a tester approaches this
          </button>
          {methodologyOpen && (
            <div className="card markdown" style={{ marginTop: 10 }}>
              <p>{vuln.methodology}</p>
            </div>
          )}
        </section>
      )}

      {/* 14 · Remediation  15 · Detection */}
      {(vuln.remediation || vuln.detection) && (
        <section className="fix-grid">
          {vuln.remediation && (
            <div className="card fix-card">
              <h3>Remediation</h3>
              <div className="markdown">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {vuln.remediation}
                </ReactMarkdown>
              </div>
            </div>
          )}
          {vuln.detection && (
            <div className="card fix-card">
              <h3>Detection</h3>
              <div className="markdown">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {vuln.detection}
                </ReactMarkdown>
              </div>
            </div>
          )}
        </section>
      )}

      {vuln.references && (
        <section className="refs-block">
          <h2>References</h2>
          <div className="card markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{vuln.references}</ReactMarkdown>
          </div>
        </section>
      )}

      <section className="solution-block">
        <h2>Solution</h2>
        <Solution vulnId={vuln.id} />
      </section>

      <div className="lesson-foot">
        <button className="btn" onClick={markLearned} disabled={learned}>
          {learned ? '✓ Marked as learned' : 'Mark as learned'}
        </button>
        <Link to={`/topic/${vuln.topic_slug}`} className="btn">
          ← Back to {vuln.topic_slug}
        </Link>
      </div>
    </div>
  )
}

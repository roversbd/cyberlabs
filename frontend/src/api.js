const API = '/api'

async function request(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      const body = await res.json()
      msg = body.detail || msg
    } catch {
      /* ignore */
    }
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
  return res.json()
}

export const api = {
  topics: () => request('/topics'),
  topic: (slug) => request(`/topics/${slug}`),
  vuln: (id) => request(`/vulns/${id}`),
  solution: (id) => request(`/vulns/${id}/solution`, { method: 'POST' }),
  stats: () => request('/stats'),
  labs: () => request('/labs'),
  lab: (id) => request(`/labs/${id}`),
  createDefaultLab: (vulnSlug) =>
    request('/labs/default', { method: 'POST', body: JSON.stringify({ vuln_slug: vulnSlug }) }),
  createAiLab: (prompt, vulnSlug = '') =>
    request('/labs/ai', { method: 'POST', body: JSON.stringify({ prompt, vuln_slug: vulnSlug }) }),
  deleteLab: (id) => request(`/labs/${id}`, { method: 'DELETE' }),
  progress: (vulnId) => request(`/progress/${vulnId}`),
  updateProgress: (vulnId, data) =>
    request(`/progress/${vulnId}`, { method: 'POST', body: JSON.stringify(data) }),
}
import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import TopicPage from './pages/TopicPage'
import LessonPage from './pages/LessonPage'
import LabsPage from './pages/LabsPage'
import LabDetailPage from './pages/LabDetailPage'

export default function App() {
  return (
    <>
      <nav className="navbar">
        <NavLink to="/" className="logo">
          cyber<span className="accent">labs</span>
        </NavLink>
        <div className="nav-links">
          <NavLink to="/" end>Roadmap</NavLink>
          <NavLink to="/labs">Labs</NavLink>
        </div>
        <div className="nav-spacer" />
        <span className="small muted mono">learn → attack → destroy</span>
      </nav>

      <main className="container">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/topic/:slug" element={<TopicPage />} />
          <Route path="/vuln/:id" element={<LessonPage />} />
          <Route path="/labs" element={<LabsPage />} />
          <Route path="/lab/:id" element={<LabDetailPage />} />
        </Routes>
      </main>
    </>
  )
}
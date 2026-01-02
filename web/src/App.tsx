import { Routes, Route, Link } from 'react-router-dom'
import './App.css'
import Dashboard from './pages/Dashboard'

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Pola PCE Dashboard</h1>
        <nav className="app-nav">
          <Link to="/" className="nav-link">Dashboard</Link>
        </nav>
      </header>
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
        </Routes>
      </main>
    </div>
  )
}

export default App

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import Landing from './Landing'
import Leaderboard from './Leaderboard'
import './index.css'

function Router() {
  const path = window.location.pathname;
  if (path === '/dashboard') return <App />;
  if (path === '/leaderboard') return <Leaderboard />;
  return <Landing />;
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Router />
  </React.StrictMode>,
)

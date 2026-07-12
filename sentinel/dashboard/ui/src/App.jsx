import React, { useState } from 'react'
import { Activity, ShieldAlert, BarChart3, ShieldCheck } from 'lucide-react'
import LiveFeed from './components/LiveFeed'
import IncidentDrillDown from './components/IncidentDrillDown'
import PolicyMetrics from './components/PolicyMetrics'
import './index.css'

function App() {
  const [currentView, setCurrentView] = useState('feed') // 'feed', 'metrics'
  const [selectedIncident, setSelectedIncident] = useState(null)

  const handleIncidentSelect = (incident) => {
    setSelectedIncident(incident)
  }

  const handleBackToFeed = () => {
    setSelectedIncident(null)
  }

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck className="brand-icon" size={32} />
          <span>Sentinel</span>
        </div>
        
        <div className="nav-links">
          <div 
            className={`nav-item ${currentView === 'feed' ? 'active' : ''}`}
            onClick={() => { setCurrentView('feed'); setSelectedIncident(null); }}
          >
            <Activity size={20} />
            Live Feed
          </div>
          <div 
            className={`nav-item ${currentView === 'metrics' ? 'active' : ''}`}
            onClick={() => { setCurrentView('metrics'); setSelectedIncident(null); }}
          >
            <BarChart3 size={20} />
            Policy Metrics
          </div>
        </div>
      </aside>

      <main className="main-content">
        {currentView === 'feed' && !selectedIncident && (
          <LiveFeed onSelectIncident={handleIncidentSelect} />
        )}
        
        {currentView === 'feed' && selectedIncident && (
          <IncidentDrillDown 
            incident={selectedIncident} 
            onBack={handleBackToFeed} 
          />
        )}

        {currentView === 'metrics' && (
          <PolicyMetrics />
        )}
      </main>
    </div>
  )
}

export default App

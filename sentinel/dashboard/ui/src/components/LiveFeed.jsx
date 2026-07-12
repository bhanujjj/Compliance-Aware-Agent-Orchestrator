import React, { useState, useEffect } from 'react'

const MOCK_INCIDENTS = [
  { incident_id: 'INC-A1B2', severity: 9.5, attack_type: 'Heartbleed', timestamp: '2026-07-12T00:32:00Z', status: 'ESCALATED' },
  { incident_id: 'INC-C3D4', severity: 7.2, attack_type: 'Infiltration', timestamp: '2026-07-12T00:30:15Z', status: 'MITIGATED' },
  { incident_id: 'INC-E5F6', severity: 4.1, attack_type: 'SSH-Patator', timestamp: '2026-07-12T00:25:40Z', status: 'BLOCKED' },
  { incident_id: 'INC-G7H8', severity: 2.0, attack_type: 'PortScan', timestamp: '2026-07-12T00:15:22Z', status: 'LOGGED' }
]

function getSeverityBadgeClass(severity) {
  if (severity >= 8.0) return 'critical'
  if (severity >= 6.0) return 'high'
  if (severity >= 4.0) return 'medium'
  return 'low'
}

function getStatusColor(status) {
  if (status === 'ESCALATED') return 'var(--accent-red)'
  if (status === 'REJECTED') return 'var(--accent-orange)'
  if (status === 'LOGGED') return 'var(--accent-green)'
  return 'var(--text-muted)'
}

export default function LiveFeed({ onSelectIncident }) {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [currentPage, setCurrentPage] = useState(1)
  const itemsPerPage = 30

  useEffect(() => {
    let ws = null
    let reconnectTimer = null
    const connect = () => {
      ws = new WebSocket('ws://localhost:8000/ws/incidents')
      ws.onopen = () => {
        console.log('[Sentinel] WebSocket connected — live feed active')
        setLoading(false)
      }
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (Array.isArray(data) && data.length > 0) {
            setIncidents(data)
            setLoading(false)
          }
        } catch (e) {
          console.warn('[Sentinel] Failed to parse WebSocket message', e)
        }
      }
      ws.onerror = () => {
        console.warn('[Sentinel] WebSocket error — falling back to mock data')
        setIncidents(MOCK_INCIDENTS)
        setLoading(false)
      }
      ws.onclose = () => {
        console.log('[Sentinel] WebSocket closed — reconnecting in 5s...')
        reconnectTimer = setTimeout(connect, 5000)
      }
    }
    connect()
    // Cleanup on component unmount
    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) ws.close()
    }
  }, [])

  if (loading) return <div>Loading live feed...</div>

  const totalPages = Math.ceil(incidents.length / itemsPerPage)
  const indexOfLastItem = currentPage * itemsPerPage
  const indexOfFirstItem = indexOfLastItem - itemsPerPage
  const currentIncidents = incidents.slice(indexOfFirstItem, indexOfLastItem)

  const handleNextPage = () => {
    if (currentPage < totalPages) setCurrentPage(currentPage + 1)
  }

  const handlePrevPage = () => {
    if (currentPage > 1) setCurrentPage(currentPage - 1)
  }

  return (
    <div>
      <h1>Live Feed</h1>
      <p className="subtitle">Real-time incident governance and response queue</p>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          background: 'rgba(0, 255, 128, 0.1)', border: '1px solid rgba(0,255,128,0.3)',
          borderRadius: '20px', padding: '4px 12px', fontSize: '12px', fontWeight: 600,
          color: 'var(--accent-green)'
        }}>
          <span style={{
            width: '8px', height: '8px', borderRadius: '50%',
            background: 'var(--accent-green)',
            animation: 'pulse 1.5s ease-in-out infinite'
          }} />
          LIVE
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
          Auto-refreshes every 3 seconds
        </span>
      </div>
      <div className="glass-card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Incident ID</th>
              <th>Time</th>
              <th>Attack Type</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {currentIncidents.map(inc => (
              <tr key={inc.incident_id} onClick={() => onSelectIncident(inc)}>
                <td style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{inc.incident_id}</td>
                <td style={{ color: 'var(--text-muted)' }}>{new Date(inc.last_seen ?? inc.timestamp).toLocaleTimeString()}</td>
                <td>{inc.attack_type || 'Multiple'}</td>
                <td>
                  <span className={`badge ${getSeverityBadgeClass(inc.highest_severity ?? inc.severity ?? 0)}`}>
                    {Number(inc.highest_severity ?? inc.severity ?? 0).toFixed(1)}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: getStatusColor(inc.status) }}>
                    {inc.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '20px', padding: '10px 0', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
            <span style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
              Showing {indexOfFirstItem + 1} to {Math.min(indexOfLastItem, incidents.length)} of {incidents.length} incidents
            </span>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button 
                onClick={handlePrevPage} 
                disabled={currentPage === 1}
                style={{
                  background: currentPage === 1 ? 'rgba(255,255,255,0.05)' : 'rgba(255,255,255,0.1)',
                  color: currentPage === 1 ? 'rgba(255,255,255,0.3)' : '#fff',
                  border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
                }}>
                Previous
              </button>
              <span style={{ display: 'flex', alignItems: 'center', margin: '0 10px', fontSize: '14px' }}>
                Page {currentPage} of {totalPages}
              </span>
              <button 
                onClick={handleNextPage} 
                disabled={currentPage === totalPages}
                style={{
                  background: currentPage === totalPages ? 'rgba(255,255,255,0.05)' : 'var(--accent-blue)',
                  color: currentPage === totalPages ? 'rgba(255,255,255,0.3)' : '#fff',
                  border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: currentPage === totalPages ? 'not-allowed' : 'pointer'
                }}>
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

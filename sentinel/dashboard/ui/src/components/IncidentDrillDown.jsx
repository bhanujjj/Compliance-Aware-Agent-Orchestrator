import React, { useState, useEffect } from 'react'
import { ArrowLeft } from 'lucide-react'

const MOCK_EVENTS = [
  { event_id: '1', timestamp: '2026-07-12T00:32:00Z', event_type: 'DETECTION', actor: 'InvestigationAgent', payload: { alerts: 5 } },
  { event_id: '2', timestamp: '2026-07-12T00:32:02Z', event_type: 'PROPOSAL', actor: 'ResponseAgent', payload: { action_type: 'isolate_host', target: '10.1.1.2' } },
  { event_id: '3', timestamp: '2026-07-12T00:32:03Z', event_type: 'REJECTION', actor: 'PolicyEngine', payload: { reason: "Role 'tier1_analyst' is not permitted to call 'isolate_host'." } },
  { event_id: '4', timestamp: '2026-07-12T00:32:04Z', event_type: 'ESCALATION', actor: 'EscalationAgent', payload: { reason: "Incident severity 9.5 >= threshold 8.0.", human_queue_id: 'hq-1234' } }
]

export default function IncidentDrillDown({ incident, onBack }) {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`http://localhost:8000/api/incidents/${incident.incident_id}/events`)
      .then(res => res.json())
      .then(data => {
        setEvents(data)
        setLoading(false)
      })
      .catch(err => {
        console.warn('Backend not reachable, using mock event data.')
        setEvents(MOCK_EVENTS)
        setLoading(false)
      })
  }, [incident.incident_id])

  return (
    <div>
      <button className="back-btn" onClick={onBack}>
        <ArrowLeft size={16} /> Back to Feed
      </button>

      <h1>Incident {incident.incident_id}</h1>
      <p className="subtitle">
        Severity: <span className={`badge ${(incident.highest_severity ?? incident.severity ?? 0) >= 8 ? 'critical' : 'medium'}`}>{Number(incident.highest_severity ?? incident.severity ?? 0).toFixed(1)}</span> • {incident.attack_type || 'Multiple'}
      </p>

      <div className="glass-card">
        <h3>Audit Timeline</h3>
        {loading ? (
          <p style={{ marginTop: 16 }}>Loading timeline...</p>
        ) : (
          <div className="timeline">
            {events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)).map((evt, idx) => {
              const isEscalated = evt.event_type === 'ESCALATION' || evt.event_type === 'REJECTION'
              const isTrace = evt.event_type === 'TRACE'
              
              if (isTrace) {
                return (
                  <div key={evt.event_id || idx} className="timeline-event trace">
                    <div className="timeline-dot" style={{ background: 'var(--text-muted)' }}></div>
                    <div className="timeline-time" style={{ color: 'var(--text-muted)' }}>{new Date(evt.timestamp).toLocaleTimeString()} • {evt.actor}</div>
                    <div className="timeline-content">
                      <p style={{ margin: 0, fontSize: '14px', color: 'var(--text-muted)' }}>
                        ⚙ {evt.payload?.step || JSON.stringify(evt.payload)}
                      </p>
                    </div>
                  </div>
                )
              }
              
              return (
                <div key={evt.event_id || idx} className={`timeline-event ${isEscalated ? 'escalated' : ''}`}>
                  <div className="timeline-dot"></div>
                  <div className="timeline-time">{new Date(evt.timestamp).toLocaleTimeString()} • {evt.actor}</div>
                  <div className="timeline-content">
                    <h4 style={{ color: isEscalated ? 'var(--accent-red)' : 'var(--accent-blue)' }}>{evt.event_type}</h4>
                    <pre style={{ fontSize: '13px', color: 'var(--text-muted)', whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
                      {JSON.stringify(evt.payload, null, 2)}
                    </pre>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

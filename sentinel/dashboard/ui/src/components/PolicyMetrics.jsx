import React, { useState, useEffect } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  LineChart, Line
} from 'recharts'

const MOCK_METRICS = {
  guardrail_catch_rate: 95.5,
  overall_pass_rate: 88.2,
  latency_p50_ms: 124,
  latency_p95_ms: 310,
  latency_history: [
    { time: '10:00', p50: 120, p95: 290 },
    { time: '10:15', p50: 125, p95: 300 },
    { time: '10:30', p50: 130, p95: 410 },
    { time: '10:45', p50: 122, p95: 280 },
    { time: '11:00', p50: 124, p95: 310 },
  ],
  catch_rate_history: [
    { time: '10:00', rate: 98 },
    { time: '10:15', rate: 96 },
    { time: '10:30', rate: 94 },
    { time: '10:45', rate: 95 },
    { time: '11:00', rate: 95.5 },
  ]
}

export default function PolicyMetrics() {
  const [metrics, setMetrics] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('http://localhost:8000/api/metrics')
      .then(res => res.json())
      .then(data => {
        setMetrics({
          ...MOCK_METRICS,
          ...(data.metrics || data)
        })
        setLoading(false)
      })
      .catch(err => {
        console.warn('Backend not reachable, using mock metrics data.')
        setMetrics(MOCK_METRICS)
        setLoading(false)
      })
  }, [])

  if (loading) return <div>Loading metrics...</div>

  return (
    <div>
      <h1>Policy Metrics</h1>
      <p className="subtitle">Governance framework performance and guardrail catch rates</p>
      
      <div className="metrics-grid">
        <div className="glass-card metric-card">
          <h3>Guardrail Catch Rate</h3>
          <div className="metric-value" style={{ color: 'var(--accent-green)' }}>
            {metrics.guardrail_catch_rate.toFixed(1)}%
          </div>
          <div className="metric-trend trend-up">
            Target &gt; 95% met
          </div>
        </div>
        
        <div className="glass-card metric-card">
          <h3>Overall Pass Rate</h3>
          <div className="metric-value" style={{ color: 'var(--accent-blue)' }}>
            {metrics.overall_pass_rate.toFixed(1)}%
          </div>
          <div className="metric-trend trend-up">
            Healthy baseline
          </div>
        </div>
        
        <div className="glass-card metric-card">
          <h3>P95 Latency</h3>
          <div className="metric-value" style={{ color: 'var(--accent-orange)' }}>
            {Number(metrics.latency_p95_ms).toFixed(1)} <span style={{ fontSize: '20px' }}>ms</span>
          </div>
          <div className="metric-trend trend-down">
            Needs optimization
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
        <div className="glass-card" style={{ flex: '1 1 400px', minHeight: '300px' }}>
          <h3 style={{ marginBottom: '24px', color: 'var(--text-muted)', fontSize: '14px', fontWeight: 500 }}>
            Catch Rate History
          </h3>
          <div style={{ width: '100%', height: '220px' }}>
            <ResponsiveContainer>
              <BarChart data={metrics.catch_rate_history}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} domain={[80, 100]} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: 'var(--bg-dark)', borderColor: 'var(--border-color)', borderRadius: '8px' }} 
                  itemStyle={{ color: 'var(--text-main)' }} 
                />
                <Bar dataKey="rate" fill="var(--accent-green)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="glass-card" style={{ flex: '1 1 400px', minHeight: '300px' }}>
          <h3 style={{ marginBottom: '24px', color: 'var(--text-muted)', fontSize: '14px', fontWeight: 500 }}>
            Latency Trends (ms)
          </h3>
          <div style={{ width: '100%', height: '220px' }}>
            <ResponsiveContainer>
              <LineChart data={metrics.latency_history}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: 'var(--bg-dark)', borderColor: 'var(--border-color)', borderRadius: '8px' }}
                />
                <Line type="monotone" dataKey="p50" stroke="var(--accent-blue)" strokeWidth={3} dot={false} />
                <Line type="monotone" dataKey="p95" stroke="var(--accent-orange)" strokeWidth={3} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  )
}

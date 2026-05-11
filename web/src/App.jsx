import React, { useState, useEffect } from 'react'
import axios from 'axios'
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, 
  PieChart, Pie, Cell, AreaChart, Area, BarChart, Bar, Legend, ComposedChart 
} from 'recharts'

// Use relative URL so Vite's dev proxy handles it; works in both dev and prod
const API_URL = '/api'

const COLORS = {
  primary: '#3b82f6',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  purple: '#8b5cf6',
  cyan: '#06b6d4',
  dark: '#1e293b',
  darker: '#0f172a'
}

const SEVERITY_COLORS = { 
  critical: '#ef4444', 
  high: '#f59e0b', 
  medium: '#3b82f6', 
  low: '#10b981' 
}

function App() {
  const [stats, setStats] = useState(null)
  const [history, setHistory] = useState([])
  const [alerts, setAlerts] = useState([])
  const [blocked, setBlocked] = useState([])
  const [status, setStatus] = useState(null)
  const [mitigation, setMitigation] = useState(null)
  const [detection, setDetection] = useState(null)
  const [snort, setSnort] = useState(null)
  const [snortAlerts, setSnortAlerts] = useState([])
  const [activeTab, setActiveTab] = useState('overview')
  const [timeRange, setTimeRange] = useState(30)
  const [darkMode, setDarkMode] = useState(true)
  const [notifications, setNotifications] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const [autoBlockEnabled, setAutoBlockEnabled] = useState(false)
  const [toasts, setToasts] = useState([])
  const [blockingIPs, setBlockingIPs] = useState(new Set())

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  // Sync auto-block state from server
  useEffect(() => {
    if (mitigation?.enabled !== undefined) {
      setAutoBlockEnabled(mitigation.enabled)
    }
  }, [mitigation?.enabled])

  const addToast = (message, type = 'success') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }

  const fetchData = async () => {
    const requests = [
      axios.get(`${API_URL}/stats`),
      axios.get(`${API_URL}/status`),
      axios.get(`${API_URL}/mitigation`),
      axios.get(`${API_URL}/detection`),
      axios.get(`${API_URL}/snort`),
    ]
    // Fetch IDS alerts if active
    if (snort?.enabled) requests.push(axios.get(`${API_URL}/snort/alerts`))

    const results = await Promise.allSettled(requests)
    const statsResult = results[0]
    const statusResult = results[1]

    if (statsResult.status === 'fulfilled') {
      const data = statsResult.value.data
      setStats(data)
      setIsConnected(true)
      setHistory(prev => {
        const newEntry = {
          time: new Date().toLocaleTimeString(),
          pps: data.stats?.PPS || 0,
          bps: (data.stats?.BPS || 0) / 1024,
          tcp: data.stats?.TCP || 0,
          udp: data.stats?.UDP || 0,
          icmp: data.stats?.ICMP || 0,
          syn: data.stats?.SynCount || 0,
          ack: data.stats?.AckCount || 0,
        }
        return [...prev, newEntry].slice(-timeRange)
      })
      if (data.alerts) setAlerts(data.alerts)
      if (data.blocked) setBlocked(data.blocked)
    } else {
      setIsConnected(false)
    }
    if (statusResult.status === 'fulfilled') setStatus(statusResult.value.data)
    if (results[2]?.status === 'fulfilled') setMitigation(results[2].value.data)
    if (results[3]?.status === 'fulfilled') setDetection(results[3].value.data)
    if (results[4]?.status === 'fulfilled') setSnort(results[4].value.data)
    if (snort?.enabled && results[5]?.status === 'fulfilled') {
      setSnortAlerts(results[5].value.data?.alerts || [])
    }
  }

  const toggleSnort = async () => {
    const newState = !snort?.enabled
    try {
      const res = await axios.post(`${API_URL}/snort/toggle`, { enabled: newState })
      addToast(newState ? `🦅 IDS Enabled (${res.data?.engine || 'snort'})` : '🦅 IDS Disabled', newState ? 'success' : 'warning')
      fetchData()
    } catch (err) {
      addToast(`IDS toggle failed: ${err.response?.data?.error || err.message}`, 'error')
    }
  }

  const blockIP = async (ip, reason = 'Manual block') => {
    if (blockingIPs.has(ip)) return
    setBlockingIPs(prev => new Set([...prev, ip]))
    try {
      await axios.post(`${API_URL}/block/${ip}`, null, { params: { reason } })
      addToast(`🔒 Blocked ${ip}`, 'success')
      fetchData()
    } catch (err) {
      addToast(`Failed to block ${ip}: ${err.response?.data?.error || err.message}`, 'error')
    } finally {
      setBlockingIPs(prev => { const s = new Set(prev); s.delete(ip); return s })
    }
  }

  const blockFromAlert = async (ip, attackType) => {
    await blockIP(ip, `Blocked from alert: ${attackType}`)
  }

  const toggleAutoBlock = async (enabled) => {
    try {
      await axios.post(`${API_URL}/mitigation/autoblock`, { enabled })
      setAutoBlockEnabled(enabled)
      addToast(enabled ? '🤖 Auto-Block ENABLED — threats blocked automatically' : '⚠️ Auto-Block DISABLED', enabled ? 'success' : 'warning')
      fetchData()
    } catch (err) {
      addToast('Failed to toggle auto-block', 'error')
    }
  }

  const unblockIP = async (ip) => {
    try {
      await axios.delete(`${API_URL}/block/${ip}`)
      addToast(`🔓 Unblocked ${ip}`, 'warning')
      fetchData()
    } catch (err) {
      addToast(`Failed to unblock ${ip}`, 'error')
    }
  }

  const getSeverityColor = (severity) => SEVERITY_COLORS[severity] || '#94a3b8'

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(2) + 'M'
    if (num >= 1000) return (num / 1000).toFixed(2) + 'K'
    return num?.toString() || '0'
  }

  const protocolData = stats ? [
    { name: 'TCP', value: stats.stats.TCP || 0 },
    { name: 'UDP', value: stats.stats.UDP || 0 },
    { name: 'ICMP', value: stats.stats.ICMP || 0 },
    { name: 'Other', value: stats.stats.Other || 0 }
  ] : []

  const attackData = alerts.reduce((acc, alert) => {
    const type = alert.attack_type.split(' ')[0]
    const existing = acc.find(a => a.name === type)
    if (existing) existing.count++
    else acc.push({ name: type || 'Unknown', count: 1 })
    return acc
  }, [])

  const renderGlowCard = (icon, title, value, subtitle, color = COLORS.primary) => (
    <div style={{
      ...styles.glowCard,
      background: `linear-gradient(135deg, ${COLORS.darker} 0%, ${COLORS.dark} 100%)`,
      border: `1px solid ${color}30`
    }}>
      <div style={{...styles.glowIcon, background: `${color}20`}}>{icon}</div>
      <div style={styles.glowContent}>
        <span style={styles.glowLabel}>{title}</span>
        <span style={{...styles.glowValue, color}}>{value}</span>
        <span style={styles.glowSub}>{subtitle}</span>
      </div>
    </div>
  )

  const renderOverview = () => {
    // Calculate Threat Level
    let threatLevel = 'SAFE'
    let threatColor = COLORS.success
    let threatMsg = 'Normal traffic baseline'
    
    if (alerts.length > 5 || (stats?.stats?.PPS > 10000)) {
      threatLevel = 'CRITICAL'
      threatColor = COLORS.danger
      threatMsg = 'Active attack detected'
    } else if (alerts.length > 0 || (stats?.stats?.SynCount > 1000)) {
      threatLevel = 'ELEVATED'
      threatColor = COLORS.warning
      threatMsg = 'Anomalous patterns observed'
    }

    const totalProtos = (stats?.stats?.TCP || 0) + (stats?.stats?.UDP || 0) + (stats?.stats?.ICMP || 0) || 1
    const getPercent = (val) => ((val / totalProtos) * 100).toFixed(1)

    return (
    <>
      {/* Pro Dashboard Header */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px', marginBottom: '25px' }}>
        <div style={{
          background: `linear-gradient(135deg, ${COLORS.darker} 0%, ${COLORS.dark} 100%)`,
          border: `1px solid ${threatColor}40`,
          borderRadius: '16px', padding: '24px',
          boxShadow: `0 8px 32px ${threatColor}15`,
          display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center'
        }}>
          <span style={{ fontSize: '14px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '1px', fontWeight: '700' }}>System Threat Level</span>
          <span style={{ fontSize: '36px', fontWeight: '800', color: threatColor, textShadow: `0 0 20px ${threatColor}60`, margin: '10px 0' }}>{threatLevel}</span>
          <span style={{ fontSize: '13px', color: '#64748b' }}>{threatMsg}</span>
        </div>

        <div style={styles.statsGrid}>
          {renderGlowCard('📊', 'Throughput', formatNumber(stats?.stats?.PPS) + ' PPS', 'packets / sec', COLORS.primary)}
          {renderGlowCard('⚡', 'Bandwidth', `${((stats?.stats?.BPS || 0) / 1024 / 1024).toFixed(2)} MB/s`, 'current rate', COLORS.success)}
          {renderGlowCard('🚨', 'Active Alerts', alerts.length, 'unresolved threats', alerts.length > 0 ? COLORS.danger : COLORS.success)}
          {renderGlowCard('🛡️', 'Mitigated', blocked.length, 'ips blocked', COLORS.warning)}
        </div>
      </div>

      {/* Main Charts */}
      <div style={styles.chartsGrid}>
        {/* Traffic Chart */}
        <div style={styles.chartCard}>
          <div style={styles.chartHeader}>
            <h3 style={styles.chartTitle}>📈 Network Traffic</h3>
            <select 
              value={timeRange} 
              onChange={(e) => setTimeRange(Number(e.target.value))}
              style={styles.select}
            >
              <option value={30}>Last 30s</option>
              <option value={60}>Last 60s</option>
              <option value={120}>Last 2min</option>
            </select>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <ComposedChart data={history}>
              <defs>
                <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.primary} stopOpacity={0.4}/>
                  <stop offset="95%" stopColor={COLORS.primary} stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="bpsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={COLORS.success} stopOpacity={0.4}/>
                  <stop offset="95%" stopColor={COLORS.success} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
              <YAxis stroke="#64748b" fontSize={10} />
              <Tooltip 
                contentStyle={{ background: COLORS.darker, border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#94a3b8' }}
              />
              <Legend />
              <Area type="monotone" dataKey="pps" stroke={COLORS.primary} fill="url(#ppsGrad)" name="PPS" strokeWidth={2} />
              <Line type="monotone" dataKey="bps" stroke={COLORS.success} strokeWidth={2} dot={false} name="KB/s" />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* Protocol Distribution Pro Bars */}
        <div style={styles.chartCard}>
          <h3 style={styles.chartTitle}>🔌 Protocol Breakdown</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', marginTop: '20px' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px', fontWeight: '600' }}>
                <span style={{ color: COLORS.primary }}>TCP Traffic</span>
                <span>{getPercent(stats?.stats?.TCP || 0)}%</span>
              </div>
              <div style={{ width: '100%', height: '8px', background: '#1e293b', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ width: `${getPercent(stats?.stats?.TCP || 0)}%`, height: '100%', background: COLORS.primary, transition: 'width 0.5s ease' }}></div>
              </div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px', fontWeight: '600' }}>
                <span style={{ color: COLORS.success }}>UDP Traffic</span>
                <span>{getPercent(stats?.stats?.UDP || 0)}%</span>
              </div>
              <div style={{ width: '100%', height: '8px', background: '#1e293b', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ width: `${getPercent(stats?.stats?.UDP || 0)}%`, height: '100%', background: COLORS.success, transition: 'width 0.5s ease' }}></div>
              </div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '13px', fontWeight: '600' }}>
                <span style={{ color: COLORS.warning }}>ICMP Traffic</span>
                <span>{getPercent(stats?.stats?.ICMP || 0)}%</span>
              </div>
              <div style={{ width: '100%', height: '8px', background: '#1e293b', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{ width: `${getPercent(stats?.stats?.ICMP || 0)}%`, height: '100%', background: COLORS.warning, transition: 'width 0.5s ease' }}></div>
              </div>
            </div>
            <div style={{ marginTop: 'auto', padding: '15px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid #334155' }}>
               <span style={{ fontSize: '12px', color: '#94a3b8' }}>SYN/ACK Ratio: <strong style={{ color: COLORS.purple }}>{(stats?.stats?.SynAckRatio || 0).toFixed(2)}</strong></span>
            </div>
          </div>
        </div>
      </div>

      {/* Secondary Charts */}
      <div style={styles.chartsGrid}>
        {/* TCP Flags */}
        <div style={styles.chartCard}>
          <h3 style={styles.chartTitle}>🔐 TCP Flags Analysis</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[
              { name: 'SYN', value: stats?.stats?.SynCount || 0, fill: COLORS.warning },
              { name: 'ACK', value: stats?.stats?.AckCount || 0, fill: COLORS.success }
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip contentStyle={{ background: COLORS.darker, border: '1px solid #334155' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Types */}
        <div style={styles.chartCard}>
          <h3 style={styles.chartTitle}>⚠️ Attack Detection</h3>
          {attackData.length === 0 ? (
            <div style={styles.emptyState}>✅ No attacks detected - System Secure</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={attackData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" stroke="#64748b" />
                <YAxis dataKey="name" type="category" stroke="#64748b" width={80} />
                <Tooltip contentStyle={{ background: COLORS.darker, border: '1px solid #334155' }} />
                <Bar dataKey="count" fill={COLORS.danger} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </>
  )
}

  const renderAlerts = () => (
    <div style={styles.section}>
      {/* Auto-Block Banner */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '16px 20px',
        background: autoBlockEnabled
          ? `linear-gradient(135deg, ${COLORS.success}15 0%, ${COLORS.success}05 100%)`
          : `linear-gradient(135deg, ${COLORS.danger}15 0%, ${COLORS.danger}05 100%)`,
        border: `1px solid ${autoBlockEnabled ? COLORS.success : COLORS.danger}40`,
        borderRadius: '14px', marginBottom: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '24px' }}>{autoBlockEnabled ? '🤖' : '🔓'}</span>
          <div>
            <div style={{ fontWeight: '700', fontSize: '15px', color: autoBlockEnabled ? COLORS.success : COLORS.danger }}>
              Auto-Block: {autoBlockEnabled ? 'ENABLED' : 'DISABLED'}
            </div>
            <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
              {autoBlockEnabled
                ? 'High/critical threats are automatically blocked via iptables'
                : 'Enable to automatically block IPs generating high/critical alerts'}
            </div>
          </div>
        </div>
        <div
          onClick={() => toggleAutoBlock(!autoBlockEnabled)}
          style={{
            width: '52px', height: '28px', borderRadius: '14px', cursor: 'pointer',
            background: autoBlockEnabled ? COLORS.success : '#334155',
            position: 'relative', transition: 'background 0.3s', flexShrink: 0
          }}
        >
          <div style={{
            position: 'absolute', top: '3px',
            left: autoBlockEnabled ? '27px' : '3px',
            width: '22px', height: '22px', borderRadius: '50%',
            background: 'white', transition: 'left 0.3s',
            boxShadow: '0 1px 4px rgba(0,0,0,0.3)'
          }} />
        </div>
      </div>

      {/* Header */}
      <div style={styles.sectionHeader}>
        <h2 style={styles.sectionTitle}>🚨 Security Alerts</h2>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          {alerts.length > 0 && (
            <span style={styles.alertCount}>{alerts.length} total</span>
          )}
        </div>
      </div>

      {alerts.length === 0 ? (
        <div style={styles.emptyState}>✅ No alerts — System is secure</div>
      ) : (
        <div style={styles.alertsList}>
          {alerts.map((alert, idx) => {
            const isBlocked = blocked.some(b => alert.top_sources?.some(s => s.ip === b.ip))
            const hasSources = alert.top_sources && alert.top_sources.length > 0
            const hasSpecificIP = alert.source_ip && alert.source_ip !== 'multiple' && alert.source_ip !== 'LLM Analysis'
            const isAlreadyBlocked = hasSpecificIP && blocked.some(b => b.ip === alert.source_ip)

            return (
              <div key={alert.id || idx} style={{
                ...styles.alertCard,
                borderLeftColor: getSeverityColor(alert.severity),
                animation: `slideIn 0.3s ease ${idx * 0.05}s both`
              }}>
                {/* Alert Header Row */}
                <div style={styles.alertHeader}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={styles.alertType}>{alert.attack_type}</span>
                    <span style={{ ...styles.alertBadge, background: getSeverityColor(alert.severity) }}>
                      {alert.severity?.toUpperCase()}
                    </span>
                    {alert.is_mitigated && (
                      <span style={{ ...styles.alertBadge, background: COLORS.success, fontSize: '10px' }}>✓ MITIGATED</span>
                    )}
                  </div>
                  {/* Block specific IP button */}
                  {hasSpecificIP && !isAlreadyBlocked && (
                    <button
                      onClick={() => blockFromAlert(alert.source_ip, alert.attack_type)}
                      disabled={blockingIPs.has(alert.source_ip)}
                      style={{ ...styles.blockBtn, opacity: blockingIPs.has(alert.source_ip) ? 0.6 : 1 }}
                    >
                      {blockingIPs.has(alert.source_ip) ? '⏳ Blocking...' : `🚫 Block ${alert.source_ip}`}
                    </button>
                  )}
                  {hasSpecificIP && isAlreadyBlocked && (
                    <span style={styles.blockedBadge}>✅ Already Blocked</span>
                  )}
                </div>

                <p style={styles.alertMessage}>{alert.message}</p>

                <div style={styles.alertFooter}>
                  <span style={styles.alertTime}>🕐 {new Date(alert.timestamp).toLocaleString()}</span>
                  <span style={{ color: '#64748b', fontSize: '12px' }}>📍 Source: {alert.source_ip}</span>
                  {alert.count > 0 && <span style={styles.alertCount}>📊 {alert.count.toLocaleString()} pkts</span>}
                </div>

                {/* Suggestion Panel — top source IPs */}
                {hasSources && (
                  <div style={styles.suggestionBox}>
                    <div style={styles.suggestionTitle}>
                      ⚡ Suggested Action — Block Top Offending IPs
                    </div>
                    <div style={styles.suggestionGrid}>
                      {alert.top_sources.map((src, si) => {
                        const alreadyBlocked = blocked.some(b => b.ip === src.ip)
                        const isBlocking = blockingIPs.has(src.ip)
                        return (
                          <div key={si} style={styles.suggestionRow}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={styles.rankBadge}>#{si + 1}</span>
                              <code style={styles.ipCode}>{src.ip}</code>
                              <span style={{ fontSize: '11px', color: '#64748b' }}>{src.count?.toLocaleString()} pkts</span>
                            </div>
                            {alreadyBlocked ? (
                              <span style={styles.blockedBadge}>✅ Blocked</span>
                            ) : (
                              <button
                                onClick={() => blockFromAlert(src.ip, alert.attack_type)}
                                disabled={isBlocking}
                                style={{ ...styles.blockBtnSm, opacity: isBlocking ? 0.6 : 1 }}
                              >
                                {isBlocking ? '⏳' : '🚫 Block'}
                              </button>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )

  const renderMitigation = () => (
    <div style={styles.section}>
      <h2 style={styles.sectionTitle}>🛡️ Mitigation Center</h2>

      {/* Auto-Block Toggle */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '20px 24px',
        background: autoBlockEnabled
          ? `linear-gradient(135deg, ${COLORS.success}20 0%, ${COLORS.dark} 100%)`
          : `linear-gradient(135deg, ${COLORS.danger}15 0%, ${COLORS.dark} 100%)`,
        border: `1px solid ${autoBlockEnabled ? COLORS.success : COLORS.danger}50`,
        borderRadius: '16px', marginBottom: '24px'
      }}>
        <div>
          <div style={{ fontWeight: '700', fontSize: '18px', color: autoBlockEnabled ? COLORS.success : COLORS.danger }}>
            {autoBlockEnabled ? '🤖 Auto-Block Active' : '🔓 Auto-Block Disabled'}
          </div>
          <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px' }}>
            {autoBlockEnabled
              ? 'High and critical alerts trigger automatic iptables IP blocks'
              : 'Enable to automatically block IPs generating high/critical severity attacks'}
          </div>
        </div>
        <div
          onClick={() => toggleAutoBlock(!autoBlockEnabled)}
          style={{
            width: '60px', height: '32px', borderRadius: '16px', cursor: 'pointer',
            background: autoBlockEnabled ? COLORS.success : '#334155',
            position: 'relative', transition: 'background 0.3s', flexShrink: 0
          }}
        >
          <div style={{
            position: 'absolute', top: '4px',
            left: autoBlockEnabled ? '32px' : '4px',
            width: '24px', height: '24px', borderRadius: '50%',
            background: 'white', transition: 'left 0.3s',
            boxShadow: '0 2px 6px rgba(0,0,0,0.3)'
          }} />
        </div>
      </div>

      {/* Status Cards */}
      <div style={styles.mitigationGrid}>
        <div style={{...styles.mitigationCard, borderColor: mitigation?.enabled ? COLORS.success : COLORS.danger}}>
          <span style={styles.mitigationLabel}>Auto-Block</span>
          <span style={{...styles.mitigationValue, color: mitigation?.enabled ? COLORS.success : COLORS.danger}}>
            {mitigation?.enabled ? 'ACTIVE' : 'INACTIVE'}
          </span>
        </div>
        <div style={styles.mitigationCard}>
          <span style={styles.mitigationLabel}>Currently Blocked</span>
          <span style={styles.mitigationValue}>{blocked.length}</span>
        </div>
        <div style={styles.mitigationCard}>
          <span style={styles.mitigationLabel}>Block Duration</span>
          <span style={styles.mitigationValue}>{mitigation?.block_duration || 'N/A'}</span>
        </div>
        <div style={styles.mitigationCard}>
          <span style={styles.mitigationLabel}>Rate Limit</span>
          <span style={styles.mitigationValue}>{mitigation?.rate_limit_pps || 0} pps</span>
        </div>
      </div>

      {/* Blocked IPs */}
      <h3 style={styles.subTitle}>🚫 Blocked IPs</h3>
      {blocked.length === 0 ? (
        <div style={styles.emptyState}>✅ No IPs currently blocked</div>
      ) : (
        <div style={styles.blockedList}>
          {blocked.map((ip, idx) => (
            <div key={idx} style={styles.blockedCard}>
              <div style={styles.blockedInfo}>
                <span style={styles.blockedIP}>🔒 {ip.ip}</span>
                <span style={styles.blockedReason}>{ip.reason}</span>
              </div>
              <button style={styles.unblockBtn} onClick={() => unblockIP(ip.ip)}>Release</button>
            </div>
          ))}
        </div>
      )}
    </div>
  )

  const getIDSStatusColor = (s) => {
    if (s === 'running') return COLORS.success
    if (s === 'stopped') return COLORS.danger
    return COLORS.warning
  }

  const getIDSSeverityColor = (sev) => {
    if (sev === 1) return COLORS.danger
    if (sev === 2) return COLORS.warning
    return COLORS.primary
  }

  const renderSnort = () => (
    <div style={styles.section}>
      {/* Header with toggle */}
      <div style={styles.sectionHeader}>
        <h2 style={styles.sectionTitle}>🦅 IDS Integration {snort?.engine ? `(${snort.engine})` : ''}</h2>
        <button
          onClick={toggleSnort}
          style={{
            ...styles.snortToggle,
            background: snort?.enabled
              ? `linear-gradient(135deg, ${COLORS.success}, #059669)`
              : `linear-gradient(135deg, ${COLORS.danger}, #dc2626)`
          }}
        >
          {snort?.enabled ? '🟢 Enabled' : '🔴 Disabled'}
        </button>
      </div>

      {/* Status Cards */}
      <div style={styles.snortStats}>
        <div style={styles.snortCard}>
          <span style={styles.snortLabel}>Status</span>
          <span style={{...styles.snortValue, color: getIDSStatusColor(snort?.status)}}>
            {snort?.status?.toUpperCase() || 'UNKNOWN'}
          </span>
        </div>
        <div style={styles.snortCard}>
          <span style={styles.snortLabel}>Engine</span>
          <span style={styles.snortValue}>{snort?.engine || 'none'}</span>
        </div>
        <div style={styles.snortCard}>
          <span style={styles.snortLabel}>Rules Loaded</span>
          <span style={styles.snortValue}>{snort?.rules_loaded?.toLocaleString() || 0}</span>
        </div>
        <div style={styles.snortCard}>
          <span style={styles.snortLabel}>IDS Alerts</span>
          <span style={{...styles.snortValue, color: (snort?.alerts || 0) > 0 ? COLORS.danger : COLORS.success}}>
            {snort?.alerts || 0}
          </span>
        </div>
        <div style={styles.snortCard}>
          <span style={styles.snortLabel}>Dropped</span>
          <span style={styles.snortValue}>{snort?.dropped || 0}</span>
        </div>
      </div>

      {/* Log file info */}
      {snort?.log_file && (
        <div style={{...styles.snortInfo, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px'}}>
          <span>📁</span>
          <span>Tailing: <code style={styles.ipCode}>{snort.log_file}</code></span>
          {snort?.last_update && (
            <span style={{marginLeft: 'auto', fontSize: '11px', color: '#64748b'}}>
              Updated: {new Date(snort.last_update).toLocaleTimeString()}
            </span>
          )}
        </div>
      )}

      {/* IDS Alerts Table */}
      <h3 style={styles.subTitle}>🚨 IDS Alerts ({snortAlerts.length})</h3>
      {snortAlerts.length === 0 ? (
        <div style={styles.emptyState}>
          {snort?.enabled
            ? '✅ No IDS alerts — monitoring active'
            : '🔴 IDS is disabled — click Enable to start monitoring'}
        </div>
      ) : (
        <div style={{maxHeight: '500px', overflowY: 'auto', borderRadius: '12px'}}>
          <table style={{width: '100%', borderCollapse: 'collapse', fontSize: '13px'}}>
            <thead>
              <tr style={{background: COLORS.darker, position: 'sticky', top: 0, zIndex: 1}}>
                <th style={styles.th}>Time</th>
                <th style={styles.th}>Severity</th>
                <th style={styles.th}>Message</th>
                <th style={styles.th}>Src IP</th>
                <th style={styles.th}>Dst IP</th>
                <th style={styles.th}>Proto</th>
                <th style={styles.th}>Action</th>
              </tr>
            </thead>
            <tbody>
              {snortAlerts.slice(-50).reverse().map((a, i) => {
                const alreadyBlocked = blocked.some(b => b.ip === a.src_ip)
                return (
                  <tr key={i} style={{
                    background: i % 2 === 0 ? COLORS.dark : COLORS.darker,
                    borderLeft: `3px solid ${getIDSSeverityColor(a.severity)}`
                  }}>
                    <td style={styles.td}>{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td style={styles.td}>
                      <span style={{
                        padding: '2px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: '700',
                        background: getIDSSeverityColor(a.severity) + '25',
                        color: getIDSSeverityColor(a.severity)
                      }}>
                        {a.severity === 1 ? 'CRITICAL' : a.severity === 2 ? 'HIGH' : 'MEDIUM'}
                      </span>
                    </td>
                    <td style={{...styles.td, maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>
                      {a.msg || a.classification || 'Unknown'}
                    </td>
                    <td style={styles.td}><code style={{fontSize: '12px', color: '#e2e8f0'}}>{a.src_ip}:{a.src_port}</code></td>
                    <td style={styles.td}><code style={{fontSize: '12px', color: '#94a3b8'}}>{a.dst_ip}:{a.dst_port}</code></td>
                    <td style={styles.td}><span style={{color: COLORS.primary}}>{a.protocol}</span></td>
                    <td style={styles.td}>
                      {a.src_ip && !alreadyBlocked ? (
                        <button
                          onClick={() => blockFromAlert(a.src_ip, `IDS: ${a.msg || a.classification}`)}
                          disabled={blockingIPs.has(a.src_ip)}
                          style={{...styles.blockBtnSm, padding: '3px 8px', fontSize: '11px'}}
                        >
                          {blockingIPs.has(a.src_ip) ? '⏳' : '🚫'}
                        </button>
                      ) : a.src_ip && alreadyBlocked ? (
                        <span style={{...styles.blockedBadge, fontSize: '10px', padding: '2px 6px'}}>✅</span>
                      ) : null}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )


  const renderSystem = () => (
    <div style={styles.section}>
      <h2 style={styles.sectionTitle}>💻 System Status</h2>
      <div style={styles.systemGrid}>
        <div style={styles.systemCard}>
          <span style={styles.systemLabel}>System Status</span>
          <span style={{...styles.systemValue, color: status?.status === 'running' ? COLORS.success : COLORS.danger}}>
            {status?.status?.toUpperCase() || 'UNKNOWN'}
          </span>
        </div>
        <div style={styles.systemCard}>
          <span style={styles.systemLabel}>Packet Capture</span>
          <span style={{...styles.systemValue, color: status?.capture ? COLORS.success : COLORS.danger}}>
            {status?.capture ? 'ACTIVE' : 'STOPPED'}
          </span>
        </div>
        <div style={styles.systemCard}>
          <span style={styles.systemLabel}>Uptime</span>
          <span style={styles.systemValue}>{status?.uptime || 'N/A'}</span>
        </div>
        <div style={styles.systemCard}>
          <span style={styles.systemLabel}>Total Packets</span>
          <span style={styles.systemValue}>{stats?.stats?.TotalPackets?.toLocaleString() || 0}</span>
        </div>
      </div>
    </div>
  )

  return (
    <div style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <div style={styles.logoContainer}>
            <span style={styles.logo}>🛡️</span>
            <div>
              <h1 style={styles.title}>ZeroFlood</h1>
              <span style={styles.subtitle}>DDoS Detection & Mitigation</span>
            </div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <div style={styles.liveIndicator}>
            <span style={styles.liveDot(isConnected && status?.capture)}></span>
            {isConnected && status?.capture ? 'LIVE' : isConnected ? 'CONNECTED' : 'OFFLINE'}
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav style={styles.nav}>
        {[
          { id: 'overview', icon: '📊', label: 'Overview' },
          { id: 'alerts', icon: '🚨', label: 'Alerts', badge: alerts.length },
          { id: 'mitigation', icon: '🛡️', label: 'Mitigation', badge: blocked.length },
          { id: 'snort', icon: '🦅', label: 'Snort IDS' },
          { id: 'system', icon: '💻', label: 'System' }
        ].map(tab => (
          <button
            key={tab.id}
            style={{...styles.navBtn, ...(activeTab === tab.id ? styles.navBtnActive : {})}}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.icon} {tab.label}
            {tab.badge > 0 && (
              <span style={{
                marginLeft: '6px', padding: '1px 6px',
                background: tab.id === 'alerts' ? COLORS.danger : COLORS.warning,
                borderRadius: '10px', fontSize: '10px', fontWeight: '700', color: 'white'
              }}>{tab.badge}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Content */}
      <div style={styles.content}>
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'alerts' && renderAlerts()}
        {activeTab === 'mitigation' && renderMitigation()}
        {activeTab === 'snort' && renderSnort()}
        {activeTab === 'system' && renderSystem()}
      </div>

      {/* Toast Notifications */}
      <div style={{ position: 'fixed', bottom: '24px', right: '24px', display: 'flex', flexDirection: 'column', gap: '10px', zIndex: 9999 }}>
        {toasts.map(toast => (
          <div key={toast.id} style={{
            padding: '12px 20px',
            borderRadius: '12px',
            background: toast.type === 'success'
              ? `linear-gradient(135deg, ${COLORS.success}, #059669)`
              : toast.type === 'error'
              ? `linear-gradient(135deg, ${COLORS.danger}, #dc2626)`
              : `linear-gradient(135deg, ${COLORS.warning}, #d97706)`,
            color: 'white',
            fontWeight: '600',
            fontSize: '14px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            animation: 'slideIn 0.3s ease',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            minWidth: '240px'
          }}>
            {toast.type === 'success' ? '✅' : toast.type === 'error' ? '❌' : '⚠️'} {toast.message}
          </div>
        ))}
      </div>

      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateX(30px); }
          to { opacity: 1; transform: translateX(0); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        body { margin: 0; padding: 0; overflow-x: hidden; }
        button:hover { filter: brightness(1.1); }
        code { font-family: 'JetBrains Mono', 'Fira Code', monospace; }
      `}</style>
    </div>
  )
}

const styles = {
  container: {
    minHeight: '100vh',
    background: `linear-gradient(135deg, ${COLORS.darker} 0%, ${COLORS.dark} 100%)`,
    color: '#e2e8f0',
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '20px 30px',
    background: 'rgba(15, 23, 42, 0.95)',
    backdropFilter: 'blur(10px)',
    borderBottom: '1px solid #334155'
  },
  headerLeft: { display: 'flex', alignItems: 'center' },
  logoContainer: { display: 'flex', alignItems: 'center', gap: '15px' },
  logo: { fontSize: '40px' },
  title: { fontSize: '28px', fontWeight: '700', margin: 0, background: `linear-gradient(135deg, ${COLORS.primary}, ${COLORS.success})`, WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' },
  subtitle: { fontSize: '12px', color: '#64748b' },
  headerRight: { display: 'flex', alignItems: 'center', gap: '20px' },
  liveIndicator: { display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 20px', background: COLORS.dark, borderRadius: '20px', fontSize: '12px', fontWeight: '600' },
  liveDot: (active) => ({ width: '10px', height: '10px', borderRadius: '50%', background: active ? COLORS.success : COLORS.danger, boxShadow: active ? `0 0 15px ${COLORS.success}` : 'none', animation: 'pulse 2s infinite' }),
  nav: { display: 'flex', gap: '8px', padding: '15px 30px', background: 'rgba(15, 23, 42, 0.8)', borderBottom: '1px solid #334155', flexWrap: 'wrap' },
  navBtn: { padding: '10px 18px', background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '14px', fontWeight: '500', cursor: 'pointer', borderRadius: '10px', transition: 'all 0.2s' },
  navBtnActive: { background: COLORS.primary, color: 'white', boxShadow: `0 4px 15px ${COLORS.primary}40` },
  content: { padding: '30px' },
  statsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px' },
  glowCard: { display: 'flex', alignItems: 'center', gap: '15px', padding: '20px', borderRadius: '16px', border: '1px solid', transition: 'transform 0.2s', cursor: 'pointer' },
  glowIcon: { fontSize: '32px', padding: '15px', borderRadius: '12px' },
  glowContent: { display: 'flex', flexDirection: 'column' },
  glowLabel: { fontSize: '12px', color: '#64748b' },
  glowValue: { fontSize: '28px', fontWeight: '700' },
  glowSub: { fontSize: '10px', color: '#475569' },
  chartsGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px', marginBottom: '30px' },
  chartCard: { background: COLORS.dark, borderRadius: '16px', padding: '20px', border: '1px solid #334155' },
  chartHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' },
  chartTitle: { fontSize: '16px', fontWeight: '600', margin: 0, color: '#e2e8f0' },
  select: { padding: '8px 12px', background: COLORS.darker, border: '1px solid #334155', borderRadius: '8px', color: '#e2e8f0', fontSize: '12px' },
  section: { padding: '10px' },
  sectionHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' },
  sectionTitle: { fontSize: '24px', fontWeight: '600', margin: 0 },
  alertCount: { padding: '6px 12px', background: COLORS.danger + '20', color: COLORS.danger, borderRadius: '12px', fontSize: '12px', fontWeight: '600' },
  alertsList: { display: 'flex', flexDirection: 'column', gap: '12px' },
  alertCard: { padding: '20px', background: COLORS.dark, borderRadius: '12px', borderLeft: '4px solid' },
  alertHeader: { display: 'flex', justifyContent: 'space-between', marginBottom: '10px' },
  alertType: { fontWeight: '600', fontSize: '16px' },
  alertBadge: { padding: '4px 12px', borderRadius: '12px', fontSize: '11px', fontWeight: '600', color: 'white' },
  alertMessage: { color: '#94a3b8', fontSize: '14px', marginBottom: '10px' },
  alertFooter: { display: 'flex', gap: '20px', fontSize: '12px', color: '#64748b' },
  alertTime: {},
  mitigationGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '15px', marginBottom: '30px' },
  mitigationCard: { padding: '20px', background: COLORS.dark, borderRadius: '12px', textAlign: 'center', border: '1px solid #475569' },
  mitigationLabel: { display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '8px' },
  mitigationValue: { fontSize: '24px', fontWeight: '700' },
  subTitle: { fontSize: '18px', fontWeight: '600', marginBottom: '15px' },
  blockedList: { display: 'flex', flexDirection: 'column', gap: '10px' },
  blockedCard: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '15px 20px', background: COLORS.dark, borderRadius: '12px' },
  blockedInfo: { display: 'flex', flexDirection: 'column' },
  blockedIP: { fontFamily: "'JetBrains Mono', monospace", fontSize: '16px', fontWeight: '600', color: COLORS.warning },
  blockedReason: { fontSize: '12px', color: '#64748b' },
  unblockBtn: { padding: '8px 16px', background: COLORS.danger, border: 'none', borderRadius: '8px', color: 'white', fontWeight: '600', cursor: 'pointer' },
  snortToggle: { padding: '12px 24px', border: 'none', borderRadius: '12px', color: 'white', fontWeight: '600', cursor: 'pointer', fontSize: '14px' },
  snortStats: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '15px', marginBottom: '20px' },
  snortCard: { padding: '20px', background: COLORS.dark, borderRadius: '12px', textAlign: 'center' },
  snortLabel: { display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '8px' },
  snortValue: { fontSize: '20px', fontWeight: '700', color: COLORS.primary },
  snortInfo: { padding: '15px', background: COLORS.primary + '10', borderRadius: '12px', color: '#94a3b8', fontSize: '14px' },
  snortDesc: { fontSize: '12px', color: '#64748b', marginTop: '10px' },
  detectionGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '20px' },
  detectionCard: { padding: '25px', background: COLORS.dark, borderRadius: '16px', textAlign: 'center', border: '1px solid #334155' },
  detectionIcon: { fontSize: '32px', marginBottom: '10px' },
  detectionLabel: { display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '8px' },
  detectionValue: { fontSize: '28px', fontWeight: '700', color: COLORS.primary },
  systemGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '20px' },
  systemCard: { padding: '25px', background: COLORS.dark, borderRadius: '16px', textAlign: 'center' },
  systemLabel: { display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '8px' },
  systemValue: { fontSize: '20px', fontWeight: '700', color: COLORS.success },
  emptyState: { padding: '40px', textAlign: 'center', color: '#64748b', background: COLORS.dark, borderRadius: '12px', fontSize: '16px' },
  // Block action styles
  blockBtn: {
    padding: '8px 16px', background: `linear-gradient(135deg, ${COLORS.danger}, #dc2626)`,
    border: 'none', borderRadius: '10px', color: 'white', fontWeight: '700',
    cursor: 'pointer', fontSize: '13px', whiteSpace: 'nowrap',
    boxShadow: `0 4px 12px ${COLORS.danger}40`, transition: 'all 0.2s'
  },
  blockBtnSm: {
    padding: '5px 12px', background: `linear-gradient(135deg, ${COLORS.danger}, #dc2626)`,
    border: 'none', borderRadius: '8px', color: 'white', fontWeight: '600',
    cursor: 'pointer', fontSize: '12px',
    boxShadow: `0 2px 8px ${COLORS.danger}40`, transition: 'all 0.2s'
  },
  blockedBadge: {
    padding: '4px 10px', background: `${COLORS.success}25`, color: COLORS.success,
    borderRadius: '8px', fontSize: '11px', fontWeight: '600', border: `1px solid ${COLORS.success}40`
  },
  // Suggestion panel
  suggestionBox: {
    marginTop: '14px', padding: '14px 16px',
    background: `linear-gradient(135deg, ${COLORS.warning}12 0%, ${COLORS.darker} 100%)`,
    border: `1px solid ${COLORS.warning}35`, borderRadius: '10px'
  },
  suggestionTitle: {
    fontSize: '12px', fontWeight: '700', color: COLORS.warning,
    marginBottom: '10px', letterSpacing: '0.5px', textTransform: 'uppercase'
  },
  suggestionGrid: { display: 'flex', flexDirection: 'column', gap: '8px' },
  suggestionRow: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '8px 12px', background: 'rgba(255,255,255,0.03)',
    borderRadius: '8px', border: '1px solid #334155'
  },
  rankBadge: {
    padding: '2px 7px', background: `${COLORS.warning}25`, color: COLORS.warning,
    borderRadius: '6px', fontSize: '11px', fontWeight: '700'
  },
  ipCode: {
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fontSize: '13px', fontWeight: '600', color: '#e2e8f0',
    background: 'rgba(255,255,255,0.06)', padding: '2px 8px', borderRadius: '4px'
  },
  // Table styles for IDS alerts
  th: {
    padding: '10px 12px', textAlign: 'left', fontSize: '11px', fontWeight: '700',
    color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px',
    borderBottom: '1px solid #334155'
  },
  td: {
    padding: '8px 12px', color: '#e2e8f0', borderBottom: '1px solid #1e293b',
    verticalAlign: 'middle'
  }
}

export default App
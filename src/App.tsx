import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowRight, ArrowUpRight, Bell, Check, ChevronDown,
  CircleHelp, ClipboardCheck, FileSearch, Fingerprint, Globe, HardDrive,
  LayoutDashboard, LockKeyhole, Mail, Menu, Search, Settings, Shield,
  ShieldAlert, ShieldCheck, Smartphone, Wifi, X, Zap, Trash2, RefreshCw, Server, LogOut
} from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import {
  api,
  tools,
  scanWifi,
  type WifiScanResult,
  type CheckResult,
  type CheckTool,
  type Scan,
  type CheckType
} from './api'
import { onAuthStateChanged, signOut, type User } from 'firebase/auth'
import AuthScreen from './AuthScreen'
import { auth, firebaseConfigured } from './firebase'
import './styles.css'
const icons: Record<CheckType, typeof Mail> = {
  email: Mail, password: LockKeyhole, domain: Globe, device: Smartphone,
  wifi: Wifi, assistant: Zap,
}
const chartLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function DashboardApp({ userName, onLogout }: { userName: string; onLogout: () => void }) {
  const [activeNav, setActiveNav] = useState('Overview')
  const [query, setQuery] = useState('')
  const [selectedTool, setSelectedTool] = useState<CheckTool | null>(null)
  const [input, setInput] = useState('')
  const [result, setResult] = useState<CheckResult['result'] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [summary, setSummary] = useState<{ totalChecks: number; risksToReview: number; byType: Record<string, number>; recentScans: Scan[] } | null>(null)
  const [scans, setScans] = useState<Scan[]>([])
  const [serverState, setServerState] = useState<'checking' | 'online' | 'offline'>('checking')
  const [mobileMenu, setMobileMenu] = useState(false)
  const [notifications, setNotifications] = useState(false)
  const [toast, setToast] = useState('')
  const [clearing, setClearing] = useState(false)
  const [wifiData, setWifiData] = useState<WifiScanResult | null>(null)
const [wifiBusy, setWifiBusy] = useState(false)
const [wifiError, setWifiError] = useState('')

async function handleWifiScan() {
  setWifiBusy(true)
  setWifiError('')

  try {
    const data = await scanWifi()
    setWifiData(data)
  } catch (e) {
    setWifiError(
      e instanceof Error ? e.message : 'Unable to scan Wi-Fi networks.'
    )
  } finally {
    setWifiBusy(false)
  }
} 
  async function refreshData() {
    try {
      const [health, nextSummary, nextScans] = await Promise.all([api.health(), api.summary(), api.scans()])
      setServerState(health.ok ? 'online' : 'offline')
      setSummary(nextSummary)
      setScans(nextScans.scans)
    } catch {
      setServerState('offline')
    }
  }

  useEffect(() => { void refreshData() }, [])
  const filteredTools = useMemo(() => tools.filter(t => `${t.title} ${t.description}`.toLowerCase().includes(query.toLowerCase())), [query])
  const chartData = useMemo(() => chartLabels.map((day, i) => {
    const now = new Date()
    const date = new Date(now)
    date.setDate(now.getDate() - ((now.getDay() + 6) % 7) + i)
    const count = scans.filter(s => {
      const d = new Date(s.createdAt)
      return d.getFullYear() === date.getFullYear() && d.getMonth() === date.getMonth() && d.getDate() === date.getDate()
    }).length
    return { day, scans: count }
  }), [scans])

  function openTool(tool: CheckTool) {
    setSelectedTool(tool); setInput(''); setResult(null); setError('')
  }

  async function runCheck() {
    if (!selectedTool || !input.trim()) { setError('Enter a value to continue.'); return }
    setBusy(true); setError(''); setResult(null)
    try {
      const response = await api.check(selectedTool.type, input.trim())
      setResult(response.result)
      await refreshData()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not complete check.')
    } finally { setBusy(false) }
  }

  async function clearHistory() {
    if (!window.confirm('Clear all scan history saved to your account?')) return
    setClearing(true)
    try {
      await api.clearScans()
      await refreshData()
      setToast('Scan history cleared.')
      window.setTimeout(() => setToast(''), 2500)
    } catch { setToast('Could not clear history. Is the API running?') }
    finally { setClearing(false) }
  }

  const recent = scans.slice(0, 5)
  const statusLabel = serverState === 'online' ? 'Backend connected' : serverState === 'offline' ? 'Backend offline' : 'Connecting API…'

  return <div className="app-shell">
    <aside className={`sidebar ${mobileMenu ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={23}/></div><div><strong>CyberShield</strong><span>SECURITY CENTER</span></div><button className="icon-btn close-menu" onClick={() => setMobileMenu(false)} aria-label="Close menu"><X size={18}/></button></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="nav-list">
        {[{label:'Overview',icon:LayoutDashboard},{label:'Security checks',icon:ShieldCheck},{label:'Activity log',icon:Activity},{label:'Settings',icon:Settings}].map(item => { const Icon=item.icon; return <button key={item.label} className={`nav-item ${activeNav===item.label?'active':''}`} onClick={()=>{setActiveNav(item.label);setMobileMenu(false)}}><Icon size={18}/><span>{item.label}</span>{item.label==='Activity log'&&<span className="nav-count">{scans.length}</span>}</button> })}
      </nav>
      <div className="sidebar-spacer"/>
      <div className="sidebar-protection"><div className="mini-shield"><Shield size={19}/></div><div><strong>API status</strong><p>{statusLabel}</p></div><span className={`online-dot ${serverState!=='online'?'offline-dot':''}`}/></div>
      <div className="sidebar-footer"><div className="avatar">CS</div><div className="profile"><strong>{userName}</strong><span>Signed in</span></div><button className="icon-btn" onClick={onLogout} aria-label="Log out" title="Log out"><LogOut size={16}/></button></div>
    </aside>
    {mobileMenu&&<div className="scrim" onClick={()=>setMobileMenu(false)}/>}
    <main className="main-content">
      <header className="topbar"><div className="topbar-left"><button className="icon-btn mobile-menu-btn" onClick={()=>setMobileMenu(true)} aria-label="Open menu"><Menu size={20}/></button><div className="breadcrumb">Workspace <span>/</span> <strong>{activeNav}</strong></div></div><div className="topbar-actions"><div className="search-box"><Search size={16}/><input aria-label="Search security checks" placeholder="Search checks..." value={query} onChange={e=>{setQuery(e.target.value);setActiveNav('Security checks')}}/><kbd>/</kbd></div><div className="notification-wrap"><button className="icon-btn notification-btn" aria-label="Notifications" onClick={()=>setNotifications(!notifications)}><Bell size={18}/><i/></button>{notifications&&<div className="notification-pop"><strong>Workspace status</strong><p><span className="notice-dot"/> {statusLabel}</p><p><span className="notice-dot orange-dot"/> {summary?.risksToReview??0} checks flagged for review.</p><button onClick={()=>setNotifications(false)}>Close</button></div>}</div><div className="top-avatar">CS</div></div></header>

      {activeNav==='Settings'?<section className="simple-page"><div className="eyebrow">PREFERENCES</div><h1>Settings</h1><p className="muted">Firebase-backed service and data controls.</p><div className="panel settings-panel"><h3>Backend connection</h3><div className="setting-row"><span><strong>API status</strong><small>{statusLabel} · http://localhost:4000</small></span><button className="outline-btn" onClick={()=>void refreshData()}><RefreshCw size={14}/> Refresh</button></div><div className="setting-row"><span><strong>Saved scan history</strong><small>{scans.length} record(s) in Firestore</small></span><button className="outline-btn danger-btn" onClick={()=>void clearHistory()} disabled={clearing}><Trash2 size={14}/> Clear history</button></div><p className="demo-note">Scan history is scoped to your authenticated account. External scan results depend on configured provider credentials.</p></div></section>:
      activeNav==='Activity log'?<section className="simple-page"><div className="eyebrow">SAVED EVENTS</div><h1>Activity log</h1><p className="muted">Recent checks saved by the Express backend.</p><div className="panel activity-panel"><div className="activity-toolbar"><strong>{scans.length} saved checks</strong><button className="outline-btn danger-btn" onClick={()=>void clearHistory()} disabled={clearing}><Trash2 size={14}/> Clear history</button></div>{scans.length===0?<div className="empty-state"><Activity size={24}/><strong>No activity yet</strong><span>Run a security check to create the first record.</span></div>:scans.map(scan=><div className="activity-row" key={scan.id}><span className={`activity-dot ${scan.type}`}/><div><strong>{tools.find(t=>t.type===scan.type)?.title??scan.type} — {scan.summary}</strong><small>{new Date(scan.createdAt).toLocaleString()} · {scan.inputPreview}</small></div><span className="activity-tag">Saved</span></div>)}</div></section>:
      <>
        <section className="welcome-section"><div><div className="eyebrow"><span className="eyebrow-line"/> FIREBASE-POWERED SECURITY WORKSPACE</div><h1>Your digital world,<br/><span>better protected.</span></h1><p className="welcome-copy">Run checks, review provider results, and keep your scan history in Firebase Firestore.</p><div className={`api-status ${serverState}`}><span/> {statusLabel}</div></div><div className="welcome-art"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="art-glow"/><div className="art-shield"><ShieldCheck size={57} strokeWidth={1.35}/></div><div className="float-chip chip-safe"><span className="chip-check"><Check size={12}/></span> Authenticated security workspace</div><div className="float-chip chip-ai"><Zap size={14}/> Verified sources where configured</div></div></section>
        <section className="stats-grid">
          <div className="stat-card"><div className="stat-top"><span>Saved checks</span><span className="stat-icon teal"><ShieldCheck size={17}/></span></div><div className="stat-value">{summary?.totalChecks??'—'}</div><div className="stat-foot"><span>Firestore storage</span></div><div className="score-track"><div style={{width:`${Math.min(100,(summary?.totalChecks??0)*5)}%`}}/></div></div>
          <div className="stat-card"><div className="stat-top"><span>Checks today</span><span className="stat-icon blue"><ClipboardCheck size={17}/></span></div><div className="stat-value">{scans.filter(s=>new Date(s.createdAt).toDateString()===new Date().toDateString()).length}</div><div className="stat-foot"><span>Your saved records</span></div><div className="stat-spark">{[35,55,40,85,62,95,70,55,78,48,82,65].map((v,i)=><span key={i} style={{height:`${v}%`}}/>)}</div></div>
          <div className="stat-card"><div className="stat-top"><span>Risks to review</span><span className="stat-icon orange"><AlertTriangle size={17}/></span></div><div className="stat-value">{summary?.risksToReview??'—'}</div><div className="stat-foot"><span className="risk-label"><span/> Local rule flags only</span></div><div className="risk-progress"><div style={{width:`${Math.min(100,(summary?.risksToReview??0)*10)}%`}}/></div></div>
          <div className="stat-card"><div className="stat-top"><span>Backend status</span><span className="stat-icon purple"><Server size={17}/></span></div><div className="status-value"><span className={`status-indicator ${serverState==='online'?'':'status-down'}`}/>{serverState==='online'?'Connected':serverState==='offline'?'Offline':'Checking…'}</div><p className="stat-description">Express API · Firebase Firestore</p><button className="text-link" onClick={()=>void refreshData()}>Refresh status <ArrowRight size={14}/></button></div>
        </section>
        <section className="section-heading"><div><div className="eyebrow">YOUR TOOLKIT</div><h2>Security checks</h2><p>Each tool sends input to your local API and returns a structured result.</p></div><button className="outline-btn" onClick={()=>setActiveNav('Activity log')}>View history <ArrowRight size={15}/></button></section>
       
       <section className="feature-grid">{filteredTools.map(tool=>{const Icon=icons[tool.type];return <article className="feature-card" key={tool.type}><div className={`feature-icon ${tool.color}`}><Icon size={20}/></div><div className="feature-card-title"><h3>{tool.title}</h3><span className={`status-pill ${serverState==='online'?'':'warning'}`}><i/>{serverState==='online'?'API tool':'API unavailable'}</span></div><p>{tool.description}</p><button className="feature-action" onClick={()=>openTool(tool)}>{tool.action}<ArrowRight size={15}/></button></article>})}{filteredTools.length===0&&<div className="empty-state"><Search size={24}/><strong>No checks found</strong><span>Try another search term.</span></div>}</section>
       {activeNav !== 'Settings' && activeNav !== 'Activity log' && (
  <section className="panel wifi-scanner-panel">
    <div className="panel-heading">
      <div>
        <div className="eyebrow">NETWORK SECURITY</div>
        <h3>Wi-Fi Scanner</h3>
        <p>Scan networks visible to your Windows computer.</p>
      </div>

      <button
        className="primary-btn"
        onClick={() => void handleWifiScan()}
        disabled={wifiBusy}
      >
        <RefreshCw size={16} />
        {wifiBusy ? 'Scanning...' : wifiData ? 'Rescan Wi-Fi' : 'Scan Wi-Fi'}
      </button>
    </div>

    {wifiError && (
      <div className="result-box result-warning">
        <AlertTriangle size={17} />
        <p>{wifiError}</p>
      </div>
    )}

    {!wifiData && !wifiError && !wifiBusy && (
      <div className="empty-state">
        <Wifi size={28} />
        <strong>Ready to scan</strong>
        <span>Press Scan Wi-Fi to view the connected network and nearby networks.</span>
      </div>
    )}

    {wifiData && (
      <>
        <h4>Connected Network</h4>

        {wifiData.connectedWifi ? (
          <div className="wifi-details-grid">
            <div className="wifi-detail">
              <span>Network name</span>
              <strong>{wifiData.connectedWifi.ssid}</strong>
            </div>

            <div className="wifi-detail">
              <span>Signal strength</span>
              <strong>{wifiData.connectedWifi.signal}</strong>
            </div>

            <div className="wifi-detail">
              <span>Authentication</span>
              <strong>{wifiData.connectedWifi.authentication}</strong>
            </div>

            <div className="wifi-detail">
              <span>Encryption</span>
              <strong>{wifiData.connectedWifi.encryption}</strong>
            </div>

            <div className="wifi-detail">
              <span>Channel</span>
              <strong>{wifiData.connectedWifi.channel}</strong>
            </div>

            <div className="wifi-detail">
              <span>Frequency band</span>
              <strong>{wifiData.connectedWifi.band}</strong>
            </div>

            <div className="wifi-detail">
              <span>Radio type</span>
              <strong>{wifiData.connectedWifi.radioType}</strong>
            </div>

            <div className="wifi-detail">
              <span>Receive rate</span>
              <strong>{wifiData.connectedWifi.receiveRate} Mbps</strong>
            </div>

            <div className="wifi-detail">
              <span>Transmit rate</span>
              <strong>{wifiData.connectedWifi.transmitRate} Mbps</strong>
            </div>
          </div>
        ) : (
          <p>No Wi-Fi network is currently connected.</p>
        )}

        <h4>Available Wi-Fi Networks ({wifiData.networks.length})</h4>

        {wifiData.networks.length > 0 ? (
          <div className="wifi-network-list">
            {wifiData.networks.map((network, index) => (
              <div
                className="wifi-network-row"
                key={`${network.ssid}-${index}`}
              >
                <Wifi size={20} />

                <div>
                  <strong>{network.ssid || '(Hidden network)'}</strong>
                  <p>
                    {network.authentication} · {network.encryption}
                  </p>
                </div>

                <div className="wifi-network-meta">
                  <span>{network.signal}</span>
                  <small>Channel {network.channel}</small>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p>No visible Wi-Fi networks were reported.</p>
        )}

        <h4>Security Review</h4>

        {wifiData.securityWarnings.map((warning, index) => (
          <div className="wifi-warning" key={`${warning}-${index}`}>
            <AlertTriangle size={17} />
            <span>{warning}</span>
          </div>
        ))}

        <p className="limitations">{wifiData.limitations}</p>

        <small className="field-help">
          Last scanned: {new Date(wifiData.scannedAt).toLocaleString()}
        </small>
      </>
    )}
  </section>
)}
        <section className="bottom-grid">
          <div className="panel activity-chart-panel"><div className="panel-heading"><div><h3>Saved activity</h3><p>Checks stored by the backend this week</p></div><button className="select-chip" onClick={()=>void refreshData()}><RefreshCw size={13}/> Refresh</button></div><div className="chart-summary"><strong>{chartData.reduce((a,b)=>a+b.scans,0)} <span>checks this week</span></strong></div><div className="chart-area"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData} margin={{top:10,right:6,left:-20,bottom:0}}><defs><linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4f8cff" stopOpacity={0.25}/><stop offset="100%" stopColor="#4f8cff" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#263149" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="day" axisLine={false} tickLine={false} tick={{fill:'#7f8ca7',fontSize:11}} dy={10}/><YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{fill:'#7f8ca7',fontSize:11}}/><Tooltip contentStyle={{background:'#151e31',border:'1px solid #2a3853',borderRadius:10,color:'#eaf0ff'}}/><Area type="monotone" dataKey="scans" stroke="#4f8cff" strokeWidth={2.5} fill="url(#scanGradient)" activeDot={{r:5,fill:'#4f8cff',stroke:'#fff',strokeWidth:2}}/></AreaChart></ResponsiveContainer></div></div>
          <div className="panel recommendations-panel"><div className="panel-heading"><div><h3>Recent checks</h3><p>Latest records returned by the API</p></div><span className="sparkle"><Activity size={16}/></span></div>{recent.length===0?<div className="empty-state compact"><ClipboardCheck size={22}/><strong>No checks yet</strong><span>Run a tool to populate this panel.</span></div>:recent.slice(0,3).map(scan=><div className="recommendation-item" key={scan.id}><div className={`recommendation-icon ${tools.find(t=>t.type===scan.type)?.color??'blue'}`}>{(()=>{const Icon=icons[scan.type];return <Icon size={18}/>})()}</div><div><strong>{tools.find(t=>t.type===scan.type)?.title??scan.type}</strong><p>{scan.summary}</p><small>{new Date(scan.createdAt).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</small></div></div>)}<div className="tip-banner"><div className="tip-icon"><CircleHelp size={17}/></div><p><strong>Prototype limitation</strong><br/>Live reputation providers, AI APIs, and device scanning are not connected.</p></div></div>
        </section>
      </>}
      <footer className="footer"><span>© 2026 CyberShield Full-stack Prototype</span><span><span className={`footer-dot ${serverState!=='online'?'offline-dot':''}`}/> {statusLabel}<span className="footer-sep">·</span><button onClick={()=>setActiveNav('Settings')}>API settings</button></span></footer>
    </main>

    {selectedTool&&<div className="modal-backdrop" role="presentation" onClick={()=>!busy&&setSelectedTool(null)}><section className="check-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" onClick={e=>e.stopPropagation()}><button className="modal-close icon-btn" onClick={()=>setSelectedTool(null)} aria-label="Close" disabled={busy}><X size={19}/></button><div className={`feature-icon modal-feature-icon ${selectedTool.color}`}>{(()=>{const Icon=icons[selectedTool.type];return <Icon size={23}/>})()}</div><div className="eyebrow">EXPRESS API · FIREBASE</div><h2 id="modal-title">{selectedTool.title}</h2><p className="modal-description">{selectedTool.description} Results come from configured providers or clearly labelled local checks; history is saved to your account.</p><label className="field-label" htmlFor="check-input">{selectedTool.type==='email'?'Email address':selectedTool.type==='password'?'Test password (not stored)':selectedTool.type==='domain'?'Domain or URL':'Topic or item to review'}</label><input id="check-input" className="modal-input" value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>{if(e.key==='Enter')void runCheck()}} placeholder={selectedTool.placeholder} type={selectedTool.type==='password'?'password':'text'} disabled={busy}/>{selectedTool.type==='password'&&<small className="field-help">Password is checked in memory and excluded from saved history. Do not reuse a real password.</small>}<button className="primary-btn run-btn" onClick={()=>void runCheck()} disabled={busy}><Zap size={16}/>{busy?'Running check…':selectedTool.action}<ArrowRight size={15}/></button>{error&&<div className="result-box result-warning"><AlertTriangle size={17}/><p>{error}</p></div>}{result&&<div className={`result-box ${result.status === 'unavailable' || ['invalid-format','invalid-input','improve','review-needed','malicious-detections','suspicious-detections','email-invalid','email-catch-all','email-unknown','guidance-only'].includes(result.verdict)?'result-warning':'result-success'}`}><div className="result-icon">{['invalid-format','invalid-input','improve','review-needed'].includes(result.verdict)?<AlertTriangle size={17}/>:<Check size={17}/>}</div><div><strong>{result.summary}</strong><p className="result-meta">Source: {result.source} · Status: {result.status === 'complete' ? 'Completed' : 'Unavailable'}</p>{result.details?.stats&&<p>Detections — malicious: {result.details.stats.malicious}, suspicious: {result.details.stats.suspicious}, harmless: {result.details.stats.harmless}, undetected: {result.details.stats.undetected}</p>}{result.details?.providerStatus&&<p>Provider status: {result.details.providerStatus}{result.details.subStatus ? ` (${result.details.subStatus})` : ''}</p>}{result.score!==undefined&&<p>Strength checks: {result.score}/{result.maxScore}</p>}{result.details?.checks&&<ul className="result-list">{result.details.checks.map((c:{label:string;passed:boolean})=><li key={c.label}><span className={c.passed?'passed':'failed'}>{c.passed?'✓':'×'}</span>{c.label}</li>)}</ul>}{result.details?.signals&&<ul className="result-list">{result.details.signals.map((s:{label:string;found:boolean})=><li key={s.label}><span className={s.found?'failed':'passed'}>{s.found?'!':'✓'}</span>{s.label}: {s.found?'detected':'not detected'}</li>)}</ul>}{result.details?.recommendations&&<ul className="result-list">{result.details.recommendations.map((s:string)=><li key={s}><span className="passed">✓</span>{s}</li>)}</ul>}{result.details?.advice&&<p>{result.details.advice}</p>}{result.details?.advice instanceof Array&&result.details.advice.map((s:string)=><p key={s}>{s}</p>)}<p className="limitations">{result.limitations}</p></div></div>}<div className="privacy-note"><Shield size={15}/><span>Password input is never saved. Domain and email results use configured providers; other checks clearly disclose their limitations.</span></div></section></div>}
    {toast&&<div className="toast"><Check size={16}/>{toast}</div>}
  </div>
}




export default function App() {
  const [user, setUser] = useState<User | null>(null)
  const [authReady, setAuthReady] = useState(false)

  useEffect(() => {
    if (!firebaseConfigured || !auth) {
      setAuthReady(true)
      return
    }
    return onAuthStateChanged(auth, nextUser => {
      setUser(nextUser)
      setAuthReady(true)
    })
  }, [])

  if (!authReady) {
    return <div className="auth-loading"><ShieldCheck size={26}/><p>Checking your secure session…</p></div>
  }

  if (!user) return <AuthScreen onAuthenticated={() => {}} />

  return <DashboardApp
    userName={user.displayName || user.email || 'CyberShield User'}
    onLogout={() => { if (auth) void signOut(auth) }}
  />
}

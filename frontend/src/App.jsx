
import React, { useEffect, useState, useRef } from "react";
import {
  ShieldCheck, LayoutDashboard, ScanSearch, History,
  BarChart3, Layers, QrCode, GitCompare, FileText,
  Lightbulb, Globe, Trash2, Download, Menu, X,
  AlertTriangle, CheckCircle, Search, RefreshCw,
  Eye, EyeOff, LogOut
} from "lucide-react";
import { Doughnut } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { Html5Qrcode } from "html5-qrcode";
import jsPDF from "jspdf";
import "./App.css";

ChartJS.register(ArcElement, Tooltip, Legend);

const API = import.meta.env.VITE_API_URL || "http://localhost:5000";

const tips = [
  "Check the spelling of a website's domain before entering information.",
  "Avoid clicking unexpected links received through messages or emails.",
  "Never share passwords or OTPs through an unknown website.",
  "Use HTTPS websites, but remember HTTPS alone does not prove a site is trustworthy.",
  "Be careful with shortened links because they hide their final destination.",
  "Do not download unexpected files from unknown websites.",
  "Use official websites and bookmarks for banking and important accounts.",
  "Never enter personal information when a website address looks suspicious."
];

function RiskBadge({ level }) {
  return <span className={`risk-badge ${(level || "low").toLowerCase()}`}>
    {level || "Unknown"}
  </span>;
}

function Stat({ title, value, icon, color }) {
  return <div className="stat-card">
    <div className={`stat-icon ${color}`}>{icon}</div>
    <div><p>{title}</p><h2>{value ?? 0}</h2></div>
  </div>;
}

function App() {
  const [page, setPage] = useState("Dashboard");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState({});
  const [bulkText, setBulkText] = useState("");
  const [bulkResults, setBulkResults] = useState([]);
  const [compareA, setCompareA] = useState("");
  const [compareB, setCompareB] = useState("");
  const [comparison, setComparison] = useState(null);
  const [qrMessage, setQrMessage] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [user, setUser] = useState(null);
 const [token, setToken] = useState(() => localStorage.getItem("token"));
const [authMode, setAuthMode] = useState("login");
const [authName, setAuthName] = useState("");
const [authEmail, setAuthEmail] = useState("");
const [authPassword, setAuthPassword] = useState("");
const [showPassword, setShowPassword] = useState(false);
  const navigation = [
    ["Dashboard", <LayoutDashboard />],
    ["URL Scanner", <ScanSearch />],
    ["Bulk Scanner", <Layers />],
    ["QR Scanner", <QrCode />],
    ["URL Comparison", <GitCompare />],
    ["Scan History", <History />],
    ["Analytics", <BarChart3 />],
    ["Domain Analysis", <Globe />],
    ["Reports", <FileText />],
    ["Security Tips", <Lightbulb />]
  ];

  async function request(path, options = {}, authToken = token) {
    const response = await fetch(`${API}${path}`, {
      ...options,
     headers: {
  "Content-Type": "application/json",
 ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
  ...(options.headers || {})
}
    });

   
const data = await response.json();
if (!response.ok) throw new Error(data.message || "Request failed");
return data;
}



    
async function handleAuth() {
  try {
    setError("");

    const path = authMode === "register"
      ? "/api/auth/register"
      : "/api/auth/login";

    const body = authMode === "register"
      ? { name: authName, email: authEmail, password: authPassword }
      : { email: authEmail, password: authPassword };

    const data = await request(path, {
      method: "POST",
      body: JSON.stringify(body)
    });

    if (authMode === "register") {
      setAuthName("");
      setAuthEmail("");
      setAuthPassword("");
      setAuthMode("login");
      setError("Account created successfully. Please log in.");
      return;
    }

    localStorage.setItem("token", data.token);

    setHistory([]);
    setStats({
      total: 0,
      lowCount: 0,
      mediumCount: 0,
      highCount: 0,
      averageScore: 0
    });

    setToken(data.token);
    setUser(data.user);
    setAuthPassword("");

  } catch (err) {
    setError(err.message);
  }
}


  
     async function loadData(authToken = token) {
  try {
    const [rows, summary] = await Promise.all([
      request("/api/history", {}, authToken),
      request("/api/stats", {}, authToken)
    ]);

    if (authToken === token) {
      setHistory(rows);
      setStats(summary);
    }
  } catch (err) {
    setError(err.message);
  }
}

useEffect(() => {
  if (!token) return;

  let cancelled = false;

  async function loadUserData() {
    try {
      const data = await request("/api/auth/me", {}, token);

      if (cancelled) return;

      setUser(data.user);

      const [rows, summary] = await Promise.all([
        request("/api/history", {}, token),
        request("/api/stats", {}, token)
      ]);

      if (!cancelled) {
        setHistory(rows);
        setStats(summary);
      }
    } catch (err) {
      if (!cancelled) {
        localStorage.removeItem("token");
        setToken(null);
        setUser(null);
        setAuthEmail("");
        setAuthName("");
        setAuthPassword("");
        setHistory([]);
        setStats({});
      }
    }
  }

  loadUserData();

  return () => {
    cancelled = true;
  };
}, [token]);
  async function scanURL(value = url) {
    if (!value.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await request("/api/scan", {
        method: "POST",
        body: JSON.stringify({ url: value.trim() })
      });
      setResult(data);
      setUrl(value.trim());
      await loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function runBulkScan() {
    const urls = bulkText.split(/\r?\n|,/).map(x => x.trim()).filter(Boolean);

    if (!urls.length) return setError("Enter URLs on separate lines.");
    if (urls.length > 20) return setError("Maximum 20 URLs per batch.");

    setLoading(true);
    setError("");

    try {
      const data = await request("/api/bulk-scan", {
        method: "POST",
        body: JSON.stringify({ urls })
      });
      setBulkResults(data.results);
      await loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function scanQR(file) {
    if (!file) return;

    setQrMessage("Reading QR code...");
    setError("");

    try {
      const scanner = new Html5Qrcode("qr-reader");
      const decoded = await scanner.scanFile(file, true);
      setQrMessage(`QR URL found: ${decoded}`);
      setUrl(decoded);
      setPage("URL Scanner");
      await scanURL(decoded);
    } catch (err) {
      setQrMessage("Could not read a URL from this QR image. Try another clear QR image.");
    }
  }

  async function compareURLs() {
    if (!compareA.trim() || !compareB.trim()) {
      return setError("Enter both URLs to compare.");
    }

    setLoading(true);
    setError("");

    try {
      const [a, b] = await Promise.all([
        request("/api/analyze", {
          method: "POST",
          body: JSON.stringify({ url: compareA.trim() })
        }),
        request("/api/analyze", {
          method: "POST",
          body: JSON.stringify({ url: compareB.trim() })
        })
      ]);
      setComparison([a, b]);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function deleteRecord(id) {
    if (!window.confirm("Delete this scan record?")) return;

    try {
      await request(`/api/history/${id}`, { method: "DELETE" });
      await loadData();
    } catch (err) {
      setError(err.message);
    }
  }

  function downloadCSV() {
    const headings = ["URL", "Risk Score", "Risk Level", "Scanned At"];
    const rows = history.map(row => [
      row.url, row.risk_score, row.risk_level, row.scanned_at
    ]);

    const csv = [headings, ...rows]
      .map(row => row.map(value =>
        `"${String(value ?? "").replace(/"/g, '""')}"`
      ).join(","))
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "safelink-report.csv";
    link.click();
    URL.revokeObjectURL(link.href);
  }

  function downloadPDF() {
    const pdf = new jsPDF();
    pdf.setFontSize(20);
    pdf.text("SafeLink Scan Report", 14, 20);
    pdf.setFontSize(11);
    pdf.text(`Total scans: ${history.length}`, 14, 32);

    let y = 44;
    history.slice(0, 35).forEach((item, index) => {
      const lines = pdf.splitTextToSize(
        `${index + 1}. ${item.url} | Score: ${item.risk_score} | Risk: ${item.risk_level}`,
        180
      );
      if (y + lines.length * 6 > 280) {
        pdf.addPage();
        y = 20;
      }
      pdf.text(lines, 14, y);
      y += lines.length * 6 + 3;
    });

    pdf.save("safelink-report.pdf");
  }

  const filteredHistory = history.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === "All" || item.risk_level === filter;
    return matchesSearch && matchesFilter;
  });

  const chartData = {
    labels: ["Low", "Medium", "High"],
    datasets: [{
      data: [
        stats.lowCount || 0,
        stats.mediumCount || 0,
        stats.highCount || 0
      ],
      backgroundColor: ["#16a36a", "#e9a23b", "#e34d59"],
      borderWidth: 0
    }]
  };

  function historyTable(rows) {
    return <div className="table-wrap">
      <table>
        <thead><tr>
          <th>URL</th><th>Score</th><th>Risk</th><th>Date</th><th>Action</th>
        </tr></thead>
        <tbody>
          {rows.map(row => <tr key={row.id}>
            <td className="url-cell">{row.url}</td>
            <td>{row.risk_score}/100</td>
            <td><RiskBadge level={row.risk_level} /></td>
            <td>{new Date(row.scanned_at).toLocaleString()}</td>
            <td><button className="icon-button" onClick={() => deleteRecord(row.id)}><Trash2 size={16} /></button></td>
          </tr>)}
          {!rows.length && <tr><td colSpan="5" className="empty">No records available.</td></tr>}
        </tbody>
      </table>
    </div>;
  }

  function resultCard(data) {
    if (!data) return null;

    return <div className="result-card">
      <div className="result-top">
        <div><span className="muted">Scan result</span><h2>{data.url}</h2></div>
        <RiskBadge level={data.riskLevel} />
      </div>
      <div className="score">{data.riskScore}<small>/100</small></div>
      <div className="score-track"><div style={{ width: `${data.riskScore}%` }} /></div>
      <h3>Detected indicators</h3>
      {data.issues.length ? data.issues.map((issue, i) =>
        <div className="issue" key={i}>
          <AlertTriangle size={18} />
          <div><b>{issue.title} (+{issue.points})</b><p>{issue.description}</p></div>
        </div>
      ) : <p className="success-text"><CheckCircle size={17} /> No suspicious indicators were found by the basic checks.</p>}
      <div className="recommendation"><b>Safety recommendation</b><p>{data.recommendation}</p></div>
      <h3>Domain analysis</h3>
      <div className="domain-grid">
        <div><small>Domain</small><b>{data.domain}</b></div>
        <div><small>Protocol</small><b>{data.protocol.toUpperCase()}</b></div>
        <div><small>HTTPS</small><b>{data.usesHTTPS ? "Yes" : "No"}</b></div>
        <div><small>URL length</small><b>{data.urlLength}</b></div>
        <div><small>IP address</small><b>{data.hasIPAddress ? "Yes" : "No"}</b></div>
        <div><small>Domain sections</small><b>{data.hostnameParts.length}</b></div>
      </div>
      <p className="disclaimer">This is a rule-based indicator score, not a confirmed threat-intelligence verdict. A low score does not guarantee safety.</p>
    </div>;
  }

  
   function comparisonCard(item, index, higherRiskIndex) {
  return <div className="compare-card">
    <h3>URL {index + 1}: {item.domain}</h3>

    <RiskBadge level={item.riskLevel} />

    <div className="score">
      {item.riskScore}<small>/100</small>
    </div>

    <p>{item.recommendation}</p>
    <p>{item.issues.length} indicators detected</p>

    {higherRiskIndex === -1 ? (
      <p><b>Both URLs have the same risk score.</b></p>
    ) : higherRiskIndex === index ? (
      <p className="higher-risk">
        <AlertTriangle size={17} />
        <b>Higher Risk URL</b>
      </p>
    ) : (
      <p className="lower-risk">
        <CheckCircle size={17} />
        Lower risk compared with the other URL
      </p>
    )}
  </div>;
}
  
 
  if (!token) {
  return (
    <div className="auth-container">
      <form className="auth-card" onSubmit={e => {
        e.preventDefault();
        handleAuth();
      }}>
        <ShieldCheck size={40} />
        <h1>SafeLink</h1>
        <p>{authMode === "register" ? "Create your account" : "Login to your account"}</p>

        {authMode === "register" && (
         <input
  type="text"
  name="safelink-new-name"
  placeholder="Your name"
  value={authName}
  onChange={e => setAuthName(e.target.value)}
  autoComplete="off"
  required
/>
        )}

<input
  type="email"
  name="safelink-login-email"
  placeholder="Email address"
  value={authEmail}
  onChange={e => setAuthEmail(e.target.value)}
  autoComplete="off"
  required
/>
        <div className="password-wrapper">
 <input
  type={showPassword ? "text" : "password"}
  placeholder="Password (minimum 8 characters)"
  value={authPassword}
  onChange={e => setAuthPassword(e.target.value)}
  autoComplete="new-password"
  minLength="8"
  required
/>
  <button
    type="button"
    className="password-toggle"
    onClick={() => setShowPassword(!showPassword)}
  >
    {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
  </button>
</div>
        {error && <div className="error-message">{error}</div>}

        <button className="primary-button" type="submit">
          {authMode === "register" ? "Create Account" : "Login"}
        </button>

        <p>
          {authMode === "login"
            ? "Don't have an account?"
            : "Already have an account?"}
          <button
            type="button"
            onClick={() => {
  setAuthMode(authMode === "login" ? "register" : "login");
  setAuthName("");
  setAuthPassword("");
  setError("");
}}
          >
            {authMode === "login" ? "Register" : "Login"}
          </button>
        </p>
      </form>
    </div>
  );
}

  return <div className="app-shell">
    <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
      <div className="brand"><ShieldCheck size={30} /><div><b>SafeLink</b><small>URL Risk Analyzer</small></div>
        <button className="mobile-close" onClick={() => setMenuOpen(false)}><X /></button>
      </div>
      <p className="nav-label">WORKSPACE</p>
      {navigation.map(([name, icon]) =>
        <button key={name} className={`nav-item ${page === name ? "active" : ""}`}
         onClick={() => {
  
  if (name === "URL Scanner") {
  setUrl("");
}
  
  setPage(name);
  setMenuOpen(false);
  setError("");
}}
>
          {icon}<span>{name}</span>
        </button>
      )}
      <div className="sidebar-bottom">SafeLink © 2026</div>
    </aside>

    <main className="main-content">
      <header className="topbar">
        <button className="mobile-menu" onClick={() => setMenuOpen(true)}><Menu /></button>
        <div><small>SECURITY WORKSPACE</small><h2>{page}</h2></div>
        
      
<div className="topbar-actions">
  <div className="user-profile">
    <div className="user-avatar">
      {user?.name?.charAt(0).toUpperCase()}
    </div>
    <div className="user-details">
      <span className="user-label">WELCOME BACK</span>
      <span className="user-name">{user?.name}</span>
    </div>
  </div>

  <button className="refresh-button" onClick={loadData}>
    <RefreshCw size={17} /> Refresh
  </button>

  <button
    className="logout-button"
onClick={() => {
  localStorage.removeItem("token");
  setToken(null);
  setUser(null);
  setAuthEmail("");
   setAuthName("");
  setAuthPassword("");
  setHistory([]);
  setStats({});
  setResult(null);
  setBulkResults([]);
  setPage("Dashboard");
}}
  >
    <LogOut size={17} /> Logout
  </button>
</div>

      </header>

      {error && <div className="error-message">{error}<button onClick={() => setError("")}>×</button></div>}

      {page === "Dashboard" && <>
        <section className="welcome">
          <div><span>URL SECURITY OVERVIEW</span><h1>Welcome to SafeLink</h1>
            <p>Analyze URLs and understand suspicious indicators.</p></div>
          <ShieldCheck size={60} />
        </section>
        <div className="stats-grid">
          <Stat title="Total Scans" value={stats.total} icon={<ScanSearch />} color="blue" />
          <Stat title="Low Risk" value={stats.lowCount} icon={<CheckCircle />} color="green" />
          <Stat title="Medium Risk" value={stats.mediumCount} icon={<AlertTriangle />} color="orange" />
          <Stat title="High Risk" value={stats.highCount} icon={<AlertTriangle />} color="red" />
        </div>
        <div className="dashboard-grid">
          <section className="panel"><h3>Risk Distribution</h3>
            <div className="chart-box"><Doughnut data={chartData} options={{ maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } }} /></div>
          </section>
          <section className="panel"><h3>Recent Scans</h3>{historyTable(history.slice(0, 5))}</section>
        </div>
        <button className="primary-button" onClick={() => setPage("URL Scanner")}>Start URL Scan</button>
      </>}

      {page === "URL Scanner" && <section className="panel">
        <h3><ScanSearch /> URL Scanner</h3>
        <p className="muted">Enter a complete URL, including https:// or http://.</p>
        <div className="input-row"><input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" />
          <button className="primary-button" disabled={loading} onClick={() => scanURL()}>{loading ? "Scanning..." : "Scan URL"}</button></div>
        {resultCard(result)}
      </section>}

      {page === "Bulk Scanner" && <section className="panel">
        <h3><Layers /> Bulk URL Scanner</h3>
        <p className="muted">Enter up to 20 URLs, one per line or separated by commas.</p>
        <textarea rows="8" value={bulkText} onChange={e => setBulkText(e.target.value)} placeholder={"https://example.com\nhttp://example.org/login\nhttps://www.wikipedia.org"} />
        <button className="primary-button" disabled={loading} onClick={runBulkScan}>{loading ? "Scanning..." : "Scan all URLs"}</button>
        {bulkResults.length > 0 && <><h3>Bulk scan results ({bulkResults.length})</h3>
          <div className="table-wrap"><table><thead><tr><th>URL</th><th>Score</th><th>Risk</th><th>Status</th></tr></thead>
            <tbody>{bulkResults.map((r, i) => <tr key={i}><td>{r.url}</td><td>{r.riskScore ?? "-"}</td><td>{r.riskLevel ? <RiskBadge level={r.riskLevel} /> : "-"}</td><td>{r.error || "Scanned"}</td></tr>)}</tbody>
          </table></div></>}
      </section>}

      {page === "QR Scanner" && <section className="panel">
        <h3><QrCode /> QR Code Scanner</h3>
        <p className="muted">Upload a QR code image. SafeLink will read the encoded text and analyze it if it is a URL.</p>
        <div id="qr-reader" className="qr-reader"></div>
        <input type="file" accept="image/*" onChange={e => scanQR(e.target.files?.[0])} />
        {qrMessage && <p className="info-message">{qrMessage}</p>}
      </section>}

      {page === "URL Comparison" && <section className="panel">
        <h3><GitCompare /> Compare Two URLs</h3>
        <div className="compare-inputs">
          <input value={compareA} onChange={e => setCompareA(e.target.value)} placeholder="First URL" />
          <input value={compareB} onChange={e => setCompareB(e.target.value)} placeholder="Second URL" />
        </div>
        <button className="primary-button" disabled={loading} onClick={compareURLs}>Compare URLs</button>
      {comparison && (
  <>
    <div className="compare-grid">
      {comparison.map((item, i) => (
        <div className="compare-card" key={i}>
          <h3>URL {i + 1}: {item.domain}</h3>
          <RiskBadge level={item.riskLevel} />
          <div className="score">
            {item.riskScore}<small>/100</small>
          </div>
          <p>{item.recommendation}</p>
          <p>{item.issues.length} indicators detected</p>
        </div>
      ))}
    </div>

    <div className="recommendation">
      <h3>Comparison Summary</h3>
      <p>
        URL {comparison[0].riskScore > comparison[1].riskScore ? "1" : comparison[0].riskScore < comparison[1].riskScore ? "2" : "1 and 2"} has {comparison[0].riskScore === comparison[1].riskScore ? "the same risk score as" : "the higher risk than"} the other URL.
      </p>
    </div>
  </>
)}
        <p className="disclaimer">Comparison analyzes both URLs without adding them to scan history.</p>
      </section>}

      {page === "Scan History" && <section className="panel">
        <h3><History /> Scan History</h3>
        <div className="filter-row"><div className="search-box"><Search /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search URL..." /></div>
          <select value={filter} onChange={e => setFilter(e.target.value)}><option>All</option><option>Low</option><option>Medium</option><option>High</option></select>
        </div>
        {historyTable(filteredHistory)}
      </section>}

      {page === "Analytics" && <section className="panel">
        <h3><BarChart3 /> Risk Analytics</h3>
        <div className="stats-grid">
          <Stat title="Average Risk Score" value={stats.averageScore || 0} icon={<BarChart3 />} color="blue" />
          <Stat title="Total Scans" value={stats.total} icon={<ScanSearch />} color="green" />
        </div>
        <div className="chart-box analytics-chart"><Doughnut data={chartData} options={{ maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } }} /></div>
        <h3>Risk summary</h3>
        <p>Low: {stats.lowCount || 0} | Medium: {stats.mediumCount || 0} | High: {stats.highCount || 0}</p>
      </section>}

     {page === "Domain Analysis" && <section className="panel">
  <h3><Globe /> Domain Analysis</h3>
  <p>Enter a URL in the URL Scanner to view its domain, protocol, HTTPS status, hostname structure and detected indicators.</p>
  {result ? resultCard(result) : <button className="primary-button" onClick={() => setPage("URL Scanner")}>Analyze a URL</button>}
</section>}
      {page === "Reports" && <section className="panel">
        <h3><FileText /> Download Reports</h3>
        <p className="muted">Export your saved scan history for project records.</p>
        <div className="report-actions">
          <button className="primary-button" onClick={downloadPDF}><Download /> Download PDF</button>
          <button className="secondary-button" onClick={downloadCSV}><Download /> Download CSV</button>
        </div>
        <p>Total saved records: <b>{history.length}</b></p>
      </section>}

      {page === "Security Tips" && <section className="panel">
        <h3><Lightbulb /> Security Tips</h3>
        <div className="tips-grid">{tips.map((tip, i) => <div className="tip-card" key={i}>
          <span>{String(i + 1).padStart(2, "0")}</span><p>{tip}</p>
        </div>)}</div>
      </section>}

      <footer className="footer">
        SafeLink © 2026 · Smart Suspicious URL Detection System
        <p>Rule-based checks only. Results are indicators, not a guarantee of website safety.</p>
      </footer>
    </main>
  </div>;
}

export default App;

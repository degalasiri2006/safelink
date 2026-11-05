const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();

app.use(cors({
  origin: process.env.NODE_ENV === "production"
    ? (process.env.FRONTEND_URL || "").split(",").map(x => x.trim())
    : true
}));

app.use(express.json({ limit: "10mb" }));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
 ssl: process.env.DB_SSL === "true"
  ? {
      ca: fs.readFileSync(path.join(__dirname, "ca.pem"), "utf8"),
      rejectUnauthorized: true
    }
  : undefined
});

// Create the scans table automatically
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id INT AUTO_INCREMENT PRIMARY KEY,
      url VARCHAR(2048) NOT NULL,
      risk_score INT NOT NULL,
      risk_level VARCHAR(30) NOT NULL,
      detected_issues TEXT,
      scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// URL analysis engine
function analyzeURL(input) {
  let parsed;

  try {
    parsed = new URL(input);
  } catch {
    throw new Error("Please enter a valid URL, including https:// or http://");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullURL = input.toLowerCase();
  const issues = [];
  let score = 0;

  function addIssue(points, title, description) {
    score += points;
    issues.push({ points, title, description });
  }

  if (parsed.protocol === "http:") {
    addIssue(15, "HTTP connection",
      "The URL does not use HTTPS encryption.");
  }

  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const ipv6 = hostname.includes(":");

  if (ipv4 || ipv6) {
    addIssue(25, "IP address used",
      "The website uses an IP address instead of a normal domain name.");
  }

  const shorteners = [
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "ow.ly", "rb.gy"
  ];

  if (shorteners.some(domain =>
    hostname === domain || hostname.endsWith("." + domain)
  )) {
    addIssue(20, "Shortened URL",
      "The link uses a URL shortening service, hiding its final destination.");
  }

  const suspiciousWords = [
    "login", "verify", "password", "account",
    "banking", "secure", "update", "confirm", "wallet"
  ];

  const foundWords = suspiciousWords.filter(word =>
    fullURL.includes(word)
  );

  if (foundWords.length > 0) {
    addIssue(15, "Suspicious wording",
      "The URL contains these selected words: " + foundWords.join(", "));
  }

  const labels = hostname.split(".");

  if (labels.length > 4) {
    addIssue(10, "Unusual domain structure",
      "The hostname contains more than four sections.");
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    addIssue(10, "Multiple hyphens",
      "The hostname contains three or more hyphens.");
  }

  if (input.includes("@")) {
    addIssue(20, "At symbol detected",
      "The URL contains an @ symbol, which can make its destination confusing.");
  }

  if (input.length > 100) {
    addIssue(5, "Long URL",
      "The URL is unusually long.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    addIssue(10, "Non-standard port",
      "The URL uses a port other than the usual HTTP or HTTPS ports.");
  }

  score = Math.min(score, 100);

  let riskLevel = "Low";
  if (score >= 60) riskLevel = "High";
  else if (score >= 30) riskLevel = "Medium";

  let recommendation;

  if (riskLevel === "High") {
    recommendation = "Avoid opening this link unless you can independently verify its destination.";
  } else if (riskLevel === "Medium") {
    recommendation = "Be careful. Verify the website address before entering personal information.";
  } else {
    recommendation = "Few suspicious indicators were detected. This does not guarantee the website is safe.";
  }

  return {
    url: input,
    riskScore: score,
    riskLevel,
    issues,
    recommendation,
    domain: hostname,
    protocol: parsed.protocol.replace(":", ""),
    usesHTTPS: parsed.protocol === "https:",
    hostnameParts: labels,
    urlLength: input.length,
    hasIPAddress: ipv4 || ipv6
  };
}

async function saveScan(result) {
  const [insert] = await pool.execute(
    `INSERT INTO scans
     (url, risk_score, risk_level, detected_issues)
     VALUES (?, ?, ?, ?)`,
    [
      result.url,
      result.riskScore,
      result.riskLevel,
      JSON.stringify(result.issues)
    ]
  );

  return { id: insert.insertId, ...result };
}

function parseHistoryRow(row) {
  let issues = [];

  try {
    issues = JSON.parse(row.detected_issues || "[]");
  } catch {
    issues = [];
  }

  return { ...row, issues };
}

// Basic routes
app.get("/", (req, res) => {
  res.json({ message: "SafeLink backend is running!" });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "OK", database: "Connected" });
  } catch (error) {
    res.status(500).json({
      status: "ERROR",
      database: "Not connected",
      message: error.message
    });
  }
});

// Scan and save one URL
app.post("/api/scan", async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== "string") {
      return res.status(400).json({ message: "Please enter a URL." });
    }

    const result = analyzeURL(url.trim());
    const saved = await saveScan(result);

    res.json(saved);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Analyze without saving - used for comparison
app.post("/api/analyze", (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== "string") {
      return res.status(400).json({ message: "Please enter a URL." });
    }

    res.json(analyzeURL(url.trim()));
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Bulk scan and save up to 20 URLs
app.post("/api/bulk-scan", async (req, res) => {
  try {
    const { urls } = req.body;

    if (!Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({ message: "Enter at least one URL." });
    }

    if (urls.length > 20) {
      return res.status(400).json({ message: "Maximum 20 URLs per batch." });
    }

    const results = [];

    for (const item of urls) {
      try {
        if (typeof item !== "string" || !item.trim()) {
          throw new Error("Empty URL");
        }

        const result = analyzeURL(item.trim());
        results.push(await saveScan(result));
      } catch (error) {
        results.push({
          url: String(item),
          error: error.message
        });
      }
    }

    res.json({ total: results.length, results });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Scan history
app.get("/api/history", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT 500"
    );

    res.json(rows.map(parseHistoryRow));
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Dashboard analytics
app.get("/api/stats", async (req, res) => {
  try {
    const [[summary]] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(risk_level = 'Low') AS lowCount,
        SUM(risk_level = 'Medium') AS mediumCount,
        SUM(risk_level = 'High') AS highCount,
        ROUND(AVG(risk_score), 1) AS averageScore
      FROM scans
    `);

    res.json({
      total: Number(summary.total || 0),
      lowCount: Number(summary.lowCount || 0),
      mediumCount: Number(summary.mediumCount || 0),
      highCount: Number(summary.highCount || 0),
      averageScore: Number(summary.averageScore || 0)
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Delete one history record
app.delete("/api/history/:id", async (req, res) => {
  try {
    await pool.execute("DELETE FROM scans WHERE id = ?", [req.params.id]);
    res.json({ message: "Scan history record deleted." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;

initializeDatabase()
  .then(() => pool.query("SELECT 1"))
  .then(() => {
    console.log("MySQL connected successfully!");
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`SafeLink server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Unable to start SafeLink:", error.message);
    process.exit(1);
  });

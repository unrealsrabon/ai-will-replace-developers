import { analyzeHeaders, analyzeCookies, simulateCSP, computeConfidence } from '../lib/util.js';

// State
let cache = { all: [], recon: {}, origin: '', ts: null };
let activeCat = 'all';

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupCategoryFilters();
  init();
});

function setupNavigation() {
  const navBtns = document.querySelectorAll('.nav-btn[data-view]');
  const views = document.querySelectorAll('.view');
  
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const viewId = btn.dataset.view;
      navBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      views.forEach(v => v.classList.remove('active'));
      document.getElementById(viewId)?.classList.add('active');
    });
  });
}

function setupCategoryFilters() {
  const catBtns = document.querySelectorAll('.cat-btn');
  catBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      catBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeCat = btn.dataset.cat;
      renderFindings();
    });
  });
}

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url || !tab.url.startsWith('http')) {
      showEmptyState('This page cannot be scanned');
      return;
    }

    const origin = new URL(tab.url).origin;
    const bgData = await chrome.runtime.sendMessage({ type: 'GET_FINDINGS', origin });

    const headers = await getResponseHeaders(tab.url);
    const cookies = await chrome.cookies.getAll({ url: tab.url });
    const headerFindings = analyzeHeaders(headers);
    const cookieFindings = analyzeCookies(cookies);
    const cspSim = simulateCSP(headers);

    const allFindings = [
      ...(bgData.findings || []),
      ...headerFindings,
      ...cookieFindings
    ];

    if (cspSim.risky) {
      allFindings.unshift({
        id: 'hdr.csp.sim',
        title: 'CSP likely allows script execution',
        severity: 'medium',
        desc: `Reasons: ${cspSim.reasons.join(', ')}`,
        attack: 'Inline or unsafe script execution may be feasible, increasing XSS likelihood.'
      });
    }

    cache = {
      all: allFindings,
      recon: bgData.recon || {},
      origin,
      ts: bgData.ts || Date.now()
    };

    const confidence = computeConfidence(allFindings);
    
    updateDashboard(allFindings, confidence);
    renderFindings();
    renderRecon();
    hookEvents();
    
    // Fetch recon data if not already available
    if (!cache.recon.robots && !cache.recon.sitemap) {
      fetchReconData(origin);
    }
    
  } catch (e) {
    console.error('Init error:', e);
    showEmptyState('Error loading data');
  }
}

async function fetchReconData(origin) {
  const robotsEl = document.getElementById('robotsContent');
  const sitemapEl = document.getElementById('sitemapContent');
  
  // Show loading state
  if (robotsEl) robotsEl.innerHTML = '<span class="loading-text">Fetching robots.txt...</span>';
  if (sitemapEl) sitemapEl.innerHTML = '<span class="loading-text">Fetching sitemap.xml...</span>';
  
  try {
    const result = await chrome.runtime.sendMessage({ type: 'RECON_REQUEST', origin });
    cache.recon = result || {};
    renderRecon();
  } catch (e) {
    console.error('Recon error:', e);
    if (robotsEl) robotsEl.textContent = 'Error fetching';
    if (sitemapEl) sitemapEl.textContent = 'Error fetching';
  }
}

function updateDashboard(findings, confidence) {
  // Count only real findings (exclude info)
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
  
  // Total excludes informational findings
  const total = counts.high + counts.medium + counts.low;
  const totalWithInfo = findings.length;
  
  // ========== RISK SCORE CALCULATION ==========
  // Method: Only count HIGH and MEDIUM findings (real impact)
  // INFO findings don't affect risk score
  
  const categoryWeights = {
    // CRITICAL (25-30) - Direct data breach / credential theft
    'apikey': 30,      // Exposed API keys = immediate breach
    'vuln': 25,        // Known CVE = exploitable
    
    // HIGH (15-20) - Security misconfigurations with high impact
    'mixed': 20,       // Mixed content = MITM possible
    'form': 15,        // HTTP form = data interception
    'storage': 15,     // JWT in storage = token theft via XSS
    'hidden': 15,      // JWT in hidden field = token theft
    
    // MEDIUM (8-12) - Requires conditions
    'path': 10,        // Sensitive paths = if accessible
    'info': 8,         // Error messages = info disclosure
  };
  
  // Calculate raw weighted score (only high/medium findings)
  let rawScore = 0;
  const seenCategories = new Set();
  
  for (const f of findings) {
    // Skip informational findings in risk calculation
    if (f.severity === 'info') continue;
    
    const categoryId = f.id.split('.')[0];
    const baseWeight = categoryWeights[categoryId] || 5;
    
    // Severity multiplier (only high and medium matter)
    const sevMultiplier = f.severity === 'high' ? 1.0 : 0.5;
    let weight = baseWeight * sevMultiplier;
    
    // Diminishing returns for same category (25% for duplicates)
    if (seenCategories.has(categoryId)) {
      weight *= 0.25;
    }
    seenCategories.add(categoryId);
    
    rawScore += weight;
  }
  
  // Logarithmic scaling: smooth curve that approaches 100
  // Formula: 100 * (1 - e^(-rawScore/50))
  // This gives: rawScore 10 -> 18, 25 -> 39, 50 -> 63, 100 -> 86, 150 -> 95
  const riskScore = Math.round(100 * (1 - Math.exp(-rawScore / 50)));
  
  // Determine risk level label
  let riskLevel, riskClass;
  if (riskScore <= 20) {
    riskLevel = 'Low Risk';
    riskClass = 'low';
  } else if (riskScore <= 50) {
    riskLevel = 'Medium Risk';
    riskClass = 'medium';
  } else if (riskScore <= 75) {
    riskLevel = 'High Risk';
    riskClass = 'high';
  } else {
    riskLevel = 'Critical';
    riskClass = 'critical';
  }
  
  // ========== HEALTH SCORE CALCULATION ==========
  // Method: Weighted Security Score (points for what's GOOD)
  // Start with max points, subtract for issues found
  
  const maxHealthPoints = 100;
  const healthPenalties = {
    high: 15,    // Each high severity = -15 points
    medium: 8,   // Each medium = -8 points  
    low: 3       // Each low = -3 points
  };
  
  let healthPenalty = 0;
  healthPenalty += counts.high * healthPenalties.high;
  healthPenalty += counts.medium * healthPenalties.medium;
  healthPenalty += counts.low * healthPenalties.low;
  
  const healthScore = Math.max(0, maxHealthPoints - healthPenalty);
  
  // Determine health grade
  let healthGrade, healthClass;
  if (healthScore >= 90) {
    healthGrade = 'A';
    healthClass = 'a';
  } else if (healthScore >= 75) {
    healthGrade = 'B';
    healthClass = 'b';
  } else if (healthScore >= 50) {
    healthGrade = 'C';
    healthClass = 'c';
  } else if (healthScore >= 25) {
    healthGrade = 'D';
    healthClass = 'd';
  } else {
    healthGrade = 'F';
    healthClass = 'f';
  }

  // Update metrics in UI
  const riskEl = document.getElementById('riskScore');
  const findingsEl = document.getElementById('totalFindings');
  const confEl = document.getElementById('confidence');
  const riskLevelEl = document.getElementById('riskLevel');
  const healthGradeEl = document.getElementById('healthGrade');
  
  if (riskEl) riskEl.textContent = riskScore;
  if (findingsEl) findingsEl.textContent = total;
  if (confEl) confEl.textContent = `${healthScore}%`;
  
  if (riskLevelEl) {
    riskLevelEl.textContent = riskLevel;
    riskLevelEl.className = `risk-level ${riskClass}`;
  }
  
  if (healthGradeEl) {
    healthGradeEl.textContent = `Grade ${healthGrade}`;
    healthGradeEl.className = `health-grade ${healthClass}`;
  }

  // Update risk indicator based on risk score
  const indicator = document.getElementById('riskIndicator');
  if (indicator) {
    indicator.className = 'risk-indicator';
    if (riskScore > 50) indicator.classList.add('danger');
    else if (riskScore > 20) indicator.classList.add('warning');
    else indicator.classList.add('safe');
  }

  // Update severity bars
  const maxCount = Math.max(counts.high, counts.medium, counts.low, 1);
  
  const highBar = document.getElementById('highBar');
  const medBar = document.getElementById('medBar');
  const lowBar = document.getElementById('lowBar');
  const highCount = document.getElementById('highCount');
  const medCount = document.getElementById('medCount');
  const lowCount = document.getElementById('lowCount');
  
  if (highBar) highBar.style.width = `${(counts.high / maxCount) * 100}%`;
  if (medBar) medBar.style.width = `${(counts.medium / maxCount) * 100}%`;
  if (lowBar) lowBar.style.width = `${(counts.low / maxCount) * 100}%`;
  if (highCount) highCount.textContent = counts.high;
  if (medCount) medCount.textContent = counts.medium;
  if (lowCount) lowCount.textContent = counts.low;

  // Update findings badge
  const badge = document.getElementById('findingsBadge');
  if (badge && total > 0) {
    badge.textContent = total;
    badge.classList.remove('hidden');
  }

  // Update scan info
  updateScanInfo();
}

function updateScanInfo() {
  // URL
  const urlEl = document.getElementById('scanUrl');
  if (urlEl) {
    try {
      const hostname = new URL(cache.origin).hostname;
      urlEl.textContent = hostname;
      urlEl.title = cache.origin;
    } catch {
      urlEl.textContent = '-';
    }
  }

  // Last scan time
  const timeEl = document.getElementById('lastScan');
  if (timeEl) {
    timeEl.textContent = cache.ts ? new Date(cache.ts).toLocaleTimeString() : 'Just now';
  }

  // Detect technologies
  const techEl = document.getElementById('techList');
  if (techEl) {
    techEl.innerHTML = '';
    const techs = detectTechnologies();
    if (techs.length === 0) techs.push('Unknown');
    
    techs.forEach(tech => {
      const badge = document.createElement('span');
      badge.className = 'tech-badge';
      badge.textContent = tech;
      techEl.appendChild(badge);
    });
  }
}

function detectTechnologies() {
  const techs = new Set();
  
  cache.all.forEach(f => {
    const text = `${f.title} ${f.desc || ''} ${f.id}`.toLowerCase();
    
    if (text.includes('php') || text.includes('phpsessid')) techs.add('PHP');
    if (text.includes('asp') || text.includes('.net')) techs.add('ASP.NET');
    if (text.includes('wordpress') || text.includes('wp-')) techs.add('WordPress');
    if (text.includes('react')) techs.add('React');
    if (text.includes('angular')) techs.add('Angular');
    if (text.includes('vue')) techs.add('Vue.js');
    if (text.includes('jquery')) techs.add('jQuery');
    if (text.includes('nginx')) techs.add('Nginx');
    if (text.includes('apache')) techs.add('Apache');
    if (text.includes('cloudflare')) techs.add('Cloudflare');
  });

  if (cache.recon) {
    const reconText = JSON.stringify(cache.recon).toLowerCase();
    if (reconText.includes('wordpress')) techs.add('WordPress');
  }

  return Array.from(techs).slice(0, 4);
}

function renderFindings() {
  const container = document.getElementById('findingsList');
  if (!container) return;
  
  const searchInput = document.getElementById('searchInput');
  const query = (searchInput?.value || '').toLowerCase();
  
  const fltHigh = document.getElementById('fltHigh')?.checked ?? true;
  const fltMed = document.getElementById('fltMed')?.checked ?? true;
  const fltLow = document.getElementById('fltLow')?.checked ?? true;
  const fltInfo = document.getElementById('fltInfo')?.checked ?? false;  // Info off by default

  const filtered = cache.all.filter(f => {
    const sevOk = (f.severity === 'high' && fltHigh) ||
                  (f.severity === 'medium' && fltMed) ||
                  (f.severity === 'low' && fltLow) ||
                  (f.severity === 'info' && fltInfo);
    const catOk = activeCat === 'all' || categoryFor(f.id).cls === activeCat;
    const searchOk = !query || 
      f.title.toLowerCase().includes(query) ||
      (f.desc || '').toLowerCase().includes(query);
    return sevOk && catOk && searchOk;
  });

  container.innerHTML = '';

  if (!filtered.length) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <p>No findings match your filters</p>
      </div>
    `;
    return;
  }

  filtered.forEach(f => container.appendChild(createFindingCard(f)));
}

function createFindingCard(f) {
  const card = document.createElement('div');
  card.className = 'finding-card';
  const cat = categoryFor(f.id);
  
  // Generate unique ID for copy functionality
  const evidenceId = `evidence-${Math.random().toString(36).substr(2, 9)}`;
  
  card.innerHTML = `
    <div class="finding-sev ${f.severity}">${f.severity}</div>
    <div class="finding-content">
      <h4>${escapeHtml(f.title)}</h4>
      <span class="finding-cat">${cat.label}</span>
      ${f.attack ? `<div class="finding-impact ${f.severity}"><strong>⚠ Impact:</strong> ${escapeHtml(f.attack)}</div>` : ''}
      ${f.evidence ? `
        <div class="finding-evidence">
          <div class="evidence-header">
            <strong>🔑 Evidence:</strong>
            <button class="copy-evidence-btn" data-evidence-id="${evidenceId}" title="Copy to clipboard">📋 Copy</button>
          </div>
          <code id="${evidenceId}" class="evidence-code">${escapeHtml(f.evidence)}</code>
        </div>
      ` : ''}
      ${f.data ? `<div class="finding-data"><strong>📍 Location:</strong> <code>${escapeHtml(f.data)}</code></div>` : ''}
      ${f.desc ? `<div class="finding-fix"><strong>🛠 Fix:</strong> ${escapeHtml(f.desc)}</div>` : ''}
    </div>
  `;
  
  // Add copy event listener
  const copyBtn = card.querySelector('.copy-evidence-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const evidenceCode = card.querySelector(`#${evidenceId}`);
      if (evidenceCode) {
        navigator.clipboard.writeText(evidenceCode.textContent).then(() => {
          copyBtn.textContent = '✅ Copied!';
          setTimeout(() => { copyBtn.textContent = '📋 Copy'; }, 2000);
        });
      }
    });
  }
  
  return card;
}

function categoryFor(id) {
  if (!id) return { label: 'General', cls: 'gen' };
  if (id.startsWith('apikey.')) return { label: 'API Keys', cls: 'apikey' };
  if (id.startsWith('vuln.')) return { label: 'Libraries', cls: 'vuln' };
  if (id.startsWith('sourcemap.')) return { label: 'Source Maps', cls: 'sourcemap' };
  if (id.startsWith('info.')) return { label: 'Info Leak', cls: 'info' };
  if (id.startsWith('form.')) return { label: 'Forms', cls: 'form' };
  if (id.startsWith('comment.')) return { label: 'Comments', cls: 'comment' };
  if (id.startsWith('hidden.')) return { label: 'Hidden Fields', cls: 'hidden' };
  if (id.startsWith('mixed.')) return { label: 'Mixed Content', cls: 'mixed' };
  if (id.startsWith('path.')) return { label: 'Paths', cls: 'path' };
  if (id.startsWith('dom.')) return { label: 'DOM', cls: 'dom' };
  if (id.startsWith('hdr.')) return { label: 'Headers', cls: 'hdr' };
  if (id.startsWith('cookie.')) return { label: 'Cookies', cls: 'cookie' };
  if (id.startsWith('storage.')) return { label: 'Storage', cls: 'storage' };
  if (id.startsWith('net.')) return { label: 'Network', cls: 'net' };
  return { label: 'General', cls: 'gen' };
}

function renderRecon() {
  const robotsEl = document.getElementById('robotsContent');
  const sitemapEl = document.getElementById('sitemapContent');
  
  if (robotsEl) {
    if (cache.recon.robots) {
      robotsEl.textContent = cache.recon.robots;
      robotsEl.classList.add('has-content');
    } else {
      robotsEl.innerHTML = '<span class="no-content">⚠️ robots.txt not found or inaccessible</span>';
    }
  }
  
  if (sitemapEl) {
    if (cache.recon.sitemap) {
      sitemapEl.textContent = cache.recon.sitemap;
      sitemapEl.classList.add('has-content');
    } else {
      sitemapEl.innerHTML = '<span class="no-content">⚠️ sitemap.xml not found or inaccessible</span>';
    }
  }
}

function hookEvents() {
  // Search
  document.getElementById('searchInput')?.addEventListener('input', () => renderFindings());

  // Severity filters
  ['fltHigh', 'fltMed', 'fltLow', 'fltInfo'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', () => renderFindings());
  });

  // Refresh button
  document.getElementById('refreshBtn')?.addEventListener('click', () => location.reload());

  // Quick Actions
  document.getElementById('copyReport')?.addEventListener('click', () => {
    const report = generateMarkdown();
    navigator.clipboard.writeText(report).then(() => showToast('Report copied!'));
  });

  document.getElementById('scanAgain')?.addEventListener('click', () => location.reload());

  document.getElementById('viewAll')?.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-view="findings"]')?.classList.add('active');
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById('findings')?.classList.add('active');
  });

  document.getElementById('clearData')?.addEventListener('click', async () => {
    if (confirm('Clear all findings for this site?')) {
      await chrome.runtime.sendMessage({ type: 'CLEAR_FINDINGS', origin: cache.origin });
      location.reload();
    }
  });

  // Export buttons
  document.getElementById('exportJson')?.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({
      origin: cache.origin,
      findings: cache.all,
      recon: cache.recon,
      timestamp: new Date().toISOString()
    }, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `security-report-${getHostname()}.json`);
  });

  document.getElementById('exportMd')?.addEventListener('click', () => {
    const md = generateMarkdown();
    const blob = new Blob([md], { type: 'text/markdown' });
    downloadBlob(blob, `security-report-${getHostname()}.md`);
  });

  document.getElementById('exportPdf')?.addEventListener('click', () => {
    const win = window.open('', '_blank');
    const counts = { high: 0, medium: 0, low: 0 };
    cache.all.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
    
    const html = `<!DOCTYPE html>
<html><head><title>Security Audit Report - ${getHostname()}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }
.container { max-width: 900px; margin: 0 auto; padding: 40px 30px; }

/* Header */
.header { background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 40px; border-radius: 16px; margin-bottom: 30px; }
.header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; display: flex; align-items: center; gap: 12px; }
.header .subtitle { opacity: 0.8; font-size: 14px; }
.meta { display: flex; gap: 30px; margin-top: 20px; flex-wrap: wrap; }
.meta-item { font-size: 13px; }
.meta-item strong { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; margin-bottom: 2px; }

/* Summary Cards */
.summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 30px; }
.summary-card { background: white; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.summary-card.high { border-top: 4px solid #ef4444; }
.summary-card.medium { border-top: 4px solid #f59e0b; }
.summary-card.low { border-top: 4px solid #10b981; }
.summary-card .count { font-size: 36px; font-weight: 700; }
.summary-card.high .count { color: #ef4444; }
.summary-card.medium .count { color: #f59e0b; }
.summary-card.low .count { color: #10b981; }
.summary-card .label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; margin-top: 4px; }

/* Section */
.section { background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.section-title { font-size: 18px; font-weight: 600; color: #1e293b; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid #e2e8f0; }

/* Finding Card */
.finding { background: #f8fafc; border-radius: 10px; padding: 20px; margin-bottom: 16px; border: 1px solid #e2e8f0; page-break-inside: avoid; }
.finding:last-child { margin-bottom: 0; }
.finding-header { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 14px; }
.severity-badge { padding: 6px 12px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; flex-shrink: 0; }
.severity-badge.high { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.severity-badge.medium { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
.severity-badge.low { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
.finding-title { font-size: 16px; font-weight: 600; color: #1e293b; }
.finding-cat { font-size: 11px; color: #64748b; background: #e2e8f0; padding: 2px 8px; border-radius: 4px; margin-left: 8px; }

/* Impact & Fix boxes */
.info-box { padding: 14px 16px; border-radius: 8px; margin-top: 12px; font-size: 13px; }
.impact-box { background: #fef2f2; border-left: 4px solid #ef4444; }
.impact-box .label { color: #dc2626; font-weight: 600; display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
.fix-box { background: #f0fdf4; border-left: 4px solid #10b981; }
.fix-box .label { color: #16a34a; font-weight: 600; display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
.info-box p { color: #475569; }

/* Footer */
.footer { text-align: center; padding: 20px; color: #94a3b8; font-size: 12px; }

@media print {
  body { background: white; }
  .container { padding: 20px; }
  .finding { break-inside: avoid; }
}
</style></head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ Security Audit Report</h1>
    <p class="subtitle">Automated vulnerability assessment and security analysis</p>
    <div class="meta">
      <div class="meta-item"><strong>Target</strong>${escapeHtml(cache.origin)}</div>
      <div class="meta-item"><strong>Date</strong>${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</div>
      <div class="meta-item"><strong>Time</strong>${new Date().toLocaleTimeString()}</div>
      <div class="meta-item"><strong>Total Issues</strong>${cache.all.length} findings</div>
    </div>
  </div>

  <div class="summary">
    <div class="summary-card high"><div class="count">${counts.high}</div><div class="label">High Severity</div></div>
    <div class="summary-card medium"><div class="count">${counts.medium}</div><div class="label">Medium Severity</div></div>
    <div class="summary-card low"><div class="count">${counts.low}</div><div class="label">Low Severity</div></div>
  </div>

  <div class="section">
    <h2 class="section-title">📋 Detailed Findings</h2>
    ${cache.all.map((f, i) => {
      const cat = categoryFor(f.id);
      return `
    <div class="finding">
      <div class="finding-header">
        <span class="severity-badge ${f.severity}">${f.severity}</span>
        <div>
          <span class="finding-title">${escapeHtml(f.title)}</span>
          <span class="finding-cat">${cat.label}</span>
        </div>
      </div>
      ${f.attack ? `
      <div class="info-box impact-box">
        <div class="label">⚠️ Potential Impact</div>
        <p>${escapeHtml(f.attack)}</p>
      </div>` : ''}
      ${f.desc ? `
      <div class="info-box fix-box">
        <div class="label">🛠️ Recommendation</div>
        <p>${escapeHtml(f.desc)}</p>
      </div>` : ''}
    </div>`;
    }).join('')}
  </div>

  <div class="footer">
    <p>Generated by Security Auditer Extension • ${new Date().toISOString()}</p>
  </div>
</div>
</body></html>`;
    win.document.write(html);
    win.document.close();
    setTimeout(() => win.print(), 300);
  });
}

function generateMarkdown() {
  let md = `# Security Audit Report\n\n`;
  md += `**Origin:** ${cache.origin}\n`;
  md += `**Date:** ${new Date().toLocaleString()}\n`;
  md += `**Total Findings:** ${cache.all.length}\n\n`;
  md += `---\n\n## Findings\n\n`;

  const byCat = {
    Headers: cache.all.filter(f => f.id.startsWith('hdr.')),
    Cookies: cache.all.filter(f => f.id.startsWith('cookie.')),
    DOM: cache.all.filter(f => f.id.startsWith('dom.')),
    Storage: cache.all.filter(f => f.id.startsWith('storage.')),
    Network: cache.all.filter(f => f.id.startsWith('net.'))
  };

  for (const [cat, arr] of Object.entries(byCat)) {
    if (!arr.length) continue;
    md += `### ${cat}\n\n`;
    for (const f of arr) {
      md += `- **${f.title}** (${f.severity.toUpperCase()})\n`;
      md += `  - ${f.desc || 'No description'}\n`;
      if (f.attack) md += `  - Impact: ${f.attack}\n`;
    }
    md += `\n`;
  }

  return md;
}

function showEmptyState(message) {
  const dashboard = document.getElementById('dashboard');
  if (dashboard) {
    dashboard.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <p>${message}</p>
      </div>
    `;
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function getHostname() {
  try {
    return new URL(cache.origin).hostname;
  } catch {
    return 'unknown';
  }
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

async function getResponseHeaders(url) {
  try {
    const res = await fetch(url, { method: 'HEAD', cache: 'no-cache' });
    const headers = [];
    res.headers.forEach((v, k) => headers.push({ name: k, value: v }));
    return headers;
  } catch {
    return [];
  }
}

function showToast(message) {
  const toast = document.createElement('div');
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: #6366f1;
    color: #fff;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    z-index: 1000;
  `;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2000);
}

// Service worker orchestrates findings, recon tasks, and storage

const findingsByOrigin = new Map();

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeBackgroundColor({ color: '#D32F2F' });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) return;
  if (msg.type === 'FINDINGS') {
    const origin = msg.origin;
    const findings = (msg.findings || []).map(f => ({ ...f, ts: Date.now() }));
    const existing = findingsByOrigin.get(origin)?.findings || [];
    const merged = dedupe(existing.concat(findings));
    const score = scoreFindings(merged);
    const payload = { findings: merged, score, ts: Date.now(), recon: findingsByOrigin.get(origin)?.recon };
    findingsByOrigin.set(origin, payload);
    updateBadge(sender.tab?.id, score);
    // persist
    chrome.storage.local.set({ [`findings:${origin}`]: payload });
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === 'GET_FINDINGS') {
    const data = findingsByOrigin.get(msg.origin) || { findings: [], score: 0, recon: null };
    sendResponse(data);
    return true;
  }
  if (msg.type === 'RECON_REQUEST') {
    runRecon(msg.origin).then(result => {
      const existing = findingsByOrigin.get(msg.origin) || { findings: [], score: 0 };
      const payload = { ...existing, recon: result };
      findingsByOrigin.set(msg.origin, payload);
      chrome.storage.local.set({ [`findings:${msg.origin}`]: payload });
      sendResponse(result);
    });
    return true;
  }
  if (msg.type === 'CLEAR_FINDINGS') {
    findingsByOrigin.delete(msg.origin);
    chrome.storage.local.remove([`findings:${msg.origin}`]);
    sendResponse({ ok: true });
    return true;
  }
});

async function runRecon(origin) {
  try {
    const robots = await fetchTextSafe(new URL('/robots.txt', origin).toString());
    const sitemap = await fetchTextSafe(new URL('/sitemap.xml', origin).toString());
    return { robots, sitemap, ts: Date.now() };
  } catch (e) {
    return { error: String(e), ts: Date.now() };
  }
}

async function fetchTextSafe(url) {
  try {
    const res = await fetch(url, { method: 'GET' });
    if (!res.ok) throw new Error(res.statusText);
    return await res.text();
  } catch (e) {
    return null;
  }
}

function updateBadge(tabId, score) {
  if (!tabId) return;
  const text = score > 0 ? String(Math.min(score, 99)) : '';
  const color = score >= 7 ? '#D32F2F' : score >= 4 ? '#F57C00' : '#388E3C';
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function scoreFindings(findings) {
  let s = 0;
  for (const f of findings) {
    if (f.severity === 'high') s += 4;
    else if (f.severity === 'medium') s += 2;
    else if (f.severity === 'low') s += 1;
  }
  return s;
}

function dedupe(arr) {
  const seen = new Set();
  const out = [];
  for (const f of arr) {
    const key = `${f.id}:${f.title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

// Shared analyzers for popup/background use

// SEVERITY GUIDE (TRUE IMPACT ONLY):
// high = Directly exploitable, immediate risk (real secrets, active vulnerabilities)
// medium = Requires another bug to exploit OR provides significant recon value
// info = Best practice, hardening recommendation, NOT exploitable alone

export function analyzeHeaders(headers) {
  const findings = [];
  const h = (name) => headers.find(x => x.name.toLowerCase() === name);
  const csp = h('content-security-policy');
  const hsts = h('strict-transport-security');
  const xfo = h('x-frame-options');
  const xcto = h('x-content-type-options');

  // CSP - Informational only (not exploitable without XSS)
  if (!csp) findings.push(mark('hdr.csp.missing', 'CSP Header Not Set', 'info', 'Consider adding Content-Security-Policy header.', 'CSP provides defense-in-depth against XSS. Not a vulnerability by itself.'));
  else {
    const v = csp.value || '';
    if (/unsafe-inline/.test(v) && /unsafe-eval/.test(v)) {
      findings.push(mark('hdr.csp.weak', 'CSP Has Weak Configuration', 'info', 'CSP allows unsafe-inline and unsafe-eval.', 'Weak CSP may not block XSS if one is found. Informational only.'));
    }
  }

  // HSTS - Informational (SSL stripping requires specific attack position)
  if (!hsts) findings.push(mark('hdr.hsts.missing', 'HSTS Header Not Set', 'info', 'Consider adding Strict-Transport-Security header.', 'HSTS prevents SSL stripping. Informational - requires MITM position.'));
  
  // X-Frame-Options - Informational (clickjacking requires social engineering)
  if (!xfo && (!csp || !csp.value?.includes('frame-ancestors'))) {
    findings.push(mark('hdr.xfo.missing', 'Clickjacking Protection Missing', 'info', 'Add X-Frame-Options or CSP frame-ancestors.', 'Page can be framed. Informational unless sensitive actions exist.'));
  }
  
  // X-Content-Type-Options - Informational
  if (!xcto) findings.push(mark('hdr.xcto.missing', 'X-Content-Type-Options Not Set', 'info', 'Add X-Content-Type-Options: nosniff.', 'Prevents MIME sniffing. Informational.'));

  // REMOVED: COOP, COEP, Referrer-Policy - too noisy, rarely matter for bug bounty

  return findings;
}

export function analyzeCookies(cookies) {
  const findings = [];
  
  // Only report session-looking cookies, and only as informational
  const sessionCookieNames = ['session', 'sess', 'token', 'auth', 'jwt', 'sid', 'phpsessid', 'jsessionid', 'asp.net_sessionid'];
  
  for (const c of cookies) {
    const nameLC = c.name.toLowerCase();
    const isSessionCookie = sessionCookieNames.some(s => nameLC.includes(s));
    
    if (isSessionCookie) {
      if (!c.httpOnly) {
        findings.push(mark(`cookie.${c.name}.httponly`, `Session Cookie "${c.name}" Not HttpOnly`, 'info', 'Set HttpOnly flag on session cookies.', 'Cookie readable by JavaScript. Requires XSS to exploit.'));
      }
      if (!c.secure && location.protocol === 'https:') {
        findings.push(mark(`cookie.${c.name}.secure`, `Session Cookie "${c.name}" Not Secure`, 'info', 'Set Secure flag on session cookies.', 'Cookie may be sent over HTTP. Requires MITM to exploit.'));
      }
    }
    // REMOVED: SameSite warnings - too noisy
  }
  return findings;
}

// CSP simulation removed - it only generates informational noise
export function simulateCSP(headers) {
  // Return safe result - don't add CSP findings as they're not exploitable
  return { risky: false, reasons: [] };
}

export function computeConfidence(findings) {
  // Security Health = 100% minus risk impact
  // Fewer/less severe findings = higher health
  // More/severe findings = lower health
  
  if (findings.length === 0) return 100; // No issues = perfect health
  
  let penalty = 0;
  
  for (const f of findings) {
    if (f.severity === 'high') penalty += 12;
    else if (f.severity === 'medium') penalty += 6;
    else penalty += 2;
  }
  
  // Health = 100 - penalty (min 0)
  const health = Math.max(0, 100 - penalty);
  return health;
}

function mark(id, title, severity, desc, attack) {
  return { id, title, severity, desc, attack };
}

// Content script: Comprehensive security analysis - TRUE POSITIVES ONLY

(function () {
  const origin = location.origin;
  const findings = [];

  // Run all analyzers
  const results = {
    apiKeys: scanForAPIKeys(),
    sourceMaps: detectSourceMaps(),
    vulnerableLibs: detectVulnerableLibraries(),
    serverInfo: extractServerInfo(),
    formSecurity: analyzeFormSecurity(),
    htmlComments: scanHTMLComments(),
    hiddenFields: analyzeHiddenFields(),
    mixedContent: detectMixedContent(),
    sensitivePaths: discoverSensitivePaths(),
    domSecurity: analyzeDOMSecurity(),
    storageInfo: analyzeStorage(),
    techStack: detectTechnologies()
  };

  // Collect all findings
  Object.values(results).forEach(r => {
    if (r && r.findings) findings.push(...r.findings);
  });

  // Send findings to background
  chrome.runtime.sendMessage({ 
    type: 'FINDINGS', 
    origin, 
    findings,
    metadata: {
      url: location.href,
      title: document.title,
      tech: results.techStack?.detected || []
    }
  });

  // Request recon
  chrome.runtime.sendMessage({ type: 'RECON_REQUEST', origin });

  // Setup network monitoring
  setupNetworkMonitor(origin);

  // ============ API KEY DETECTION - TRUE POSITIVES ONLY ============
  function scanForAPIKeys() {
    const findings = [];
    const pageContent = document.documentElement.innerHTML;
    
    // ONLY detect keys that are ALWAYS security issues when exposed
    // NO public keys, NO site keys, NO test keys
    const secretKeyPatterns = [
      // AWS Secret Access Key (the SECRET one, not Access Key ID which can be semi-public)
      { 
        name: 'AWS Secret Access Key', 
        pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretaccesskey)["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi, 
        severity: 'high',
        extract: 1  // capture group
      },
      
      // Stripe SECRET Key (sk_live_ only - sk_test_ is not sensitive)
      { 
        name: 'Stripe Secret Key (Live)', 
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g, 
        severity: 'high' 
      },
      
      // GitHub Personal Access Token (always secret)
      { 
        name: 'GitHub Personal Access Token', 
        pattern: /ghp_[0-9a-zA-Z]{36}/g, 
        severity: 'high' 
      },
      
      // GitHub OAuth Access Token
      { 
        name: 'GitHub OAuth Token', 
        pattern: /gho_[0-9a-zA-Z]{36}/g, 
        severity: 'high' 
      },
      
      // GitHub App Token
      { 
        name: 'GitHub App Token', 
        pattern: /ghu_[0-9a-zA-Z]{36}/g, 
        severity: 'high' 
      },
      
      // GitHub Refresh Token
      { 
        name: 'GitHub Refresh Token', 
        pattern: /ghr_[0-9a-zA-Z]{36}/g, 
        severity: 'high' 
      },
      
      // Slack Bot/User Token (always secret)
      { 
        name: 'Slack Token', 
        pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, 
        severity: 'high' 
      },
      
      // Slack Webhook URL (always secret)
      { 
        name: 'Slack Webhook', 
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{20,}/g, 
        severity: 'high' 
      },
      
      // SendGrid API Key (always secret)
      { 
        name: 'SendGrid API Key', 
        pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, 
        severity: 'high' 
      },
      
      // Twilio Auth Token (not API Key SID which is less sensitive)
      { 
        name: 'Twilio Auth Token', 
        pattern: /(?:twilio_auth_token|auth_token)["'\s:=]+["']?([a-f0-9]{32})["']?/gi, 
        severity: 'high',
        extract: 1
      },
      
      // Mailchimp API Key
      { 
        name: 'Mailchimp API Key', 
        pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g, 
        severity: 'high' 
      },
      
      // Private Keys (ALWAYS critical)
      { 
        name: 'RSA Private Key', 
        pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g, 
        severity: 'high' 
      },
      { 
        name: 'Private Key', 
        pattern: /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, 
        severity: 'high' 
      },
      { 
        name: 'EC Private Key', 
        pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/g, 
        severity: 'high' 
      },
      { 
        name: 'PGP Private Key', 
        pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g, 
        severity: 'high' 
      },
      
      // NPM Token
      { 
        name: 'NPM Access Token', 
        pattern: /npm_[a-zA-Z0-9]{36}/g, 
        severity: 'high' 
      },
      
      // Heroku API Key
      { 
        name: 'Heroku API Key', 
        pattern: /(?:heroku_api_key|HEROKU_API_KEY)["'\s:=]+["']?([a-f0-9-]{36})["']?/gi, 
        severity: 'high',
        extract: 1
      },
      
      // Discord Bot Token
      { 
        name: 'Discord Bot Token', 
        pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g, 
        severity: 'high' 
      },
      
      // Discord Webhook
      { 
        name: 'Discord Webhook', 
        pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g, 
        severity: 'high' 
      },
      
      // Telegram Bot Token
      { 
        name: 'Telegram Bot Token', 
        pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g, 
        severity: 'high' 
      },
      
      // Facebook Access Token
      { 
        name: 'Facebook Access Token', 
        pattern: /EAACEdEose0cBA[0-9A-Za-z]+/g, 
        severity: 'high' 
      },
      
      // Twitter Bearer Token
      { 
        name: 'Twitter Bearer Token', 
        pattern: /AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+/g, 
        severity: 'high' 
      },
      
      // Shopify Access Token
      { 
        name: 'Shopify Access Token', 
        pattern: /shpat_[a-fA-F0-9]{32}/g, 
        severity: 'high' 
      },
      
      // Shopify Shared Secret
      { 
        name: 'Shopify Shared Secret', 
        pattern: /shpss_[a-fA-F0-9]{32}/g, 
        severity: 'high' 
      },
      
      // PyPI API Token
      { 
        name: 'PyPI API Token', 
        pattern: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g, 
        severity: 'high' 
      },
    ];

    // Known false positives to ignore
    const falsePositives = [
      // AWS example keys from documentation
      'AKIAIOSFODNN7EXAMPLE',
      'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      // Common test/example patterns
      'sk_test_', 'pk_test_', 'pk_live_',  // Stripe public/test keys
      'xxx', 'XXX', 'your_', 'YOUR_', '<your', 'example', 'EXAMPLE',
      'test_', 'TEST_', 'demo_', 'DEMO_', 'sample', 'SAMPLE',
      'insert_', 'INSERT_', 'placeholder', 'PLACEHOLDER',
    ];

    const foundKeys = new Set();
    
    for (const { name, pattern, severity, extract } of secretKeyPatterns) {
      let matches;
      const regex = new RegExp(pattern.source, pattern.flags);
      
      while ((matches = regex.exec(pageContent)) !== null) {
        const fullMatch = matches[0];
        const keyValue = extract ? matches[extract] : fullMatch;
        
        // Skip if already found
        if (foundKeys.has(keyValue)) continue;
        
        // Skip false positives
        const isFalsePositive = falsePositives.some(fp => 
          keyValue.toLowerCase().includes(fp.toLowerCase()) ||
          fullMatch.toLowerCase().includes(fp.toLowerCase())
        );
        if (isFalsePositive) continue;
        
        // Skip if it looks like a placeholder (all same char, too short, etc.)
        if (/^(.)\1+$/.test(keyValue)) continue;  // All same character
        if (keyValue.length < 10 && !name.includes('Private')) continue;  // Too short
        
        foundKeys.add(keyValue);
        findings.push({
          id: 'apikey.' + name.toLowerCase().replace(/\s+/g, ''),
          title: `🔴 ${name} Exposed`,
          severity,
          desc: `Remove this secret immediately and rotate the key.`,
          attack: `This is a SECRET key that should never be in frontend code. Can lead to unauthorized access, data breach, or financial loss.`,
          evidence: keyValue
        });
      }
    }

    return { findings };
  }

  // ============ SOURCE MAP DETECTION ============
  function detectSourceMaps() {
    const findings = [];
    const scripts = Array.from(document.scripts);
    const foundMaps = new Set();
    
    // Only report if we actually find sourceMappingURL reference
    scripts.forEach(script => {
      if (script.textContent?.includes('sourceMappingURL')) {
        if (!foundMaps.has('inline')) {
          foundMaps.add('inline');
          findings.push({
            id: 'sourcemap.inline',
            title: 'Source Map Reference Found',
            severity: 'info',
            desc: 'Source maps expose original code. Consider removing in production.',
            attack: 'Aids reverse engineering. Informational - not directly exploitable.'
          });
        }
      }
    });

    return { findings };
  }

  // ============ VULNERABLE JS LIBRARIES ============
  function detectVulnerableLibraries() {
    const findings = [];
    
    const vulnerableLibs = {
      jquery: {
        check: () => window.jQuery?.fn?.jquery || window.$?.fn?.jquery,
        vulnerabilities: [
          { below: '3.5.0', cve: 'CVE-2020-11022', desc: 'XSS via HTML passed to DOM methods' },
          { below: '3.4.0', cve: 'CVE-2019-11358', desc: 'Prototype pollution' },
          { below: '3.0.0', cve: 'CVE-2015-9251', desc: 'XSS in ajax cross-domain requests' },
        ]
      },
      angularjs: {
        check: () => window.angular?.version?.full,
        vulnerabilities: [
          { below: '1.8.0', cve: 'Multiple', desc: 'Template injection and sandbox escapes' },
        ]
      },
      lodash: {
        check: () => window._?.VERSION,
        vulnerabilities: [
          { below: '4.17.21', cve: 'CVE-2021-23337', desc: 'Command injection via template' },
          { below: '4.17.12', cve: 'CVE-2019-10744', desc: 'Prototype pollution' }
        ]
      },
      moment: {
        check: () => window.moment?.version,
        vulnerabilities: [
          { below: '2.29.4', cve: 'CVE-2022-31129', desc: 'ReDoS via malicious string' }
        ]
      }
    };

    for (const [lib, config] of Object.entries(vulnerableLibs)) {
      try {
        const version = config.check();
        if (version) {
          for (const vuln of config.vulnerabilities) {
            if (compareVersions(version, vuln.below) < 0) {
              findings.push({
                id: `vuln.${lib}`,
                title: `🔴 Vulnerable ${lib.charAt(0).toUpperCase() + lib.slice(1)} (${version})`,
                severity: 'high',  // HIGH because real CVE with known exploits
                desc: `Update ${lib} to latest version. Current: ${version}`,
                attack: `${vuln.cve}: ${vuln.desc}. Known exploits may exist.`,
                data: `${lib}@${version}`
              });
              break;
            }
          }
        }
      } catch (e) {}
    }

    return { findings };
  }

  function compareVersions(v1, v2) {
    const parts1 = String(v1).replace(/[^0-9.]/g, '').split('.').map(Number);
    const parts2 = String(v2).replace(/[^0-9.]/g, '').split('.').map(Number);
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;
      if (p1 < p2) return -1;
      if (p1 > p2) return 1;
    }
    return 0;
  }

  // ============ SERVER INFO EXTRACTION ============
  function extractServerInfo() {
    const findings = [];
    
    // Check meta tags for version info
    const generators = document.querySelectorAll('meta[name="generator"]');
    generators.forEach(meta => {
      const content = meta.content;
      if (content) {
        findings.push({
          id: 'info.generator',
          title: 'Technology Version Disclosed',
          severity: 'info',  // Informational - aids recon but not exploitable
          desc: 'Generator meta tag reveals technology stack.',
          attack: `Disclosed: "${content}". Informational only.`,
          data: content
        });
      }
    });

    // Check for error messages - only report really significant ones
    const pageText = document.body?.innerText || '';
    const errorPatterns = [
      // SQL errors are HIGH - may indicate SQL injection
      { pattern: /SQL syntax.*?MySQL/i, name: 'MySQL Error', sev: 'high' },
      { pattern: /PostgreSQL.*?ERROR/i, name: 'PostgreSQL Error', sev: 'high' },
      { pattern: /ORA-\d{5}/i, name: 'Oracle Error', sev: 'high' },
      // Stack traces are MEDIUM - reveal internal paths
      { pattern: /Fatal error.*?on line \d+/i, name: 'PHP Fatal Error', sev: 'medium' },
      { pattern: /Traceback \(most recent call last\)/i, name: 'Python Traceback', sev: 'medium' },
      { pattern: /at .+\.java:\d+/i, name: 'Java Stack Trace', sev: 'medium' },
    ];

    for (const { pattern, name, sev } of errorPatterns) {
      if (pattern.test(pageText)) {
        findings.push({
          id: 'info.error.' + name.toLowerCase().replace(/\s+/g, ''),
          title: `${name} Exposed`,
          severity: sev,
          desc: 'Disable debug mode and implement custom error pages.',
          attack: 'Error messages reveal internal paths, database structure, and technology stack.'
        });
      }
    }

    return { findings };
  }

  // ============ FORM SECURITY ANALYSIS ============
  function analyzeFormSecurity() {
    const findings = [];
    const forms = Array.from(document.forms);
    const foundIssues = new Set();

    forms.forEach((form, idx) => {
      const action = form.action || location.href;
      const method = (form.method || 'get').toUpperCase();
      
      // HTTP form on HTTPS page
      if (location.protocol === 'https:' && action.startsWith('http://')) {
        const key = 'http-form-' + action;
        if (!foundIssues.has(key)) {
          foundIssues.add(key);
          findings.push({
            id: `form.http`,
            title: 'Form Submits Over HTTP',
            severity: 'high',
            desc: 'Change form action to HTTPS.',
            attack: 'Form data can be intercepted via MITM attack.',
            data: action.substring(0, 60)
          });
        }
      }

      // CSRF check for POST forms - informational only (hard to prove exploitable)
      if (method === 'POST') {
        const hasCSRF = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
        if (!hasCSRF && !foundIssues.has('csrf-' + idx)) {
          foundIssues.add('csrf-' + idx);
          findings.push({
            id: `form.csrf`,
            title: 'POST Form Without Visible CSRF Token',
            severity: 'info',  // Informational - may have other CSRF protection
            desc: 'Form may lack CSRF protection. Verify manually.',
            attack: 'Potential CSRF. Requires manual verification.',
            data: action.substring(0, 60)
          });
        }
      }

      // Password autocomplete - REMOVED, too noisy and not a real issue
    });

    return { findings };
  }

  // ============ HTML COMMENT SCANNER ============
  function scanHTMLComments() {
    const findings = [];
    const comments = [];
    const foundTypes = new Set();
    
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    while (walker.nextNode()) {
      comments.push(walker.currentNode.textContent);
    }

    // Only report HIGH-VALUE comments (actual credentials, not just TODO/FIXME)
    const sensitivePatterns = [
      { pattern: /password\s*[:=]\s*['"][^'"]+['"]/i, type: 'Hardcoded Password', sev: 'high' },
      { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i, type: 'API Key in Comment', sev: 'high' },
      { pattern: /secret\s*[:=]\s*['"][^'"]+['"]/i, type: 'Secret in Comment', sev: 'high' },
      { pattern: /credential\s*[:=]/i, type: 'Credential Reference', sev: 'medium' },
    ];
    // REMOVED: TODO, FIXME, admin paths, debug - too noisy, not valuable

    comments.forEach(comment => {
      for (const { pattern, type, sev } of sensitivePatterns) {
        if (pattern.test(comment) && !foundTypes.has(type)) {
          foundTypes.add(type);
          // Only show evidence for high-value comments (passwords, credentials, secrets)
          const needsEvidence = /password|passwd|pwd|secret|credential|api[_-]?key/i.test(comment);
          findings.push({
            id: 'comment.' + type.toLowerCase().replace(/\s+/g, ''),
            title: `Sensitive Comment: ${type}`,
            severity: sev,
            desc: 'Remove development comments before deployment.',
            attack: 'Comments may reveal internal information.',
            ...(needsEvidence && { evidence: `<!-- ${comment.trim().substring(0, 200)} -->` })
          });
          break;
        }
      }
    });

    return { findings };
  }

  // ============ HIDDEN FIELD ANALYSIS ============
  function analyzeHiddenFields() {
    const findings = [];
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const foundFields = new Set();

    hiddenInputs.forEach(input => {
      const name = (input.name || '').toLowerCase();
      const value = input.value || '';

      // Only report JWT tokens - they're the only truly sensitive hidden field finding
      if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value) && !foundFields.has('jwt')) {
        foundFields.add('jwt');
        findings.push({
          id: 'hidden.jwt',
          title: '🔴 JWT Token in Hidden Field',
          severity: 'high',  // HIGH - actual token that can be stolen
          desc: 'JWT in hidden field can be stolen via XSS. Use HttpOnly cookies.',
          attack: 'Token theft possible via XSS or DOM inspection.',
          evidence: value,
          data: input.name
        });
      }
      
      // REMOVED: Generic "sensitive" hidden fields - too many false positives
      // Things like user_id, role, etc. are often fine to have in hidden fields
    });

    return { findings };
  }

  // ============ MIXED CONTENT DETECTION ============
  function detectMixedContent() {
    const findings = [];
    if (location.protocol !== 'https:') return { findings };
    
    const foundUrls = new Set();

    // Only report HTTP scripts - they're the real risk (code execution)
    document.querySelectorAll('script[src^="http://"]').forEach(el => {
      if (!foundUrls.has(el.src)) {
        foundUrls.add(el.src);
        findings.push({
          id: 'mixed.script',
          title: '🔴 HTTP Script on HTTPS Page',
          severity: 'high',  // HIGH - MITM can inject malicious JS
          desc: 'Script loaded over HTTP can be modified by attacker.',
          attack: 'MITM can inject malicious JavaScript.',
          data: el.src
        });
      }
    });

    // REMOVED: HTTP CSS and iframes - less impactful, too noisy

    return { findings };
  }

  // ============ SENSITIVE PATH DISCOVERY ============
  function discoverSensitivePaths() {
    const findings = [];
    const pageContent = document.documentElement.innerHTML;
    const foundPaths = new Set();

    // Only report ACTUALLY sensitive paths - not generic API endpoints
    const sensitivePaths = [
      // HIGH - Exposed database/backup files
      { pattern: /["']([^\/"']*?\.(?:sql|bak|backup|db|sqlite))\b/gi, type: 'Database/Backup File', sev: 'high' },
      // HIGH - phpMyAdmin exposure
      { pattern: /["'](\/phpmyadmin[^\/"']*?)["']/gi, type: 'phpMyAdmin', sev: 'high' },
      // MEDIUM - Debug endpoints that might leak info
      { pattern: /["'](\/debug[^\/"']*?)["']/gi, type: 'Debug Endpoint', sev: 'medium' },
    ];
    
    // REMOVED: /api/, /graphql, /admin, /swagger, /wp-admin - these are normal, not vulnerabilities

    for (const { pattern, type, sev } of sensitivePaths) {
      let match;
      while ((match = pattern.exec(pageContent)) !== null) {
        const path = match[1];
        if (!foundPaths.has(path) && path.length > 3 && path.length < 100) {
          foundPaths.add(path);
          findings.push({
            id: 'path.' + type.toLowerCase().replace(/\s+/g, ''),
            title: `🔴 ${type} Reference Found`,
            severity: sev,
            desc: 'Verify this file/path is not publicly accessible.',
            attack: `May expose sensitive data if accessible.`,
            data: path
          });
          if (findings.length >= 5) break;  // Limit findings
        }
      }
    }

    return { findings };
  }

  // ============ DOM SECURITY ============
  function analyzeDOMSecurity() {
    // REMOVED: document.write, inline handlers - not directly exploitable
    // These require finding an actual XSS vector first
    return { findings: [] };
  }

  // ============ STORAGE ANALYSIS ============
  function analyzeStorage() {
    const findings = [];
    const foundKeys = new Set();
    
    const checkStorage = (storage, type) => {
      try {
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          const value = storage.getItem(key) || '';
          
          // Only report JWT tokens - actual sensitive data
          if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value) && !foundKeys.has('jwt-' + type)) {
            foundKeys.add('jwt-' + type);
            findings.push({
              id: `storage.jwt`,
              title: `🔴 JWT Token in ${type}`,
              severity: 'high',  // HIGH - actual token theft possible via XSS
              desc: 'JWT in browser storage can be stolen via XSS. Use HttpOnly cookies.',
              attack: 'Token can be exfiltrated via JavaScript.',
              evidence: value,
              data: key
            });
          }
          
          // REMOVED: Generic "sensitive key names" - too many false positives
          // Many apps store non-sensitive data with names like "token" for UI state
        }
      } catch (e) {}
    };

    checkStorage(localStorage, 'localStorage');
    checkStorage(sessionStorage, 'sessionStorage');

    return { findings };
  }

  // ============ TECHNOLOGY DETECTION ============
  function detectTechnologies() {
    const detected = [];

    if (window.React || document.querySelector('[data-reactroot], [data-react-root]')) detected.push('React');
    if (window.angular || document.querySelector('[ng-version], [ng-app]')) detected.push('Angular');
    if (window.Vue || document.querySelector('[data-v-]')) detected.push('Vue.js');
    if (window.jQuery || window.$?.fn?.jquery) detected.push(`jQuery ${window.$?.fn?.jquery || ''}`);
    if (window._?.VERSION) detected.push(`Lodash ${window._.VERSION}`);
    if (document.querySelector('[data-bs-toggle], [data-toggle="modal"]')) detected.push('Bootstrap');
    if (document.querySelector('meta[name="generator"][content*="WordPress"]')) detected.push('WordPress');
    if (document.querySelector('meta[name="generator"][content*="Drupal"]')) detected.push('Drupal');
    if (window.__NEXT_DATA__) detected.push('Next.js');
    if (window.__NUXT__) detected.push('Nuxt.js');

    return { detected, findings: [] };
  }

  // ============ NETWORK MONITOR ============
  function setupNetworkMonitor(origin) {
    const reportedUrls = new Set();

    const origFetch = window.fetch;
    window.fetch = async function(resource, init) {
      const url = typeof resource === 'string' ? resource : resource?.url;
      try {
        const res = await origFetch.apply(this, arguments);
        checkNetworkIssues(url, res, origin, reportedUrls);
        return res;
      } catch (e) {
        throw e;
      }
    };

    const OrigXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new OrigXHR();
      let reqUrl = '';
      const origOpen = xhr.open;
      xhr.open = function(method, url) {
        reqUrl = url;
        return origOpen.apply(xhr, arguments);
      };
      xhr.addEventListener('load', () => checkXHR(reqUrl, xhr, origin, reportedUrls));
      return xhr;
    };
  }

  function checkNetworkIssues(url, res, origin, reported) {
    if (!url || reported.has(url)) return;
    const findings = [];
    
    if (location.protocol === 'https:' && url.startsWith('http://')) {
      reported.add(url);
      findings.push({
        id: 'net.cleartext',
        title: 'Cleartext HTTP Request',
        severity: 'high',
        desc: 'Use HTTPS for all requests.',
        attack: 'Data can be intercepted by MITM.',
        data: url.substring(0, 80)
      });
    }

    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');
    if (acao === '*' && acac === 'true') {
      findings.push({
        id: 'net.cors',
        title: 'Insecure CORS',
        severity: 'medium',
        desc: 'Do not use wildcard origin with credentials.',
        attack: 'Any origin can make authenticated requests.',
        data: url.substring(0, 80)
      });
    }

    if (findings.length) chrome.runtime.sendMessage({ type: 'FINDINGS', origin, findings });
  }

  function checkXHR(url, xhr, origin, reported) {
    if (!url || reported.has(url)) return;
    const findings = [];

    if (location.protocol === 'https:' && url.startsWith('http://')) {
      reported.add(url);
      findings.push({
        id: 'net.cleartext.xhr',
        title: 'Cleartext XHR Request',
        severity: 'high',
        desc: 'Use HTTPS for all requests.',
        attack: 'XHR data can be intercepted.',
        data: url.substring(0, 80)
      });
    }

    if (findings.length) chrome.runtime.sendMessage({ type: 'FINDINGS', origin, findings });
  }

})();

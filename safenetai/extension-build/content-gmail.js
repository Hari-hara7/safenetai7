// PhishGuard Gmail Content Script v3.0
// Detects phishing emails directly in Gmail — only when an email is open
// Specialized for Indian university internship scams

const SUSPICIOUS_KEYWORDS = [
  // Payment related
  'pay', 'payment', 'fee', 'processing fee', '₹', 'rupees', 'training fee',
  'training fee is applicable', 'mentor charges', 'fee scholarship',

  // Urgency tactics
  'urgent', 'immediately', 'asap', 'final call', 'last chance', 'final window',
  'final batch', 'limited seats', 'seats are filling', 'apply before registrations close',
  'no further extensions', 'closing soon', 'deadline alert',

  // Action requests
  'click here', 'click the link', 'verify now', 'confirm now', 'apply now',
  'fill out the form asap', 'complete your enrollment', 'enrollment process',

  // Selection claims
  'congratulations', 'you have won', 'selected', 'shortlisted',
  'shortlisted for', 'pleased to inform you', 'been shortlisted',

  // Document requests
  'aadhaar', 'pan card', 'bank details', 'account number',
  'send documents', 'share your', 'id proof',

  // Too good to be true
  'guaranteed', '100% placement', 'placement guarantee', 'lifetime job assistance',
  'stipend upto', 'stipend up to', 'free tablet', 'co-branded certificate',

  // Fake program names
  'job bridge program', 'digital bridge program', 'edulet tablet', 'smart edulet',
  'blu ai', 'smart labs', 'prepfree platform',

  // Fake organizations
  'unlox academy', 'shikshavertex', 'shiksha vertex', 'smarted innovations',
  'skill vertex', 'skillvertex',

  // Fake collaboration claims
  'powered by ibm', 'ibm powered', 'ibm training', 'microsoft internship',
  'in collaboration with meity', 'nasscom', 'aicte approved', 'vtu approved',

  // Campus scam patterns
  'campus outreach campaign', 'scholarship campaign', 'campus engagement team',
  'scholarship code', 'use code', 'avail discount',

  // Generic internship scam
  'certificate', 'internship opportunity', 'exclusive opportunity',
  'specially designed for', 'mandatory internship'
];

// Fake internship scam domains targeting Indian students
const SUSPICIOUS_DOMAINS = [
  // Known scam domains from user reports
  'shikshavertex.in', 'unloxacademy.com', 'smartedinnovations.com',
  'skillvertex.com', 'edusera.org', 'edulyt.in',

  // Fake internship sites (already blocked)
  'systemtron.in', 'codsoft.in', 'oasisinfobyte.com', 'bharatintern.live',
  'internpe.in', 'letsintern.in', 'vaultofcodes.com', 'theinternbuddy.com',
  'sparkfoundation.org', 'synapseinterns.com', 'coderscave.com',
  'intrainternship.tech', 'futureinternship.in', 'virtualintern.in',
  'youthopp.in', 'careerbuddy.online', 'trainwithcode.in',
  'prodigyinfotech.dev', 'cognifyz.com', 'infyinternshiphub.com',
  'codealpha.tech', 'mainflow.in', 'interncareerhub.com',
  'interncareerpath.tech', 'codersdata.in', 'upskillintern.in',
  'codeclause.com', 'technohacks.in', 'thecodex.in',

  // Generic suspicious domains
  'internmail.cc', 'careers-meta.org', 'hr-google.com', 'careerupdate.online',
  'urgent-offer.net', 'jobs-securelink.co', 'intern-portal.org', 'verify-now.info',
  'intern-checks.net', 'internship-certificate.xyz', 'internshipoffer.tech',
  'careers-ms.net', 'intern-recruiter.co', 'google-careers.online',
  'join-appleinterns.org', 'tesla-careerhub.info', 'intern-meta-program.net',
  'student-careerconnect.com', 'netflixintern-portal.com', 'linkedinterns.work'
];

// Only trust emails FROM these exact domains
const LEGITIMATE_DOMAINS = [
  'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'meta.com',
  'facebook.com', 'netflix.com', 'adobe.com', 'ibm.com', 'intel.com',
  'nvidia.com', 'oracle.com', 'sap.com', 'infosys.com', 'tcs.com',
  'wipro.com', 'accenture.com', 'deloitte.com', 'pwc.com', 'kpmg.com',
  // Indian universities - these are LEGITIMATE
  'nmamit.in', 'nitte.edu.in'
];

// Patterns that indicate scam even with personal Gmail accounts
const SCAM_PATTERNS = [
  /job\s*bridge\s*program/i,
  /digital\s*bridge\s*program/i,
  /vtu\s*approved\s*internship/i,
  /edulet\s*tablet/i,
  /unlox\s*academy/i,
  /shiksha\s*vertex/i,
  /smarted\s*innovations/i,
  /ibm\s*training\s*&\s*internship/i,
  /ibm\s*powered\s*internship/i,
  /microsoft\s*internship\s*program/i,
  /stipend\s*upto?\s*\d+k/i,
  /100%\s*placement/i,
  /scholarship\s*code:\s*\w+/i,
  /training\s*fee\s*(is|are)?\s*applicable/i,
  /mentor\s*charges\s*(are|is)?\s*applicable/i,
  /collaboration\s*with\s*(meity|nasscom)/i,
  /powered\s*by\s*(ibm|microsoft|google)/i,
  /final\s*call\s*[–-]\s*limited\s*seats/i,
  /complete\s*(your|the)\s*enrollment\s*(process)?/i,
  /all\s*shortlisted\s*students/i,
  /campus\s*(outreach|engagement)\s*(campaign|team)/i
];

let lastAnalyzedEmail = null;
let warningBanner = null;

// Returns true only when the user is viewing an actual email (not inbox/home)
function isInsideEmailView() {
  const hash = location.hash;
  // Gmail email URLs contain: #inbox/messageId, #sent/messageId, etc.
  // They always have a second segment after the folder name
  const parts = hash.replace('#', '').split('/');
  // Home screen is just #inbox or #all or nothing — no message ID segment
  if (parts.length < 2) return false;
  // The message ID is a long hex string (at least 10 chars)
  const msgId = parts[parts.length - 1];
  return msgId.length >= 10 && /^[a-zA-Z0-9_+%-]+$/.test(msgId);
}

function analyzeEmailContent() {
  // Only analyze when the user has actually opened an email
  if (!isInsideEmailView()) {
    console.log('🛡️ PhishGuard: Not in email view, skipping analysis');
    removeWarningBanner();
    return;
  }
  console.log('🛡️ PhishGuard: Analyzing email...');

  // Get email content - try multiple selectors
  const emailBody = document.querySelector('.a3s.aiL') ||
    document.querySelector('[data-message-id]') ||
    document.querySelector('.ii.gt') ||
    document.querySelector('[role="listitem"]') ||
    document.querySelector('[role="main"]');

  if (!emailBody) {
    console.log('🛡️ PhishGuard: No email body found');
    return;
  }

  const emailText = emailBody.innerText.toLowerCase();
  const emailTextOriginal = emailBody.innerText; // Keep original for regex
  const emailHTML = emailBody.innerHTML;

  console.log('🛡️ PhishGuard: Email text length:', emailText.length);

  // Check if already analyzed this email
  const emailId = document.location.href;
  if (lastAnalyzedEmail === emailId) {
    console.log('🛡️ PhishGuard: Already analyzed this email');
    return;
  }
  lastAnalyzedEmail = emailId;

  // ── Sender extraction ──────────────────────────────────────────────
  // Scope to the OPEN email's header area to avoid stale data from prev email
  let senderEmail = '';
  let senderDomain = '';

  // The open email's header lives inside elements like .ha, .hP parent, .nH
  // Try scoped querySelectorAll inside the email thread container first
  const emailThread = document.querySelector('.ha') ||
    document.querySelector('.adn.ads') ||
    document.querySelector('[data-message-id]');

  // Attributes that Gmail uses for the actual email address
  const attrCandidates = ['email', 'data-hovercard-id'];
  // Prioritize .gD which is the true sender header element in Gmail!
  const scopedSelectors = ['.gD[email]', 'h3 span[email]', 'span[email]', '.go[email]', '[data-hovercard-id*="@"]'];

  outer:
  for (const sel of scopedSelectors) {
    // Prefer elements scoped to the open email header
    const elements = (emailThread || document).querySelectorAll(sel);
    for (const el of elements) {
      for (const attr of attrCandidates) {
        const val = el.getAttribute(attr) || '';
        if (val.includes('@') && !val.startsWith('http')) {
          senderEmail = val.trim();
          senderDomain = senderEmail.split('@')[1] || '';
          break outer;
        }
      }
    }
  }

  // Fallback: regex-scan the header text
  if (!senderEmail) {
    const headerEl = document.querySelector('.ha') ||
      document.querySelector('.gE.iv.gt') ||
      document.querySelector('.hP')?.closest('.ha');
    if (headerEl) {
      const m = headerEl.innerText.match(/[\w.+%-]+@[\w.-]+\.[a-z]{2,}/i);
      if (m) {
        senderEmail = m[0].trim();
        senderDomain = senderEmail.split('@')[1] || '';
      }
    }
  }

  // Clean up sender email (sometimes it includes < > brackets)
  if (senderEmail) {
    senderEmail = senderEmail.replace(/[<>]/g, '').trim();
    senderDomain = senderEmail.split('@')[1] || '';
  }

  console.log('🛡️ PhishGuard: Extracted Sender:', `"${senderEmail}"`, 'Domain:', `"${senderDomain}"`);

  // ── Whitelist check — NMAMIT / NITTE trusted domains & emails ───────────────
  // Emails from these legitimate college domains and specific emails will NOT show a warning banner
  // This prevents legitimate institutional emails from triggering false alarms
  const ALWAYS_SAFE_DOMAINS = ['nmamit.in', 'nitte.edu.in'];
  const ALWAYS_SAFE_EMAILS = ['placement@nmamit.in']; // Explicitly safe sender

  const isFromCollegeDomain = senderDomain && ALWAYS_SAFE_DOMAINS.some(d => senderDomain.toLowerCase().endsWith(d.toLowerCase()));
  const isSafeEmail = senderEmail && ALWAYS_SAFE_EMAILS.some(e => senderEmail.toLowerCase().includes(e.toLowerCase()));

  if (isFromCollegeDomain || isSafeEmail) {
    console.log('🛡️ PhishGuard: Email from legitimate college source - SUPPRESSING BANNER:', senderEmail || senderDomain);
    removeWarningBanner();
    return; // Skip all analysis and banner for college domains/emails
  }

  // Analyze for phishing indicators
  const analysis = {
    suspiciousKeywords: [],
    matchedScamPatterns: [],
    isSuspiciousDomain: false,
    isPersonalGmailScam: false,
    isLegitimate: false,
    riskScore: 0,
    reasons: []
  };

  // Check keywords
  SUSPICIOUS_KEYWORDS.forEach(keyword => {
    if (emailText.includes(keyword.toLowerCase())) {
      analysis.suspiciousKeywords.push(keyword);
      analysis.riskScore += 8;
    }
  });

  // Check scam patterns (regex) - HIGH PRIORITY
  SCAM_PATTERNS.forEach(pattern => {
    if (pattern.test(emailTextOriginal)) {
      analysis.matchedScamPatterns.push(pattern.source);
      analysis.riskScore += 25; // High score for known scam patterns
    }
  });

  // Check for personal Gmail sending corporate-style internship emails
  if (senderDomain === 'gmail.com' &&
    (emailText.includes('internship') || emailText.includes('shortlisted') ||
      emailText.includes('enrollment') || emailText.includes('program'))) {
    analysis.isPersonalGmailScam = true;
    analysis.riskScore += 35;
    analysis.reasons.push('Personal Gmail sending internship offers (common scam pattern)');
  }

  // Check sender domain
  if (senderDomain) {
    if (SUSPICIOUS_DOMAINS.some(d => senderDomain.includes(d))) {
      analysis.isSuspiciousDomain = true;
      analysis.riskScore += 50;
      analysis.reasons.push(`Known scam domain: ${senderDomain}`);
    }

    // Check for shikshavertex pattern (name_name@shikshavertex.in)
    if (senderDomain.includes('shikshavertex') || senderDomain.includes('skillvertex')) {
      analysis.riskScore += 60;
      analysis.reasons.push('ShikshaVertex/SkillVertex scam domain detected');
    }

    if (LEGITIMATE_DOMAINS.some(d => senderDomain.endsWith(d))) {
      analysis.isLegitimate = true;
      analysis.riskScore = Math.max(0, analysis.riskScore - 30);
    }
  }

  // Check for payment requests with internship context
  if ((emailText.includes('fee') || emailText.includes('payment') || emailText.includes('charges')) &&
    (emailText.includes('internship') || emailText.includes('training') || emailText.includes('program'))) {
    analysis.riskScore += 45;
    analysis.reasons.push('Requires payment for internship (legitimate internships are FREE)');
  }

  // Check for urgency tactics
  if (emailText.includes('urgent') || emailText.includes('immediately') ||
    emailText.includes('final call') || emailText.includes('final batch') ||
    emailText.includes('limited seats') || emailText.includes('last chance')) {
    analysis.riskScore += 25;
    analysis.reasons.push('Uses aggressive urgency tactics');
  }

  // Check for document requests
  if (emailText.includes('aadhaar') || emailText.includes('pan card') || emailText.includes('id proof')) {
    analysis.riskScore += 30;
    analysis.reasons.push('Requests sensitive documents');
  }

  // Check for fake collaboration claims
  if ((emailText.includes('meity') || emailText.includes('nasscom') || emailText.includes('aicte')) &&
    (emailText.includes('internship') || emailText.includes('training'))) {
    analysis.riskScore += 30;
    analysis.reasons.push('Claims fake govt/industry collaboration');
  }

  // Check for scholarship code pattern (scam indicator)
  if (/scholarship\s*code/i.test(emailTextOriginal) || /use\s*code:\s*\w+/i.test(emailTextOriginal)) {
    analysis.riskScore += 35;
    analysis.reasons.push('Contains "scholarship code" (common scam tactic)');
  }

  // Check for "100% placement" or "guaranteed" claims
  if (emailText.includes('100% placement') || emailText.includes('placement guarantee')) {
    analysis.riskScore += 40;
    analysis.reasons.push('Claims 100% placement guarantee (unrealistic)');
  }

  // Check for free tablet / device promises
  if (emailText.includes('tablet') && (emailText.includes('free') || emailText.includes('receive'))) {
    analysis.riskScore += 30;
    analysis.reasons.push('Promises free device (bait tactic)');
  }

  // Check for mass BCC pattern (to bcc: me)
  const emailHeader = document.querySelector('.iw') || document.querySelector('.gE');
  if (emailHeader && emailHeader.innerText.toLowerCase().includes('bcc:')) {
    analysis.riskScore += 15;
    analysis.reasons.push('Sent as BCC (mass email)');
  }

  // Add scam pattern reasons
  if (analysis.matchedScamPatterns.length > 0) {
    analysis.reasons.push(`Matches ${analysis.matchedScamPatterns.length} known scam patterns`);
  }

  // Collect top suspicious keywords found (up to 8 for display)
  analysis.topKeywords = analysis.suspiciousKeywords.slice(0, 8);
  if (analysis.suspiciousKeywords.length > 0) {
    analysis.reasons.push(`Contains ${analysis.suspiciousKeywords.length} suspicious keyword${analysis.suspiciousKeywords.length > 1 ? 's' : ''}`);
  }

  // Cap risk score at 100
  analysis.riskScore = Math.min(analysis.riskScore, 100);

  // Show warning if suspicious (lowered threshold for better detection)
  if (analysis.riskScore >= 25) {
    showPhishingWarning(analysis, senderEmail);
  } else {
    removeWarningBanner();
  }
}

function showPhishingWarning(analysis, senderEmail) {
  removeWarningBanner();

  // ── Severity tiers ───────────────────────────────────────────────────
  let scamType = 'Suspicious Email';
  let severityLabel = 'Caution';
  let accentColor = '#f59e0b';   // amber
  let barColor = 'linear-gradient(90deg, #f59e0b, #ef4444)';
  let headerBg = 'linear-gradient(135deg, #1e1035 0%, #2d1a5e 100%)';
  let bodyBg = '#110d22';
  let borderCol = 'rgba(139,92,246,0.4)';

  if (analysis.reasons.some(r => r.includes('internship') || r.includes('ShikshaVertex') || r.includes('scam pattern'))) {
    scamType = 'Fake Internship Scam';
  } else if (analysis.reasons.some(r => r.includes('payment'))) {
    scamType = 'Payment Scam';
  }

  if (analysis.riskScore >= 70) {
    severityLabel = 'High Risk';
    accentColor = '#f87171';
    barColor = 'linear-gradient(90deg, #ef4444, #dc2626)';
    headerBg = 'linear-gradient(135deg, #1a0a0a 0%, #3b0c0c 100%)';
    bodyBg = '#130808';
    borderCol = 'rgba(239,68,68,0.5)';
  } else if (analysis.riskScore >= 50) {
    severityLabel = 'High Risk';
    accentColor = '#fb923c';
    barColor = 'linear-gradient(90deg, #f97316, #ef4444)';
    headerBg = 'linear-gradient(135deg, #1a0f00 0%, #431407 100%)';
    bodyBg = '#130b04';
    borderCol = 'rgba(249,115,22,0.45)';
  }

  const topReasons = analysis.reasons.slice(0, 4);
  const topKeywords = (analysis.topKeywords || []).slice(0, 8);

  warningBanner = document.createElement('div');
  warningBanner.id = 'phishguard-warning';
  warningBanner.innerHTML = `
    <style>
      #phishguard-warning {
        font-family: 'Google Sans', 'Segoe UI', Arial, sans-serif;
        margin: 12px 0 18px;
        border-radius: 16px;
        overflow: hidden;
        box-shadow: 0 12px 40px rgba(0,0,0,0.5), 0 0 0 1px ${borderCol};
        animation: pgSlideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes pgSlideIn {
        from { opacity: 0; transform: translateY(-16px) scale(0.98); }
        to   { opacity: 1; transform: translateY(0)   scale(1); }
      }
      #phishguard-warning .pg-header {
        background: ${headerBg};
        padding: 14px 18px 13px;
        display: flex;
        align-items: center;
        gap: 13px;
        border-bottom: 1px solid ${borderCol};
      }
      #phishguard-warning .pg-icon {
        width: 40px; height: 40px;
        background: rgba(255,255,255,0.1);
        backdrop-filter: blur(4px);
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        flex-shrink: 0;
        font-size: 20px;
        border: 1px solid rgba(255,255,255,0.15);
      }
      #phishguard-warning .pg-title-group { flex: 1; min-width: 0; }
      #phishguard-warning .pg-badge {
        font-size: 9.5px; font-weight: 800; letter-spacing: 0.1em;
        text-transform: uppercase;
        background: ${accentColor};
        color: #0a0005;
        padding: 2px 9px; border-radius: 20px;
        display: inline-block; margin-bottom: 5px;
      }
      #phishguard-warning .pg-title {
        font-size: 15px; font-weight: 700; color: #fff;
        line-height: 1.25; white-space: nowrap;
        overflow: hidden; text-overflow: ellipsis;
      }
      #phishguard-warning .pg-dismiss {
        background: rgba(255,255,255,0.08);
        border: 1px solid rgba(255,255,255,0.18);
        color: rgba(255,255,255,0.75);
        padding: 5px 13px;
        border-radius: 20px;
        cursor: pointer;
        font-size: 11.5px;
        font-weight: 600;
        transition: all 0.2s;
        white-space: nowrap;
        flex-shrink: 0;
      }
      #phishguard-warning .pg-dismiss:hover {
        background: rgba(255,255,255,0.18);
        color: #fff;
      }
      #phishguard-warning .pg-body {
        background: ${bodyBg};
        padding: 14px 18px 16px;
      }
      /* Score row */
      #phishguard-warning .pg-score-row {
        display: flex; align-items: center; gap: 10px;
        margin-bottom: 13px;
      }
      #phishguard-warning .pg-score-label {
        font-size: 11px; color: #71717a; white-space: nowrap;
        text-transform: uppercase; letter-spacing: 0.05em;
      }
      #phishguard-warning .pg-score-bar {
        flex: 1; height: 5px; border-radius: 3px;
        background: rgba(255,255,255,0.08);
        overflow: hidden;
      }
      #phishguard-warning .pg-score-fill {
        height: 100%; border-radius: 3px;
        background: ${barColor};
        width: ${analysis.riskScore}%;
        transition: width 0.8s cubic-bezier(0.16,1,0.3,1);
      }
      #phishguard-warning .pg-score-num {
        font-size: 14px; font-weight: 700; color: ${accentColor};
        white-space: nowrap; min-width: 36px; text-align: right;
      }
      /* Reasons */
      #phishguard-warning .pg-reasons {
        display: flex; flex-direction: column; gap: 4px;
        margin-bottom: 11px;
      }
      #phishguard-warning .pg-reason {
        font-size: 12px; color: #c4c4cc;
        display: flex; align-items: flex-start; gap: 7px;
        line-height: 1.45;
      }
      #phishguard-warning .pg-reason-dot {
        width: 5px; height: 5px; border-radius: 50%;
        background: ${accentColor};
        flex-shrink: 0; margin-top: 5px;
      }
      /* Sender chip */
      #phishguard-warning .pg-sender {
        display: inline-flex; align-items: center; gap: 5px;
        background: rgba(255,255,255,0.06);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 11px; color: #9ca3af;
        margin-bottom: 11px;
      }
      /* Keyword chips */
      #phishguard-warning .pg-keywords {
        display: flex; flex-wrap: wrap; gap: 5px;
        margin-bottom: 13px;
      }
      #phishguard-warning .pg-kw-label {
        font-size: 10.5px; color: #6b7280;
        text-transform: uppercase; letter-spacing: 0.05em;
        width: 100%; margin-bottom: 2px;
      }
      #phishguard-warning .pg-kw {
        font-size: 10.5px; font-weight: 600;
        background: rgba(255,255,255,0.07);
        border: 1px solid rgba(255,255,255,0.12);
        color: ${accentColor};
        padding: 2px 8px; border-radius: 5px;
        white-space: nowrap;
      }
      /* Footer tip */
      #phishguard-warning .pg-footer {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 10px;
        padding: 10px 13px;
        font-size: 11.5px;
        color: #9ca3af;
        line-height: 1.65;
      }
      #phishguard-warning .pg-footer strong { color: #fcd34d; }
      #phishguard-warning .pg-actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-bottom: 10px;
      }
      #phishguard-warning .pg-btn {
        border: 0;
        border-radius: 8px;
        padding: 7px 12px;
        font-size: 11.5px;
        font-weight: 700;
        cursor: pointer;
      }
      #phishguard-warning .pg-btn.report {
        background: rgba(239,68,68,0.25);
        color: #fecaca;
        border: 1px solid rgba(239,68,68,0.55);
      }
      #phishguard-warning .pg-btn.open {
        background: rgba(45,212,191,0.2);
        color: #99f6e4;
        border: 1px solid rgba(45,212,191,0.45);
      }
    </style>

    <div class="pg-header">
      <div class="pg-icon">🛡️</div>
      <div class="pg-title-group">
        <div class="pg-badge">${severityLabel}</div>
        <div class="pg-title">PhishGuard · ${scamType}</div>
      </div>
      <button id="phishguard-dismiss-btn" class="pg-dismiss">✕ Dismiss</button>
    </div>

    <div class="pg-body">
      <div class="pg-score-row">
        <span class="pg-score-label">Risk Score</span>
        <div class="pg-score-bar"><div class="pg-score-fill"></div></div>
        <span class="pg-score-num">${analysis.riskScore}%</span>
      </div>

      <div class="pg-reasons">
        ${topReasons.map(r => `<div class="pg-reason"><div class="pg-reason-dot"></div><span>${r}</span></div>`).join('')}
      </div>

      ${senderEmail ? `<div class="pg-sender">📧 <span>${senderEmail}</span></div>` : ''}

      ${topKeywords.length > 0 ? `
      <div class="pg-keywords">
        <div class="pg-kw-label">Suspicious keywords detected</div>
        ${topKeywords.map(k => `<span class="pg-kw">${k}</span>`).join('')}
      </div>` : ''}

      <div class="pg-actions">
        <button id="phishguard-report-btn" class="pg-btn report">Report to SafeNet</button>
        <button id="phishguard-open-dashboard-btn" class="pg-btn open">Open Dashboard</button>
      </div>

      <div class="pg-footer">
        <strong>⚠️ Stay Safe:</strong> Legitimate internships <strong>never charge fees</strong>.
        Don't fill any Google Form link. Verify with your placement cell.
        Real companies (IBM, Microsoft) <strong>never</strong> email from Gmail or random domains.
      </div>
    </div>
  `;

  // Insert banner — try multiple Gmail containers
  const containerSelectors = [
    '.a3s.aiL',
    '.ii.gt',
    '[data-message-id]',
    '.gs',
    '.adn.ads',
    '[role="listitem"]'
  ];

  let emailContainer = null;
  for (const selector of containerSelectors) {
    const el = document.querySelector(selector);
    if (el) {
      emailContainer = el.parentElement || el;
      break;
    }
  }

  if (emailContainer) {
    emailContainer.insertBefore(warningBanner, emailContainer.firstChild);
    console.log('🛡️ PhishGuard: Banner inserted successfully');
  } else {
    const mainArea = document.querySelector('[role="main"]');
    if (mainArea) mainArea.insertBefore(warningBanner, mainArea.firstChild);
  }

  const dismissBtn = document.getElementById('phishguard-dismiss-btn');
  if (dismissBtn) dismissBtn.addEventListener('click', removeWarningBanner);
  const reportBtn = document.getElementById('phishguard-report-btn');
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      const emailData = extractEmailData();
      const reportText = [
        `Sender: ${senderEmail || emailData.sender || "unknown"}`,
        `Subject: ${emailData.subject || "unknown"}`,
        "",
        (emailData.body || "").slice(0, 5000),
      ].join("\n");
      chrome.runtime.sendMessage({
        action: "reportScamMessage",
        platform: "gmail",
        messageText: reportText,
        includeScreenshot: true,
        analysis: {
          isScam: true,
          riskScore: analysis.riskScore,
          scamType,
          explanation: analysis.reasons.join(" | ").slice(0, 800),
        },
        pageUrl: window.location.href,
        createdAt: new Date().toISOString(),
      }, (response) => {
        const ok = Boolean(response?.success);
        reportBtn.textContent = ok ? "Reported with Screenshot" : "Report Sent";
        reportBtn.disabled = true;
        reportBtn.style.opacity = "0.75";
      });
    });
  }
  const openDashBtn = document.getElementById('phishguard-open-dashboard-btn');
  if (openDashBtn) {
    openDashBtn.addEventListener('click', () => {
      window.open('http://localhost:3000/dashboard', '_blank');
    });
  }

  console.log('🛡️ PhishGuard: Phishing email detected!', analysis);
}

function removeWarningBanner() {
  const existing = document.getElementById('phishguard-warning');
  if (existing) {
    existing.remove();
  }
  warningBanner = null;
}

// Observe DOM changes for email navigation
function setupObserver() {
  let lastUrl = location.href;

  const observer = new MutationObserver(() => {
    const currentUrl = location.href;

    // URL changed — user navigated (e.g., opened or closed an email)
    if (currentUrl !== lastUrl) {
      lastUrl = currentUrl;
      lastAnalyzedEmail = null;

      if (isInsideEmailView()) {
        // Navigated INTO an email
        setTimeout(analyzeEmailContent, 600);
        setTimeout(analyzeEmailContent, 1400);
      } else {
        // Navigated BACK to inbox/home — remove any existing banner
        removeWarningBanner();
      }
      return;
    }

    // Same URL but email body appeared (e.g., expanding a thread)
    if (isInsideEmailView()) {
      const emailBody = document.querySelector('.a3s.aiL');
      if (emailBody && !document.getElementById('phishguard-warning')) {
        setTimeout(analyzeEmailContent, 400);
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

// Initialize
console.log('🛡️ PhishGuard: Gmail protection active - v3.0');

// Setup observer for navigation
setupObserver();

// Check on hash change (Gmail uses hash-based routing for emails)
window.addEventListener('hashchange', () => {
  console.log('🛡️ PhishGuard: Hash changed');
  lastAnalyzedEmail = null;
  if (isInsideEmailView()) {
    setTimeout(analyzeEmailContent, 500);
    setTimeout(analyzeEmailContent, 1200);
    setTimeout(addScanButton, 800);
  } else {
    removeWarningBanner();
  }
});

// Initial check — only run if already inside an email (e.g., page refresh on email URL)
if (isInsideEmailView()) {
  setTimeout(analyzeEmailContent, 1000);
}

// ========== SCAN WITH PHISHGUARD BUTTON ==========

function addScanButton() {
  // Only add when inside an email view
  if (!isInsideEmailView()) return;
  // Don't add if already exists
  if (document.getElementById('phishguard-scan-btn')) return;

  // Find the email toolbar (action buttons area)
  const toolbar = document.querySelector('.ade') ||
    document.querySelector('[gh="mtb"]') ||
    document.querySelector('.G-atb');

  if (!toolbar) return;

  // Create scan button
  const scanBtn = document.createElement('div');
  scanBtn.id = 'phishguard-scan-btn';
  scanBtn.innerHTML = `
    <div style="
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 16px;
      margin-left: 8px;
      background: linear-gradient(135deg, #0891b2 0%, #2563eb 100%);
      color: white;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(8, 145, 178, 0.3);
      transition: all 0.2s;
      font-family: 'Google Sans', Roboto, sans-serif;
    " onmouseover="this.style.transform='scale(1.02)'; this.style.boxShadow='0 4px 12px rgba(8, 145, 178, 0.4)'"
       onmouseout="this.style.transform='scale(1)'; this.style.boxShadow='0 2px 8px rgba(8, 145, 178, 0.3)'">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path>
        <path d="m9 12 2 2 4-4"></path>
      </svg>
      Scan with PhishGuard
    </div>
  `;

  toolbar.appendChild(scanBtn);

  // Add click handler
  scanBtn.addEventListener('click', scanWithPhishGuard);

  console.log('🛡️ PhishGuard: Scan button added');
}

function scanWithPhishGuard() {
  // Extract email data
  const emailData = extractEmailData();

  if (!emailData.body) {
    alert('Please open an email first to scan it with PhishGuard');
    return;
  }

  // Encode data for URL
  const params = new URLSearchParams({
    sender: emailData.sender,
    subject: emailData.subject,
    body: emailData.body,
    autoScan: 'true'
  });

  // Open PhishGuard Email Scanner with data
  const scannerUrl = `http://localhost:3000/email?${params.toString()}`;
  window.open(scannerUrl, '_blank');

  console.log('🛡️ PhishGuard: Opening scanner with email data');
}

function extractEmailData() {
  const data = {
    sender: '',
    subject: '',
    body: ''
  };

  // Get sender
  const senderSelectors = ['span[email]', '.gD[email]', '.go[email]', '.g2'];
  for (const selector of senderSelectors) {
    const el = document.querySelector(selector);
    if (el) {
      data.sender = el.getAttribute('email') || el.innerText || '';
      if (data.sender.includes('@')) break;
    }
  }

  // Get subject
  const subjectEl = document.querySelector('h2.hP') ||
    document.querySelector('[data-thread-perm-id]') ||
    document.querySelector('.ha h2');
  if (subjectEl) {
    data.subject = subjectEl.innerText || '';
  }

  // Get body
  const bodyEl = document.querySelector('.a3s.aiL') ||
    document.querySelector('.ii.gt') ||
    document.querySelector('[data-message-id]');
  if (bodyEl) {
    data.body = bodyEl.innerText || '';
  }

  return data;
}

// Add scan button on load
setTimeout(addScanButton, 2000);
setTimeout(addScanButton, 4000);


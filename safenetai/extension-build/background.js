// PhishGuard Chrome Extension - Combined Link & Email Phishing Detection
// Background Service Worker

try {
  importScripts('gemini-config.js');
} catch (error) {
  console.warn('Gemini config file not loaded, falling back to storage key lookup.');
}

const DEFAULT_GEMINI_MODEL = 'gemini-2.5-flash';
const FIREBASE_PROJECT_ID = 'phisquard';

let phishingLinks = [];
let phishingEmails = [];
let suspiciousKeywords = [];
let phishingPatterns = [];

async function getGeminiApiKey() {
  if (typeof GEMINI_CONFIG !== 'undefined' && GEMINI_CONFIG.apiKey) {
    return GEMINI_CONFIG.apiKey;
  }

  const stored = await chrome.storage.local.get(['geminiApiKey']);
  if (stored.geminiApiKey) {
    return stored.geminiApiKey;
  }

  throw new Error('Missing Gemini API key. Set GEMINI_CONFIG.apiKey or chrome.storage.local.geminiApiKey.');
}

function getGeminiModel() {
  if (typeof GEMINI_CONFIG !== 'undefined' && GEMINI_CONFIG.model) {
    return GEMINI_CONFIG.model;
  }
  return DEFAULT_GEMINI_MODEL;
}

async function getAppApiBaseUrl() {
  if (typeof GEMINI_CONFIG !== 'undefined' && GEMINI_CONFIG.appApiBaseUrl) {
    return GEMINI_CONFIG.appApiBaseUrl;
  }

  const stored = await chrome.storage.local.get(['safenetAppApiBaseUrl']);
  if (stored.safenetAppApiBaseUrl) {
    return stored.safenetAppApiBaseUrl;
  }

  return 'http://localhost:3000';
}

function safeParseJsonObject(text) {
  try {
    return JSON.parse(text);
  } catch {
    const jsonMatch = String(text || '').match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return null;
    }

    try {
      return JSON.parse(jsonMatch[0]);
    } catch {
      return null;
    }
  }
}

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard Extension Installed');
  fetchPhishingData();
  setInterval(fetchPhishingData, 5 * 60 * 1000); // Refresh every 5 mins
});

// Fetch phishing data from Firebase
async function fetchPhishingData() {
  try {
    // Fetch phishing links
    const linksRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/phishing_links`
    );
    const linksData = await linksRes.json();
    if (linksData.documents) {
      phishingLinks = linksData.documents.map((doc) => doc.fields.url?.stringValue || '').filter(Boolean);
    }

    // Fetch phishing email domains
    const emailsRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/phishing_emails`
    );
    const emailsData = await emailsRes.json();
    if (emailsData.documents) {
      phishingEmails = emailsData.documents.map((doc) => doc.fields.domain?.stringValue || '').filter(Boolean);
    }

    // Fetch suspicious keywords
    const keywordsRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/suspicious_keywords`
    );
    const keywordsData = await keywordsRes.json();
    if (keywordsData.documents) {
      suspiciousKeywords = keywordsData.documents.map((doc) => doc.fields.keyword?.stringValue || '').filter(Boolean);
    }

    // Fetch phishing patterns
    const patternsRes = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/phishing_patterns`
    );
    const patternsData = await patternsRes.json();
    if (patternsData.documents) {
      phishingPatterns = patternsData.documents.map((doc) => doc.fields.pattern?.stringValue || '').filter(Boolean);
    }

    console.log('PhishGuard data refreshed:', {
      links: phishingLinks.length,
      emails: phishingEmails.length,
      keywords: suspiciousKeywords.length,
      patterns: phishingPatterns.length
    });

    // Update declarative net request rules
    await updateBlockRules();
  } catch (error) {
    console.error('Error fetching phishing data:', error);
  }
}

// Update declarative net request rules dynamically
async function updateBlockRules() {
  try {
    // Get existing rules
    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
    const existingRuleIds = existingRules.map(rule => rule.id);

    // Remove all existing rules
    if (existingRuleIds.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existingRuleIds
      });
    }

    // Create new rules from phishing links
    const newRules = phishingLinks.map((url, index) => ({
      id: index + 1,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: url,
        resourceTypes: ['main_frame']
      }
    }));

    // Add new rules (limit to 5000 rules for Chrome)
    if (newRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: newRules.slice(0, 5000)
      });
    }

    console.log(`Updated ${Math.min(newRules.length, 5000)} blocking rules`);
  } catch (error) {
    console.error('Error updating block rules:', error);
  }
}

// Analyze link with Gemini AI
async function analyzeLinkWithGemini(url) {
  try {
    const geminiApiKey = await getGeminiApiKey();
    const model = getGeminiModel();
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: `Analyze this URL for phishing indicators and determine if it's malicious or legitimate. URL: ${url}

Please provide:
1. A verdict: PHISHING or LEGITIMATE
2. Risk level: HIGH, MEDIUM, or LOW
3. Brief explanation (2-3 sentences) of why this is suspicious or safe

Format your response as JSON:
{
  "verdict": "PHISHING" or "LEGITIMATE",
  "riskLevel": "HIGH/MEDIUM/LOW",
  "explanation": "Your explanation here"
}`
            }]
          }]
        })
      }
    );

    const data = await response.json();
    const responseText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

    const parsed = safeParseJsonObject(responseText);
    if (parsed) {
      return parsed;
    }
    
    return {
      verdict: 'UNKNOWN',
      riskLevel: 'MEDIUM',
      explanation: 'Unable to analyze the URL at this time.'
    };
  } catch (error) {
    console.error('Gemini analysis error:', error);
    return {
      verdict: 'UNKNOWN',
      riskLevel: 'MEDIUM',
      explanation: 'Analysis service temporarily unavailable.'
    };
  }
}

// Analyze email with Gemini AI
async function analyzeEmailWithGemini(senderDomain, emailContent) {
  try {
    const geminiApiKey = await getGeminiApiKey();
    const model = getGeminiModel();
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: `Analyze this email for phishing indicators:

Sender Domain: ${senderDomain}
Email Content: ${emailContent}

Check for:
1. Sender domain legitimacy
2. Suspicious keywords (urgent action required, verify account, etc.)
3. Common phishing patterns (fake urgency, requesting credentials, etc.)

Please provide:
1. A verdict: PHISHING or LEGITIMATE
2. Risk level: HIGH, MEDIUM, or LOW
3. Brief explanation (2-3 sentences) of why this email is suspicious or safe

Format your response as JSON:
{
  "verdict": "PHISHING" or "LEGITIMATE",
  "riskLevel": "HIGH/MEDIUM/LOW",
  "explanation": "Your explanation here",
  "suspiciousIndicators": ["indicator1", "indicator2"]
}`
            }]
          }]
        })
      }
    );

    const data = await response.json();
    const responseText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

    const parsed = safeParseJsonObject(responseText);
    if (parsed) {
      return parsed;
    }
    
    return {
      verdict: 'UNKNOWN',
      riskLevel: 'MEDIUM',
      explanation: 'Unable to analyze the email at this time.',
      suspiciousIndicators: []
    };
  } catch (error) {
    console.error('Gemini email analysis error:', error);
    return {
      verdict: 'UNKNOWN',
      riskLevel: 'MEDIUM',
      explanation: 'Analysis service temporarily unavailable.',
      suspiciousIndicators: []
    };
  }
}

// Verify reported URL with Gemini before adding to blocklist
async function verifyAndAddToBlocklist(reportedUrl, description, scamType) {
  try {
    const geminiApiKey = await getGeminiApiKey();
    const model = getGeminiModel();
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [{
            parts: [{
              text: `A user has reported this URL as a phishing/scam site. Please verify if this is genuinely a phishing attempt.

Reported URL: ${reportedUrl}
Scam Type Reported: ${scamType}
User Description: ${description}

Analyze the URL structure, domain, and the provided context to determine:
1. Is this genuinely a phishing/scam site?
2. Should this URL be added to a blocklist?

Format your response as JSON:
{
  "isPhishing": true or false,
  "shouldBlock": true or false,
  "confidence": "HIGH/MEDIUM/LOW",
  "reason": "Explanation of your decision"
}`
            }]
          }]
        })
      }
    );

    const data = await response.json();
    const responseText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const result = safeParseJsonObject(responseText);
    if (result) {
      
      if (result.shouldBlock && result.isPhishing) {
        // Add to Firebase blocklist
        await addToFirebaseBlocklist(reportedUrl, scamType, result.reason);
        return {
          added: true,
          ...result
        };
      }
      
      return {
        added: false,
        ...result
      };
    }
    
    return {
      added: false,
      isPhishing: false,
      shouldBlock: false,
      confidence: 'LOW',
      reason: 'Unable to verify the reported URL.'
    };
  } catch (error) {
    console.error('Verification error:', error);
    return {
      added: false,
      isPhishing: false,
      shouldBlock: false,
      confidence: 'LOW',
      reason: 'Verification service temporarily unavailable.'
    };
  }
}

async function analyzeChatMessageWithGemini(messageText) {
  const buildLocalFallback = (reason) => {
    const text = String(messageText || '').toLowerCase();
    const indicators = [
      'urgent',
      'verify',
      'account',
      'suspend',
      'blocked',
      'otp',
      'password',
      'bank',
      'kyc',
      'fee',
      'payment',
      'click',
      'shortlisted',
      'internship',
      'whatsapp',
      'job offer',
      'refundable',
    ];

    let score = 0;
    indicators.forEach((word) => {
      if (text.includes(word)) score += 1;
    });

    if (text.includes('http://') || text.includes('https://')) score += 2;

    const riskScore = Math.min(95, 35 + score * 7);
    const isScam = score >= 3;

    return {
      isScam,
      riskScore: isScam ? riskScore : Math.min(25, riskScore),
      scamType: isScam ? 'phishing' : 'unknown',
      explanation: isScam
        ? `Local fallback flagged scam indicators (${reason}).`
        : `AI analysis unavailable (${reason}); local fallback found low risk.`,
      fallback: true,
    };
  };

  try {
    const geminiApiKey = await getGeminiApiKey();
    const model = getGeminiModel();

    const prompt = `Analyze the following message and determine if it is a scam.
Respond in JSON format with:

* isScam (true/false)
* riskScore (0-100)
* scamType (e.g., phishing, job scam, financial fraud)
* explanation (short reason)

Message: ${messageText}`;

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          generationConfig: {
            temperature: 0.1,
            responseMimeType: 'application/json',
          },
          contents: [{
            parts: [{ text: prompt }],
          }],
        }),
      }
    );

    if (!response.ok) {
      if (response.status === 429) {
        // Rate-limited: use local fallback instead of throwing noisy runtime errors.
        return buildLocalFallback('rate_limited_429');
      }

      return buildLocalFallback(`http_${response.status}`);
    }

    const data = await response.json();
    const responseText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const parsed = safeParseJsonObject(responseText);

    if (!parsed) {
      return buildLocalFallback('parse_failed');
    }

    return {
      isScam: Boolean(parsed.isScam),
      riskScore: Math.max(0, Math.min(100, Number(parsed.riskScore) || 0)),
      scamType: String(parsed.scamType || 'unknown'),
      explanation: String(parsed.explanation || 'No explanation provided.'),
    };
  } catch (error) {
    console.warn('Gemini chat analysis unavailable, using local fallback.');
    return buildLocalFallback('network_or_runtime');
  }
}

async function storeScamReport(reportPayload) {
  try {
    const existing = await chrome.storage.local.get(['scamReports']);
    const reports = Array.isArray(existing.scamReports) ? existing.scamReports : [];
    reports.unshift(reportPayload);
    await chrome.storage.local.set({
      scamReports: reports.slice(0, 250),
    });
    console.log('Stored scam report:', reportPayload);
    return { success: true };
  } catch (error) {
    console.error('Failed to store scam report:', error);
    return { success: false };
  }
}

async function sendReportToSafeNetBackend(reportPayload) {
  try {
    const baseUrl = await getAppApiBaseUrl();
    const cleanBaseUrl = String(baseUrl).replace(/\/$/, '');

    const response = await fetch(`${cleanBaseUrl}/api/extension/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        platform: reportPayload.platform,
        messageText: reportPayload.messageText,
        analysis: reportPayload.analysis,
        pageUrl: reportPayload.pageUrl,
        createdAt: reportPayload.createdAt,
        proofFile: reportPayload.proofFile || undefined,
      }),
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      console.error('Failed to send report to SafeNet backend:', payload);
      return { success: false, error: payload?.error || `http_${response.status}` };
    }

    console.log('Report synced to SafeNet backend:', payload);
    return { success: true, payload };
  } catch (error) {
    console.error('SafeNet backend sync error:', error);
    return { success: false, error: error?.message || 'network_error' };
  }
}

function dataUrlToProofFilePayload(dataUrl, fileName = 'gmail-screenshot.png') {
  if (!dataUrl || typeof dataUrl !== 'string' || !dataUrl.startsWith('data:')) {
    return null;
  }

  const commaIndex = dataUrl.indexOf(',');
  if (commaIndex === -1) {
    return null;
  }

  const meta = dataUrl.slice(0, commaIndex);
  const base64Data = dataUrl.slice(commaIndex + 1);
  const mimeMatch = /data:([^;]+);base64/i.exec(meta);
  const mimeType = mimeMatch?.[1] || 'image/png';

  // Approximate base64 decoded size in bytes
  const sizeBytes = Math.floor((base64Data.length * 3) / 4);
  if (sizeBytes <= 0) {
    return null;
  }

  return {
    fileName,
    mimeType,
    sizeBytes,
    base64Data,
  };
}

async function captureScreenshotProof(senderTab) {
  if (!senderTab || typeof senderTab.windowId !== 'number') {
    return null;
  }

  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(senderTab.windowId, { format: 'png' });
    return dataUrlToProofFilePayload(dataUrl);
  } catch (error) {
    console.warn('Screenshot capture failed:', error);
    return null;
  }
}

// Add verified phishing URL to Firebase blocklist
async function addToFirebaseBlocklist(url, scamType, reason) {
  try {
    const response = await fetch(
      `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/phishing_links`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          fields: {
            url: { stringValue: url },
            scamType: { stringValue: scamType },
            reason: { stringValue: reason },
            addedAt: { timestampValue: new Date().toISOString() },
            source: { stringValue: 'gemini_verified_report' }
          }
        })
      }
    );

    if (response.ok) {
      console.log('URL added to blocklist:', url);
      // Refresh local blocklist
      await fetchPhishingData();
      return true;
    }
    return false;
  } catch (error) {
    console.error('Error adding to Firebase:', error);
    return false;
  }
}

// Check if a URL is in the local blocklist
function isUrlBlocked(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.replace('www.', '');
    
    return phishingLinks.some(blockedUrl => {
      const cleanBlocked = blockedUrl.replace('www.', '').toLowerCase();
      return hostname.toLowerCase().includes(cleanBlocked) || 
             url.toLowerCase().includes(cleanBlocked);
    });
  } catch {
    return false;
  }
}

// Check if email sender domain is suspicious
function isEmailDomainSuspicious(domain) {
  const cleanDomain = domain.toLowerCase().replace('www.', '');
  
  return phishingEmails.some(blockedDomain => {
    const cleanBlocked = blockedDomain.toLowerCase().replace('www.', '');
    return cleanDomain.includes(cleanBlocked) || cleanBlocked.includes(cleanDomain);
  });
}

// Check for suspicious keywords in email content
function checkSuspiciousKeywords(content) {
  const lowerContent = content.toLowerCase();
  const found = [];
  
  // Default suspicious keywords if none loaded from Firebase
  const defaultKeywords = [
    'urgent action required',
    'verify your account',
    'password expired',
    'click here immediately',
    'suspend your account',
    'confirm your identity',
    'limited time offer',
    'act now',
    'free gift',
    'you have won',
    'congratulations winner',
    'claim your prize',
    'account compromised',
    'unusual activity',
    'update payment',
    'wire transfer',
    'social security',
    'bank account details'
  ];
  
  const keywords = suspiciousKeywords.length > 0 ? suspiciousKeywords : defaultKeywords;
  
  keywords.forEach(keyword => {
    if (lowerContent.includes(keyword.toLowerCase())) {
      found.push(keyword);
    }
  });
  
  return found;
}

// Check for phishing patterns in email content
function checkPhishingPatterns(content) {
  const patterns = [
    /dear\s+(customer|user|member|account\s*holder)/i,
    /verify\s+your\s+(account|identity|information)/i,
    /click\s+(here|below|this\s+link)\s+to/i,
    /your\s+account\s+(has\s+been|will\s+be)\s+(suspended|locked|terminated)/i,
    /confirm\s+your\s+(password|credentials|login)/i,
    /update\s+your\s+(payment|billing|card)\s+information/i,
    /unusual\s+(activity|sign-in|login)/i,
    /immediately|urgently|within\s+24\s+hours/i
  ];
  
  const found = [];
  patterns.forEach(pattern => {
    if (pattern.test(content)) {
      found.push(pattern.toString());
    }
  });
  
  return found;
}

// Message handler for popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkLink') {
    const isBlocked = isUrlBlocked(request.url);
    analyzeLinkWithGemini(request.url).then(analysis => {
      sendResponse({
        isBlocked,
        localMatch: isBlocked,
        geminiAnalysis: analysis
      });
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'checkEmail') {
    const domainSuspicious = isEmailDomainSuspicious(request.senderDomain);
    const suspiciousKeywordsFound = checkSuspiciousKeywords(request.content);
    const patternsFound = checkPhishingPatterns(request.content);
    
    analyzeEmailWithGemini(request.senderDomain, request.content).then(analysis => {
      sendResponse({
        domainSuspicious,
        suspiciousKeywords: suspiciousKeywordsFound,
        patterns: patternsFound,
        geminiAnalysis: analysis
      });
    });
    return true;
  }
  
  if (request.action === 'verifyReport') {
    verifyAndAddToBlocklist(request.url, request.description, request.scamType).then(result => {
      sendResponse(result);
    });
    return true;
  }
  
  if (request.action === 'getStats') {
    sendResponse({
      blockedLinks: phishingLinks.length,
      blockedEmails: phishingEmails.length,
      suspiciousKeywords: suspiciousKeywords.length,
      patterns: phishingPatterns.length
    });
    return true;
  }
  
  if (request.action === 'refreshData') {
    fetchPhishingData().then(() => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.action === 'getStatus') {
    chrome.storage.local.get(['blockedCount', 'scannedCount'], function(data) {
      sendResponse({
        active: true,
        blockedCount: data.blockedCount || 0,
        scannedCount: data.scannedCount || 0,
        rulesLoaded: phishingLinks.length + phishingEmails.length
      });
    });
    return true;
  }

  if (request.action === 'analyzeChatMessage') {
    analyzeChatMessageWithGemini(request.messageText).then((analysis) => {
      sendResponse(analysis);
    });
    return true;
  }

  if (request.action === 'reportScamMessage') {
    (async () => {
      const screenshotProof = request.includeScreenshot
        ? await captureScreenshotProof(sender?.tab)
        : null;

      const reportPayload = {
        platform: request.platform || 'unknown',
        messageText: request.messageText || '',
        analysis: request.analysis || null,
        pageUrl: request.pageUrl || '',
        createdAt: request.createdAt || new Date().toISOString(),
        sourceTabId: sender?.tab?.id ?? null,
        proofFile: screenshotProof || undefined,
      };

      const [localResult, backendResult] = await Promise.all([
        storeScamReport(reportPayload),
        sendReportToSafeNetBackend(reportPayload),
      ]);

      sendResponse({
        success: localResult.success || backendResult.success,
        local: localResult,
        backend: backendResult,
        screenshotAttached: Boolean(screenshotProof),
      });
    })();
    return true;
  }
});

// Initial data fetch
fetchPhishingData();

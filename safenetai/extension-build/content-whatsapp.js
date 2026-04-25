// PhishGuard WhatsApp Content Script

const PHISHGUARD_PLATFORM = "whatsapp";
const analyzedCache = new Map();
let periodicRescanId = null;
const LINK_SCAN_THRESHOLD = 78;
const TRUSTED_DOMAINS = ["google.com", "microsoft.com", "github.com", "nmamit.in", "nitte.edu.in"];

function detectPlatform() {
  const host = window.location.hostname;
  if (host === "web.whatsapp.com") {
    return "whatsapp";
  }
  if (host.includes("linkedin.com") && window.location.pathname.includes("/messaging")) {
    return "linkedin";
  }
  return "unknown";
}

function normalizeMessageText(text) {
  return (text || "").replace(/\s+/g, " ").trim();
}

function hashMessage(text) {
  const input = `${PHISHGUARD_PLATFORM}:${text}`;
  let hash = 5381;
  for (let i = 0; i < input.length; i += 1) {
    hash = (hash * 33) ^ input.charCodeAt(i);
  }
  return String(hash >>> 0);
}

function getChatRoot() {
  return document.querySelector("#main") || document.querySelector("[data-testid='conversation-panel-body']") || document.body;
}

function isLikelyMessageNode(node) {
  if (!(node instanceof HTMLElement)) return false;
  if (node.closest("[contenteditable='true']")) return false;

  const text = normalizeMessageText(node.textContent || "");
  if (text.length < 8) return false;

  return (
    node.closest(".message-in") ||
    node.closest(".message-out") ||
    node.closest("[data-testid='msg-container']")
  );
}

function getIncomingMessageNodes(root = document) {
  const selectors = [
    ".message-in .copyable-text .selectable-text",
    ".message-in .copyable-text",
    ".message-out .copyable-text .selectable-text",
    ".message-out .copyable-text",
    "[data-testid='msg-container'] .copyable-text .selectable-text",
    "[data-testid='msg-container'] .selectable-text",
    "[data-testid='msg-container'] .copyable-text",
    "div.copyable-text[data-pre-plain-text]",
  ];

  const nodes = [];
  const seen = new Set();
  selectors.forEach((selector) => {
    root.querySelectorAll(selector).forEach((node) => {
      if (node && node.textContent && !seen.has(node) && isLikelyMessageNode(node)) {
        seen.add(node);
        nodes.push(node);
      }
    });
  });
  return nodes;
}

function resolveBubbleContainer(node) {
  return node.closest(".message-in") || node.closest(".message-out") || node.parentElement || node;
}

function normalizeCandidateUrl(rawUrl) {
  if (!rawUrl) return null;
  const href = String(rawUrl).trim();
  if (!/^https?:\/\//i.test(href)) return null;

  try {
    const parsed = new URL(href);
    const wrappedUrl = parsed.searchParams.get("u") || parsed.searchParams.get("url") || parsed.searchParams.get("target");
    if (wrappedUrl && /^https?:\/\//i.test(wrappedUrl)) {
      return decodeURIComponent(wrappedUrl);
    }
    return parsed.toString();
  } catch (_error) {
    return null;
  }
}

function buildBlockedPageUrl(targetUrl, result) {
  const riskScore = Number(result?.risk_score || 0);
  const reasons = Array.isArray(result?.explanations) ? result.explanations.slice(0, 5) : [];
  const params = new URLSearchParams({
    url: targetUrl,
    score: String(riskScore),
    level: String(result?.risk_level || "HIGH"),
    eventId: String(result?.event_id || ""),
    reasons: JSON.stringify(reasons),
  });
  return chrome.runtime.getURL(`blocked.html?${params.toString()}`);
}

async function scanLinkWithMlModel(url) {
  const response = await chrome.runtime.sendMessage({
    action: "scanUrlIntel",
    payload: {
      url,
      trusted_domains: TRUSTED_DOMAINS,
    },
  });
  return response;
}

function shouldBlockScanResult(result) {
  if (!result || !result.ok || !result.data) return false;
  const riskScore = Number(result.data.risk_score || 0);
  const recommendation = String(result.data.recommendation || "").toLowerCase();
  return riskScore >= LINK_SCAN_THRESHOLD || recommendation === "block";
}

function installWhatsAppLinkBlocker() {
  document.addEventListener(
    "click",
    async (event) => {
      const anchor = event.target instanceof Element ? event.target.closest("a[href]") : null;
      if (!anchor) return;

      const rawHref = anchor.getAttribute("href") || "";
      const absoluteHref = anchor.href || rawHref;
      const targetUrl = normalizeCandidateUrl(absoluteHref);
      if (!targetUrl) return;

      const targetDomain = (() => {
        try {
          return new URL(targetUrl).hostname.toLowerCase();
        } catch {
          return "";
        }
      })();

      // Ignore WhatsApp internal navigation links.
      if (targetDomain === "web.whatsapp.com" || targetDomain.endsWith(".whatsapp.com")) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();

      try {
        const result = await scanLinkWithMlModel(targetUrl);
        if (shouldBlockScanResult(result)) {
          const blockedPage = buildBlockedPageUrl(targetUrl, result.data);
          window.location.assign(blockedPage);
          return;
        }
      } catch (_error) {
        // If ML scan fails, allow normal navigation to avoid dead click.
      }

      window.location.assign(targetUrl);
    },
    true
  );
}

async function analyzeWithGemini(messageText) {
  try {
    const response = await chrome.runtime.sendMessage({
      action: "analyzeChatMessage",
      platform: PHISHGUARD_PLATFORM,
      messageText,
    });

    if (!response || response.error) {
      return {
        isScam: false,
        riskScore: 0,
        scamType: "unknown",
        explanation: "AI analysis unavailable right now.",
      };
    }

    return response;
  } catch (error) {
    console.error("PhishGuard WhatsApp Gemini error:", error);
    return {
      isScam: false,
      riskScore: 0,
      scamType: "unknown",
      explanation: "AI analysis unavailable right now.",
    };
  }
}

function handleReport(messageText, analysis) {
  chrome.runtime.sendMessage({
    action: "reportScamMessage",
    platform: PHISHGUARD_PLATFORM,
    messageText,
    analysis,
    pageUrl: window.location.href,
    createdAt: new Date().toISOString(),
  });
}

function injectWarningUI(messageNode, analysis, messageText) {
  const bubble = resolveBubbleContainer(messageNode);
  if (!bubble || bubble.querySelector(".phishguard-warning")) {
    return;
  }

  const warning = document.createElement("div");
  warning.className = "phishguard-warning";
  warning.style.cssText = [
    "margin-top: 8px",
    "padding: 12px 13px",
    "border-radius: 12px",
    "background: linear-gradient(135deg, rgba(33, 10, 16, 0.96), rgba(66, 16, 24, 0.9))",
    "border: 1px solid rgba(251, 113, 133, 0.58)",
    "box-shadow: 0 10px 24px rgba(0, 0, 0, 0.35)",
    "color: #ffe4eb",
    "font-size: 12px",
    "line-height: 1.45",
    "font-family: Segoe UI, Arial, sans-serif",
  ].join(";");

  const top = document.createElement("div");
  top.style.cssText = "display:flex;align-items:center;justify-content:space-between;gap:8px;";

  const title = document.createElement("div");
  title.textContent = "SafeNet Alert";
  title.style.cssText = "font-weight: 800; color: #fecdd3;";

  const score = document.createElement("span");
  score.textContent = `Risk ${Math.round(Number(analysis.riskScore || 0))}%`;
  score.style.cssText =
    "font-size:10px;font-weight:700;padding:3px 8px;border-radius:999px;background:rgba(251,113,133,0.2);border:1px solid rgba(251,113,133,0.45);color:#fecdd3;";

  const details = document.createElement("div");
  details.textContent = `Type: ${analysis.scamType || "phishing"}`;
  details.style.cssText = "margin-top:5px;color:#fecdd3;font-weight:600;";

  const reason = document.createElement("div");
  reason.textContent = analysis.explanation || "Suspicious scam pattern detected.";
  reason.style.cssText = "margin-top: 5px; color: #ffd5df;";

  const actions = document.createElement("div");
  actions.style.cssText = "display:flex;gap:8px;flex-wrap:wrap;margin-top:9px;";

  const reportBtn = document.createElement("button");
  reportBtn.type = "button";
  reportBtn.textContent = "Report Incident";
  reportBtn.style.cssText = [
    "padding: 5px 10px",
    "border: 1px solid rgba(251, 113, 133, 0.7)",
    "background: rgba(251, 113, 133, 0.24)",
    "color: #ffe7e7",
    "border-radius: 8px",
    "cursor: pointer",
    "font-size: 11px",
    "font-weight: 700",
  ].join(";");

  const dashboardBtn = document.createElement("button");
  dashboardBtn.type = "button";
  dashboardBtn.textContent = "Open Dashboard";
  dashboardBtn.style.cssText = [
    "padding: 5px 10px",
    "border: 1px solid rgba(45, 212, 191, 0.6)",
    "background: rgba(45, 212, 191, 0.18)",
    "color: #a7f3d0",
    "border-radius: 8px",
    "cursor: pointer",
    "font-size: 11px",
    "font-weight: 700",
  ].join(";");

  reportBtn.addEventListener("click", () => {
    handleReport(messageText, analysis);
    reportBtn.textContent = "Reported";
    reportBtn.disabled = true;
    reportBtn.style.opacity = "0.7";
    reportBtn.style.cursor = "default";
  });

  dashboardBtn.addEventListener("click", () => {
    window.open("http://localhost:3000/dashboard", "_blank");
  });

  top.appendChild(title);
  top.appendChild(score);
  warning.appendChild(top);
  warning.appendChild(details);
  warning.appendChild(reason);
  actions.appendChild(reportBtn);
  actions.appendChild(dashboardBtn);
  warning.appendChild(actions);
  bubble.appendChild(warning);
}

async function processMessageNode(node) {
  if (!node || node.dataset.phishguardAnalyzed === "1") {
    return;
  }

  const messageText = normalizeMessageText(node.textContent || "");
  if (!messageText || messageText.length < 6) {
    node.dataset.phishguardAnalyzed = "1";
    return;
  }

  const hash = hashMessage(messageText);
  node.dataset.phishguardHash = hash;

  if (analyzedCache.has(hash)) {
    const cachedResult = analyzedCache.get(hash);
    node.dataset.phishguardAnalyzed = "1";
    if (cachedResult?.isScam) {
      injectWarningUI(node, cachedResult, messageText);
    }
    return;
  }

  const analysis = await analyzeWithGemini(messageText);
  const lowerText = messageText.toLowerCase();
  const suspiciousWords = [
    "urgent",
    "verify",
    "account",
    "suspended",
    "suspend",
    "blocked",
    "block",
    "permanent block",
    "avoid",
    "otp",
    "password",
    "bank",
    "kyc",
    "fee",
    "payment",
    "click",
    "shortlisted",
    "internship",
  ];
  let score = 0;
  suspiciousWords.forEach((word) => {
    if (lowerText.includes(word)) score += 1;
  });
  if (lowerText.includes("http://") || lowerText.includes("https://")) score += 2;

  const hasSuspensionPattern =
    (lowerText.includes("account") && (lowerText.includes("suspend") || lowerText.includes("blocked"))) ||
    (lowerText.includes("verify") && lowerText.includes("account"));
  if (hasSuspensionPattern) score += 2;

  const fallbackAnalysis = {
    isScam: score >= 3,
    riskScore: Math.min(95, 40 + score * 7),
    scamType: "phishing",
    explanation: "Multiple scam indicators detected locally (urgency, credential/payment cues, and link patterns).",
  };

  const finalAnalysis = analysis.isScam ? analysis : fallbackAnalysis;
  analyzedCache.set(hash, finalAnalysis);
  node.dataset.phishguardAnalyzed = "1";

  if (finalAnalysis.isScam) {
    injectWarningUI(node, finalAnalysis, messageText);
  }
}

function observeMessages() {
  const root = getChatRoot();
  if (!root) {
    return;
  }

  getIncomingMessageNodes(root).forEach((node) => {
    processMessageNode(node);
  });

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((addedNode) => {
        if (!(addedNode instanceof HTMLElement)) {
          return;
        }

        if (
          addedNode.matches &&
          addedNode.matches(
            ".message-in .copyable-text, .message-in .selectable-text, .message-out .copyable-text, .message-out .selectable-text, [data-testid='msg-container'] .copyable-text, [data-testid='msg-container'] .selectable-text"
          )
        ) {
          processMessageNode(addedNode);
        }

        getIncomingMessageNodes(addedNode).forEach((node) => {
          processMessageNode(node);
        });
      });
    }
  });

  observer.observe(root, {
    childList: true,
    subtree: true,
  });

  if (periodicRescanId) {
    clearInterval(periodicRescanId);
  }

  periodicRescanId = setInterval(() => {
    getIncomingMessageNodes(getChatRoot()).forEach((node) => {
      processMessageNode(node);
    });
  }, 2000);
}

(function init() {
  const platform = detectPlatform();
  if (platform !== "whatsapp") {
    return;
  }

  installWhatsAppLinkBlocker();
  observeMessages();
})();

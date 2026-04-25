// PhishGuard LinkedIn Messaging Content Script

const PHISHGUARD_PLATFORM = "linkedin";
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

function getThreadRoot() {
  return (
    document.querySelector(".msg-s-message-list-content") ||
    document.querySelector(".msg-thread") ||
    document.querySelector("[data-view-name*='messaging']") ||
    document.querySelector("main") ||
    document.body
  );
}

function isLikelyChatNode(node) {
  if (!(node instanceof HTMLElement)) return false;
  if (node.closest("[contenteditable='true']")) return false;
  if (node.closest(".msg-form__contenteditable")) return false;
  if (node.closest(".msg-overlay-list-bubble")) return false;

  const text = normalizeMessageText(node.textContent || "");
  if (text.length < 12) return false;

  return (
    node.closest("li.msg-s-message-list__event") ||
    node.closest(".msg-s-event-listitem") ||
    node.closest(".msg-thread") ||
    node.closest("[data-view-name*='messaging']")
  );
}

function getIncomingMessageNodes(root = document) {
  const selectors = [
    "li.msg-s-message-list__event .msg-s-event-listitem__body",
    "li.msg-s-message-list__event .msg-s-event-listitem__message-bubble",
    "li.msg-s-message-list__event p",
    ".msg-s-event-listitem__body",
    ".msg-s-event-listitem__message-bubble",
    ".msg-thread p",
    "main .msg-thread p",
    "[data-view-name*='messaging'] p",
    "[data-view-name*='messaging'] a[href^='http']",
  ];

  const nodes = [];
  const seen = new Set();
  selectors.forEach((selector) => {
    root.querySelectorAll(selector).forEach((node) => {
      if (node && node.textContent && !seen.has(node) && isLikelyChatNode(node)) {
        seen.add(node);
        nodes.push(node);
      }
    });
  });
  return nodes;
}

function resolveBubbleContainer(node) {
  return (
    node.closest("li.msg-s-message-list__event") ||
    node.closest(".msg-s-event-listitem") ||
    node.parentElement ||
    node
  );
}

function normalizeCandidateUrl(rawUrl) {
  if (!rawUrl) return null;
  const href = String(rawUrl).trim();
  if (!/^https?:\/\//i.test(href)) return null;

  try {
    const parsed = new URL(href);
    const wrappedUrl = parsed.searchParams.get("url") || parsed.searchParams.get("u") || parsed.searchParams.get("target");
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

function installLinkedInLinkBlocker() {
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

      // Ignore LinkedIn internal navigation links.
      if (targetDomain === "linkedin.com" || targetDomain === "www.linkedin.com" || targetDomain.endsWith(".linkedin.com")) {
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

function localScamHeuristic(messageText) {
  const text = messageText.toLowerCase();
  const suspiciousTerms = [
    "shortlisted",
    "internship",
    "registration",
    "fee",
    "refundable",
    "urgent",
    "confirm your seat",
    "whatsapp",
    "selection",
    "microsoft-powered",
    "pay",
    "onboarding",
  ];

  let signalCount = 0;
  suspiciousTerms.forEach((term) => {
    if (text.includes(term)) {
      signalCount += 1;
    }
  });

  const hasExternalLink = text.includes("http://") || text.includes("https://") || text.includes("chat.whatsapp.com");
  const hasMoneyCue = /₹\s?\d+|\brs\.?\s?\d+|\b\d+\s?(inr|rupees?)\b/i.test(messageText);
  const score = signalCount + (hasExternalLink ? 2 : 0) + (hasMoneyCue ? 2 : 0);

  if (score >= 5) {
    return {
      isScam: true,
      riskScore: Math.min(95, 45 + score * 6),
      scamType: "job scam",
      explanation: "Multiple internship scam indicators found: fee request, urgency, and external recruitment link.",
    };
  }

  return {
    isScam: false,
    riskScore: 0,
    scamType: "unknown",
    explanation: "No strong local scam indicators.",
  };
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
    console.error("PhishGuard LinkedIn Gemini error:", error);
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
    "padding: 12px 14px",
    "border-radius: 12px",
    "background: linear-gradient(135deg, #fff1f2, #ffe4e6)",
    "border: 1px solid rgba(239, 68, 68, 0.45)",
    "box-shadow: 0 10px 24px rgba(0, 0, 0, 0.10)",
    "color: #7f1d1d",
    "font-size: 12px",
    "line-height: 1.45",
    "font-family: Segoe UI, Arial, sans-serif",
  ].join(";");

  const top = document.createElement("div");
  top.style.cssText = "display:flex;align-items:center;justify-content:space-between;gap:8px;";

  const title = document.createElement("div");
  title.textContent = "SafeNet Alert";
  title.style.cssText = "font-weight: 800; color: #b91c1c;";

  const score = document.createElement("span");
  score.textContent = `Risk ${Math.round(Number(analysis.riskScore || 0))}%`;
  score.style.cssText =
    "font-size:10px;font-weight:700;padding:3px 8px;border-radius:999px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.35);color:#991b1b;";

  const details = document.createElement("div");
  details.textContent = `Type: ${analysis.scamType}`;
  details.style.cssText = "font-weight: 700; color: #991b1b; margin-top: 6px;";

  const reason = document.createElement("div");
  reason.textContent = analysis.explanation || "Suspicious scam pattern detected.";
  reason.style.cssText = "margin-top: 6px; color: #7f1d1d;";

  const actions = document.createElement("div");
  actions.style.cssText = "display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;";

  const reportBtn = document.createElement("button");
  reportBtn.type = "button";
  reportBtn.textContent = "Report Incident";
  reportBtn.style.cssText = [
    "padding: 6px 12px",
    "border: 1px solid #dc2626",
    "background: #dc2626",
    "color: #ffffff",
    "border-radius: 8px",
    "cursor: pointer",
    "font-size: 11px",
    "font-weight: 600",
  ].join(";");

  const dashboardBtn = document.createElement("button");
  dashboardBtn.type = "button";
  dashboardBtn.textContent = "Open Dashboard";
  dashboardBtn.style.cssText = [
    "padding: 6px 12px",
    "border: 1px solid rgba(15, 118, 110, 0.4)",
    "background: rgba(45, 212, 191, 0.18)",
    "color: #0f766e",
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
  const fallback = localScamHeuristic(messageText);
  const finalAnalysis = analysis.isScam ? analysis : fallback;

  analyzedCache.set(hash, finalAnalysis);
  node.dataset.phishguardAnalyzed = "1";

  if (finalAnalysis.isScam) {
    injectWarningUI(node, finalAnalysis, messageText);
  }
}

function observeMessages() {
  const root = getThreadRoot();
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
            "li.msg-s-message-list__event, .msg-s-event-listitem__body, .msg-s-event-listitem__message-bubble, .msg-thread p, [data-view-name*='messaging'] p"
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
    getIncomingMessageNodes(getThreadRoot()).forEach((node) => {
      processMessageNode(node);
    });
  }, 2000);
}

(function init() {
  const platform = detectPlatform();
  if (platform !== "linkedin") {
    return;
  }

  installLinkedInLinkBlocker();
  observeMessages();
})();

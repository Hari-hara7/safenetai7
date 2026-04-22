const DEFAULT_BASE_URL = "http://localhost:3000";

function showToast(message, variant) {
  const el = document.getElementById("toast");
  el.classList.remove("ok", "error");
  el.dataset.state = "show";
  if (variant) el.classList.add(variant);
  el.textContent = message;
  window.clearTimeout(showToast._t);
  showToast._t = window.setTimeout(() => {
    el.dataset.state = "";
    el.textContent = "";
  }, 4500);
}

async function getBaseUrl() {
  const res = await chrome.storage.sync.get({ baseUrl: DEFAULT_BASE_URL });
  const raw = String(res.baseUrl || DEFAULT_BASE_URL).trim();
  return raw.replace(/\/+$/, "");
}

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function openUrl(url) {
  await chrome.tabs.create({ url });
}

document.addEventListener("DOMContentLoaded", async () => {
  const tabUrlEl = document.getElementById("tab-url");
  const apiBaseEl = document.getElementById("api-base");
  const messageEl = document.getElementById("message");
  const reportBtn = document.getElementById("report");
  const openDashBtn = document.getElementById("scan-open-dashboard");
  const openOptions = document.getElementById("open-options");

  const [tabUrl, baseUrl] = await Promise.all([getActiveTabUrl(), getBaseUrl()]);

  tabUrlEl.textContent = tabUrl || "—";
  tabUrlEl.title = tabUrl || "";
  apiBaseEl.textContent = baseUrl;

  openOptions.addEventListener("click", async (e) => {
    e.preventDefault();
    await chrome.runtime.openOptionsPage();
  });

  openDashBtn.addEventListener("click", async () => {
    await openUrl(`${baseUrl}/dashboard`);
  });

  reportBtn.addEventListener("click", async () => {
    const messageText = String(messageEl.value || "").trim();
    if (messageText.length < 6) {
      showToast("Please add at least a short message (6+ characters).", "error");
      return;
    }

    reportBtn.disabled = true;
    openDashBtn.disabled = true;

    try {
      const payload = {
        platform: "chrome_extension",
        messageText,
        pageUrl: tabUrl || undefined,
        createdAt: new Date().toISOString(),
      };

      const resp = await fetch(`${baseUrl}/api/extension/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const json = await resp.json().catch(() => ({}));

      if (!resp.ok || !json?.ok) {
        const detail = json?.error ? ` ${json.error}` : "";
        showToast(`Report failed.${detail}`, "error");
        return;
      }

      messageEl.value = "";
      showToast("Report saved. Thank you for strengthening the community feed.", "ok");
    } catch (err) {
      showToast(`Network error: ${err instanceof Error ? err.message : "unknown"}`, "error");
    } finally {
      reportBtn.disabled = false;
      openDashBtn.disabled = false;
    }
  });
});


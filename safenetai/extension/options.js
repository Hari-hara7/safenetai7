const DEFAULT_BASE_URL = "http://localhost:3000";

function setStatus(text, variant) {
  const el = document.getElementById("status");
  el.classList.remove("error");
  if (variant) el.classList.add(variant);
  el.textContent = text || "";
}

function normalizeBaseUrl(raw) {
  const value = String(raw || "").trim();
  if (!value) return DEFAULT_BASE_URL;
  return value.replace(/\/+$/, "");
}

async function load() {
  const { baseUrl } = await chrome.storage.sync.get({ baseUrl: DEFAULT_BASE_URL });
  document.getElementById("baseUrl").value = normalizeBaseUrl(baseUrl);
}

document.addEventListener("DOMContentLoaded", async () => {
  const baseUrlInput = document.getElementById("baseUrl");
  const saveBtn = document.getElementById("save");
  const resetBtn = document.getElementById("reset");

  await load();

  saveBtn.addEventListener("click", async () => {
    setStatus("");
    const baseUrl = normalizeBaseUrl(baseUrlInput.value);

    try {
      // Validate URL shape
      // eslint-disable-next-line no-new
      new URL(baseUrl);
      await chrome.storage.sync.set({ baseUrl });
      setStatus("Saved.");
    } catch {
      setStatus("Please enter a valid URL (example: https://example.com).", "error");
    }
  });

  resetBtn.addEventListener("click", async () => {
    baseUrlInput.value = DEFAULT_BASE_URL;
    await chrome.storage.sync.set({ baseUrl: DEFAULT_BASE_URL });
    setStatus("Reset to default.");
  });
});


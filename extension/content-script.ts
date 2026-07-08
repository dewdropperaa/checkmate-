/** Content script — passive page context bridge (no scanning logic yet). */

const SENTINEL_ATTR = "data-sentinel-scan";

function markPage(): void {
  if (document.documentElement.getAttribute(SENTINEL_ATTR)) {
    return;
  }
  document.documentElement.setAttribute(SENTINEL_ATTR, "active");
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "PING") {
    sendResponse({ ok: true, url: window.location.href });
    return true;
  }
  return false;
});

markPage();

export {};

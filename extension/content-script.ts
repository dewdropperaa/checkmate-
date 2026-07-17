/** Content script — passive page context bridge (no scanning logic yet). */

const CHECKMATE_ATTR = "data-checkmate";

function markPage(): void {
  if (document.documentElement.getAttribute(CHECKMATE_ATTR)) {
    return;
  }
  document.documentElement.setAttribute(CHECKMATE_ATTR, "active");
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

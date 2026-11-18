// Ringtail extension service worker: the right-click menu (ADR 0005).
//
// The context menu click hands us the selected text directly (info.selectionText), so the
// extension needs no content scripts and never reads the page. The text is parked in
// chrome.storage.session for the side panel to pick up; it's never sent anywhere until the
// user presses "Draft and prove" in the panel.

const MENU_ID = "ringtail-detect";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Detect with Ringtail",
    contexts: ["selection"],
  });
  // Clicking the toolbar icon opens the panel too.
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID || !info.selectionText) return;
  // sidePanel.open must run inside the click's user gesture, so call it before any await.
  if (tab && tab.windowId !== undefined) {
    chrome.sidePanel.open({ windowId: tab.windowId }).catch(() => {});
  }
  chrome.storage.session.set({ pendingSelection: { text: info.selectionText, at: Date.now() } });
});

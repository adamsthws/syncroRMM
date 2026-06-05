browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    const url = details.url;

    // Match any ScreenConnect host URL containing a rustdesk:// deep link
    // e.g. https://*.screenconnect.com/Host#Access///rustdesk://connect/<ID>/Join
    const match = url.match(/rustdesk:\/\/connect\/(\d+)\/Join/);
    if (match) {
      const rustdeskUrl = `rustdesk://connect/${match[1]}`;
      browser.tabs.update(details.tabId, { url: rustdeskUrl });
      return { cancel: true };
    }
  },
  {
    urls: ["*://*.screenconnect.com/*"]
  },
  ["blocking"]
);

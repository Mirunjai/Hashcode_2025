// Runs whenever a tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    console.log("URL detected:", tab.url);
    chrome.storage.local.set({ lastUrl: tab.url });
  }
});
// background.js

// Simple local threat scoring function
function calculateThreatScore(url) {
  let score = 0;

  // 1️⃣ HTTPS check
  if (!url.startsWith('https://')) score += 20;

  // 2️⃣ Basic blacklist check
  const blacklist = ["malicious.com", "phishingsite.net"];
  if (blacklist.some(domain => url.includes(domain))) score += 50;

  // 3️⃣ IP address in URL
  const ipRegex = /\b\d{1,3}(\.\d{1,3}){3}\b/;
  if (ipRegex.test(url)) score += 30;

  // 4️⃣ Long URLs
  if (url.length > 75) score += 10;

  // 5️⃣ Suspicious special characters
  const specialChars = /[!@#$%^&*(),?":{}|<>]/;
  if (specialChars.test(url)) score += 10;

  return Math.min(score, 100);
}

//  Listen for tab updates (runs once when page fully loads)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    console.log("URL detected:", tab.url);

    const threatScore = calculateThreatScore(tab.url);

    // Save data for popup to use
    chrome.storage.local.set({
      lastURL: tab.url,
      lastScore: threatScore
    });

    console.log("Threat score:", threatScore);
  }
});


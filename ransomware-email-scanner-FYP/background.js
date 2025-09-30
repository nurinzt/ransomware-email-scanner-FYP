const API_KEY = "a9dda1ce37c1cb6b3f293e30b4300163a97e4be7798df1b14284d379ef7aeadd"; // Replace with your key
function toBase64Url(str) {
  try {
    // btoa expects binary string; encodeURIComponent handles unicode
    const base64 = btoa(unescape(encodeURIComponent(str)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  } catch (_) {
    return null;
  }
}

//function to scan a URL using VirusTotal API
async function scanURL(url) {
  const res = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": API_KEY,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: `url=${encodeURIComponent(url)}`
  });
  const data = await res.json();
  const analysisId = data.data.id;
  //get scan result using analysisId
  const result = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
    headers: { "x-apikey": API_KEY }
  });
  const analysis = await result.json();

  // Fetch URL object to get per-engine results using base64url(url)
  const urlId = toBase64Url(url);
  let urlObject = null;
  try {
    if (urlId) {
      const urlRes = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(urlId)}`, {
        headers: { "x-apikey": API_KEY }
      });
      if (urlRes.ok) {
        urlObject = await urlRes.json();
      }
    }
  } catch (_) {}

  return { analysis, urlObject };
}

//function to scan a file hash using VirusTotal 
async function scanHash(hash) {
  const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { "x-apikey": API_KEY }
  });
  return await res.json();
}

//Listen for messages from contentPopup.js
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "scan-url") {
    scanURL(msg.url).then(sendResponse);
    return true;
  }
  if (msg.type === "scan-hash") {
    scanHash(msg.hash).then(sendResponse);
    return true;
  }
});

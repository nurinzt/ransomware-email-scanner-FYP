// Import threat cache functions
importScripts('threatCache.js');

const API_KEY =
  "a9dda1ce37c1cb6b3f293e30b4300163a97e4be7798df1b14284d379ef7aeadd"; // Replace with your VirusTotal API key

// Get URL report directly (if previously scanned) - faster than submitting new analysis
async function getURLReport(url) {
  try {
    // Hash the URL using SHA-256
    const encoder = new TextEncoder();
    const data = encoder.encode(url);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const urlHash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlHash}`, {
      headers: { "x-apikey": API_KEY },
    });
    
    if (res.status === 200) {
      return await res.json(); // Existing report found
    } else if (res.status === 404) {
      return null; // No existing report, need to submit
    } else {
      const text = await res.text();
      console.error("Error fetching URL report:", res.status, text);
      return { error: `VT returned ${res.status}: ${text}` };
    }
  } catch (e) {
    console.error("Exception fetching URL report:", e);
    return { error: e.message || String(e) };
  }
}

// Scan a URL via VirusTotal (polls until completed or timeout)
async function scanURL(url) {
  try {
    // STEP 1: Check local cache first (fastest)
    const cachedResult = await getCachedURL(url);
    if (cachedResult) {
      console.log("✅ Found URL in local cache:", url);
      return cachedResult; // Return cached result immediately
    }
    
    // STEP 2: Try to get existing VirusTotal report (faster than new analysis)
    const existingReport = await getURLReport(url);
    if (existingReport && existingReport.data && !existingReport.error) {
      console.log("Found existing VirusTotal report for:", url);
      // Cache the result for future use
      await cacheURL(url, existingReport);
      return existingReport;
    }
    
    // STEP 3: If no existing report, submit for analysis
    console.log("Submitting URL for analysis:", url);
    const res = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    
    if (!res.ok) {
      const errorText = await res.text();
      console.error("Error submitting URL:", res.status, errorText);
      return { error: `Failed to submit URL: ${res.status} - ${errorText}` };
    }
    
    const data = await res.json();
    if (!data?.data?.id) {
      return { error: "Invalid response from VirusTotal: missing analysis ID" };
    }
    
    const analysisId = data.data.id;

    // Poll for result (max 10 tries, 1s interval)
    let result;
    for (let i = 0; i < 10; i++) {
      result = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: { "x-apikey": API_KEY },
        }
      );
      const json = await result.json();
      if (json.data?.attributes?.status === "completed") {
        console.log("Analysis completed for:", url);
        // Cache the completed analysis result
        await cacheURL(url, json);
        return json;
      }
      await new Promise((r) => setTimeout(r, 1000)); // wait 1s
    }
    // If not completed after 10s, return last response
    const lastResult = result ? await result.json() : { error: "No response from VT" };
    console.warn("Analysis not completed after 10s for:", url, lastResult);
    // Cache even incomplete results if they have data
    if (lastResult && lastResult.data && !lastResult.error) {
      await cacheURL(url, lastResult);
    }
    return lastResult;
  } catch (e) {
    console.error("Exception in scanURL:", e);
    return { error: e.message || String(e) };
  }
}

// Scan a file hash via VirusTotal
async function scanHash(hash) {
  try {
    // STEP 1: Check local cache first
    const cachedResult = await getCachedHash(hash);
    if (cachedResult) {
      console.log("✅ Found hash in local cache:", hash);
      return cachedResult;
    }
    
    // STEP 2: Query VirusTotal API
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": API_KEY },
    });
    
    if (res.status === 200) {
      const result = await res.json();
      // Cache successful results
      await cacheHash(hash, result);
      return result;
    } else if (res.status === 404) {
      const notFound = { exists: false };
      // Cache "not found" results too to avoid repeated API calls
      await cacheHash(hash, notFound);
      return notFound;
    } else {
      const text = await res.text();
      return { error: `VT returned ${res.status}: ${text}` };
    }
  } catch (e) {
    console.error("Exception in scanHash:", e);
    return { error: e.message || String(e) };
  }
}
// Upload file to VirusTotal (expects base64-encoded content from popup.js)
async function vtUploadFile(filename, mime, base64data) {
  try {
    // Convert base64 back to a Blob
    const binary = atob(base64data);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    const blob = new Blob([bytes], { type: mime });

    const form = new FormData();
    form.append("file", blob, filename);

    const r = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: { "x-apikey": API_KEY },
      body: form,
    });

    if (r.status === 200 || r.status === 201) {
      const json = await r.json();
      return { success: true, result: json };
    } else {
      const text = await r.text();
      return { error: `VT upload ${r.status}: ${text}` };
    }
  } catch (e) {
    return { error: e.message || String(e) };
  }
}

// Fetch attachment via background (with cookies)
async function fetchAttachment(url) {
  try {
    const res = await fetch(url, { credentials: "include" });
    if (!res.ok) return { error: "Failed to fetch attachment: " + res.status };
    const buffer = await res.arrayBuffer();
    return { success: true, buffer };
  } catch (e) {
    return { error: e.message || String(e) };
  }
}

// ========== Message listener (handles all actions) ==========
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "scan-url") {
      const res = await scanURL(msg.url);
      sendResponse(res);
    } else if (msg.type === "scan-hash") {
      const res = await scanHash(msg.hash);
      sendResponse(res);
    } else if (msg.action === "check-hash") {
      // Manual popup check for hash
      const report = await scanHash(msg.hash);
      sendResponse(report);
    } else if (msg.action === "upload-file") {
      // Manual popup upload
      const upload = await vtUploadFile(msg.filename, msg.mime, msg.base64);
      sendResponse(upload);
    } else if (msg.action === "fetch-attachment") {
      const result = await fetchAttachment(msg.url);
      sendResponse(result);
    } else if (msg.action === "clear-cache") {
      // Admin action to clear cache
      await clearCache();
      sendResponse({ success: true, message: "Cache cleared" });
    } else if (msg.action === "cache-stats") {
      // Get cache statistics
      const stats = await getCacheStats();
      sendResponse({ success: true, stats });
    } else {
      sendResponse({ error: "Unknown action" });
    }
  })();

  // Keep channel open for async responses
  return true;
});

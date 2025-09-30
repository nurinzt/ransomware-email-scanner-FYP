//creates a fullscreen overlay with message and loading gif
function createOverlay(message = "Processing...", isLoading = true) {
  const old = document.getElementById("email-scan-overlay");
  if (old) old.remove();

  const overlay = document.createElement("div");
  overlay.id = "email-scan-overlay";
  overlay.style = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.6); color: white; font-size: 18px;
    display: flex; flex-direction: column; justify-content: center; align-items: center;
    z-index: 99999;
  `;

  if (isLoading) {
    const img = document.createElement("img");
    img.src = chrome.runtime.getURL("icons/loading-circle.gif");
    img.style = "width: 60px; margin-bottom: 16px;";
    overlay.appendChild(img);
  }

  const text = document.createElement("div");
  text.id = "email-scan-overlay-message";
  text.textContent = message;
  overlay.appendChild(text);

  const buttons = document.createElement("div");
  buttons.style = "margin-top: 12px; display: flex; gap: 8px;";

  const viewBtn = document.createElement("button");
  viewBtn.id = "email-scan-view-details";
  viewBtn.textContent = "View details";
  viewBtn.style = "padding: 6px 10px; border-radius: 4px; border: none; cursor: pointer;";
  viewBtn.hidden = true; // will show after results are ready
  buttons.appendChild(viewBtn);

  const closeBtn = document.createElement("button");
  closeBtn.id = "email-scan-close";
  closeBtn.textContent = "Close";
  closeBtn.style = "padding: 6px 10px; border-radius: 4px; border: none; cursor: pointer;";
  closeBtn.addEventListener("click", removeOverlay);
  buttons.appendChild(closeBtn);

  overlay.appendChild(buttons);

  const details = document.createElement("div");
  details.id = "email-scan-overlay-details";
  details.style = "max-width: 80%; margin-top: 12px; font-size: 14px; text-align: left; white-space: pre-wrap; background: rgba(0,0,0,0.25); padding: 10px; border-radius: 6px;";
  details.hidden = true; // toggle on demand
  overlay.appendChild(details);
  document.body.appendChild(overlay);
}

//remove overlay from the page
function removeOverlay() {
  const el = document.getElementById("email-scan-overlay");
  if (el) el.remove();
}

//generates a SHA-256 hash of provided ArrayBuffer or string
async function getSHA256(input) {
  const buffer = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}

//Try to discover attachment links on Gmail/Outlook pages
function findAttachmentLinks() {
  const links = [];

  // Gmail: anchor href contains view=att and filename
  const gmailLinks = document.querySelectorAll("a[href*='view=att']");
  gmailLinks.forEach(a => {
    try {
      const url = new URL(a.href, location.href);
      const filename = url.searchParams.get("filename") || a.getAttribute("download") || a.textContent?.trim() || "attachment";
      links.push({ name: filename, url: url.toString() });
    } catch {}
  });

  // Outlook Web: look for links that include attachment or download parameters
  const outlookLinks = document.querySelectorAll("a[href*='attachment'], a[href*='download']");
  outlookLinks.forEach(a => {
    try {
      const url = new URL(a.href, location.href);
      const filename = a.getAttribute("download") || a.textContent?.trim() || url.pathname.split("/").pop() || "attachment";
      links.push({ name: filename, url: url.toString() });
    } catch {}
  });

  // Deduplicate by URL
  const seen = new Set();
  return links.filter(l => {
    if (seen.has(l.url)) return false;
    seen.add(l.url);
    return true;
  });
}

async function fetchAttachmentArrayBuffer(url) {
  const res = await fetch(url, { credentials: "include" });
  if (!res.ok) throw new Error(`Failed to fetch attachment: ${res.status}`);
  return await res.arrayBuffer();
}

async function scanEmail() {
  createOverlay("Scanning this email for threats...", true);
  let maliciousFound = false;
  const urlSummaries = [];
  const attachmentSummaries = [];

  const emailBody = document.querySelector(".ii.gt")?.innerText || ""; //gmail email body text
  const urls = [...emailBody.matchAll(/https?:\/\/[^\s<>\"]+/g)].map(m => m[0]); //extract URLs
  const attachmentLinks = findAttachmentLinks();

  //scan all URLs via background.js
  for (const url of urls) {
    await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: "scan-url", url }, res => {
        try {
          const analysis = res?.analysis;
          const urlObject = res?.urlObject;
          const stats = analysis?.data?.attributes?.stats || analysis?.data?.attributes?.results_stats || analysis?.data?.attributes?.last_analysis_stats;
          const malCount = stats?.malicious || 0;
          const suspCount = stats?.suspicious || 0;

          const results = (urlObject?.data?.attributes?.last_analysis_results) || (analysis?.data?.attributes?.results) || {};
          const engines = Object.entries(results)
            .filter(([, r]) => r?.category === "malicious" || r?.category === "suspicious")
            .map(([engine, r]) => ({ engine, category: r?.category, result: r?.result }));

          if ((malCount + suspCount) > 0) maliciousFound = true;
          urlSummaries.push({ url, malCount, suspCount, engines });
        } catch (_) {}
        resolve();
      });
    });
  }

  //scan discovered attachments by hashing their content
  for (const { name, url } of attachmentLinks) {
    try {
      const buf = await fetchAttachmentArrayBuffer(url);
      const hash = await getSHA256(buf);
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "scan-hash", hash, name }, res => {
          try {
            const attrs = res?.data?.attributes;
            const stats = attrs?.last_analysis_stats || {};
            const malCount = stats?.malicious || 0;
            const suspCount = stats?.suspicious || 0;
            const label = attrs?.popular_threat_classification?.suggested_threat_label || null;
            const results = attrs?.last_analysis_results || {};
            const engines = Object.entries(results)
              .filter(([, r]) => r?.category === "malicious" || r?.category === "suspicious")
              .map(([engine, r]) => ({ engine, category: r?.category, result: r?.result }));
            if ((malCount + suspCount) > 0) maliciousFound = true;
            attachmentSummaries.push({ name, hash, malCount, suspCount, label, engines });
          } catch (_) {}
          resolve();
        });
      });
    } catch (e) {
      // Ignore fetch errors and continue with other attachments
    }
  }

  const resultMsg = maliciousFound
    ? "⚠️ This email may contain threats."
    : "✅ No threats found in this email.";

  createOverlay(resultMsg, false);

  // Prepare details content generator
  function renderDetails() {
    const detailsEl = document.getElementById("email-scan-overlay-details");
    if (!detailsEl) return;
    const lines = [];

    if (urlSummaries.length) {
      lines.push("URLs:");
      urlSummaries.forEach(s => {
        lines.push(`${s.url}`);
        lines.push(`  Malicious: ${s.malCount} | Suspicious: ${s.suspCount}`);
        if (s.engines?.length) {
          const top = s.engines.slice(0, 8);
          top.forEach(e => lines.push(`    - ${e.engine}: ${e.category}${e.result ? ` (${e.result})` : ""}`));
          if (s.engines.length > top.length) lines.push(`    - ...and ${s.engines.length - top.length} more engines`);
        }
        lines.push("");
      });
    }

    if (attachmentSummaries.length) {
      lines.push("Attachments:");
      attachmentSummaries.forEach(a => {
        lines.push(`${a.name} (${a.hash})`);
        if (a.label) lines.push(`  Threat label: ${a.label}`);
        lines.push(`  Malicious: ${a.malCount} | Suspicious: ${a.suspCount}`);
        if (a.engines?.length) {
          const top = a.engines.slice(0, 8);
          top.forEach(e => lines.push(`    - ${e.engine}: ${e.category}${e.result ? ` (${e.result})` : ""}`));
          if (a.engines.length > top.length) lines.push(`    - ...and ${a.engines.length - top.length} more engines`);
        }
        lines.push("");
      });
    }

    detailsEl.textContent = lines.join("\n");
  }

  // Hook up buttons
  const viewBtn = document.getElementById("email-scan-view-details");
  const detailsEl = document.getElementById("email-scan-overlay-details");
  if (viewBtn && detailsEl) {
    viewBtn.hidden = false; // always show after scan
    viewBtn.addEventListener("click", () => {
      if (detailsEl.hidden) {
        renderDetails();
        if (!detailsEl.textContent) {
          detailsEl.textContent = "No details available yet. Try again in a moment.";
        }
      }
      detailsEl.hidden = !detailsEl.hidden;
      viewBtn.textContent = detailsEl.hidden ? "View details" : "Hide details";
    });
  }
}

// Detect when email is opened
const observer = new MutationObserver(() => {
  const emailBody = document.querySelector(".ii.gt");
  if (emailBody && !emailBody.dataset.scanned) {
    emailBody.dataset.scanned = "true";
    scanEmail();
  }
});
observer.observe(document.body, { childList: true, subtree: true });

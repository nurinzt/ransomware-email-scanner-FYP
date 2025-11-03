// reads file, compute SHA-256, asks background to check; if missing, uploads file for scanning
const fileInput = document.getElementById("fileInput");
const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

function setStatus(text) {
  statusEl.textContent = text;
}

function showResult(obj) {
  resultEl.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

// Convert ArrayBuffer → hex string
function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// Compute SHA-256 hash for a file
async function computeSHA256(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return bufferToHex(hashBuffer);
}

// Convert ArrayBuffer → Base64 for upload
function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, slice);
  }
  return btoa(binary);
}

// Ask background.js to check hash on VT
function checkHash(hash) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ action: "check-hash", hash }, resolve);
  });
}

// Ask background.js to upload file to VT
function uploadFile(filename, mime, base64) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ action: "upload-file", filename, mime, base64 }, resolve);
  });
}

scanBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) {
    setStatus("⚠️ Please choose a file first.");
    return;
  }

  try {
    setStatus("Computing SHA-256...");
    showResult("");

    const hash = await computeSHA256(file);
    setStatus(`SHA-256: ${hash}\nChecking VirusTotal...`);

    // Step 1: check if VT already knows this hash
    const checkResp = await checkHash(hash);
    if (checkResp?.exists || checkResp?.data) {
      setStatus("✅ Found existing VirusTotal report.");
      showResult(checkResp);
      return;
    }

    if (checkResp?.error) {
      setStatus("Error checking hash: " + checkResp.error);
      return;
    }

    // Step 2: not found → upload
    setStatus("No report found. Uploading file to VirusTotal...");

    const buffer = await file.arrayBuffer();
    const base64 = arrayBufferToBase64(buffer);

    const uploadResp = await uploadFile(file.name, file.type || "application/octet-stream", base64);

    if (uploadResp?.error) {
      setStatus("Upload failed: " + uploadResp.error);
    } else {
      setStatus("✅ Upload successful. (VirusTotal may take time to finish analysis)");
      showResult(uploadResp.result || uploadResp);
    }
  } catch (err) {
    setStatus("❌ Error: " + (err.message || err));
  }
});
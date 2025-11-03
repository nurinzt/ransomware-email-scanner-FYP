// utils.js - helper functions used by content script
async function getSHA256(str) {
  const msgBuffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Utility helper functions can be added here

function logInfo(message) {
  console.log("[Email Scanner] " + message);
}


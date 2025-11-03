// threatCache.js - Local cache for known malicious URLs and file hashes
// Uses Chrome storage API (chrome.storage.local)

const CACHE_VERSION = 1;
const CACHE_EXPIRY_DAYS = 30; // Cache results for 30 days

// Get SHA-256 hash of a string
async function hashString(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Check if cache entry is expired
function isExpired(timestamp) {
  const expiryTime = CACHE_EXPIRY_DAYS * 24 * 60 * 60 * 1000; // Convert days to milliseconds
  return (Date.now() - timestamp) > expiryTime;
}

// Get cached threat data for URL
async function getCachedURL(url) {
  try {
    const urlHash = await hashString(url);
    const key = `url_${urlHash}`;
    const result = await chrome.storage.local.get(key);
    
    if (result[key]) {
      const cached = result[key];
      if (isExpired(cached.timestamp)) {
        // Expired - remove from cache
        await chrome.storage.local.remove(key);
        return null;
      }
      return cached.data;
    }
    return null;
  } catch (e) {
    console.error("Error reading URL cache:", e);
    return null;
  }
}

// Cache threat data for URL
async function cacheURL(url, threatData) {
  try {
    const urlHash = await hashString(url);
    const key = `url_${urlHash}`;
    const cacheEntry = {
      data: threatData,
      timestamp: Date.now(),
      url: url // Store original URL for debugging
    };
    await chrome.storage.local.set({ [key]: cacheEntry });
    console.log("Cached URL threat data for:", url);
  } catch (e) {
    console.error("Error caching URL:", e);
  }
}

// Get cached threat data for file hash
async function getCachedHash(fileHash) {
  try {
    const key = `hash_${fileHash.toLowerCase()}`;
    const result = await chrome.storage.local.get(key);
    
    if (result[key]) {
      const cached = result[key];
      if (isExpired(cached.timestamp)) {
        // Expired - remove from cache
        await chrome.storage.local.remove(key);
        return null;
      }
      return cached.data;
    }
    return null;
  } catch (e) {
    console.error("Error reading hash cache:", e);
    return null;
  }
}

// Cache threat data for file hash
async function cacheHash(fileHash, threatData) {
  try {
    const key = `hash_${fileHash.toLowerCase()}`;
    const cacheEntry = {
      data: threatData,
      timestamp: Date.now(),
      hash: fileHash
    };
    await chrome.storage.local.set({ [key]: cacheEntry });
    console.log("Cached hash threat data for:", fileHash);
  } catch (e) {
    console.error("Error caching hash:", e);
  }
}

// Clear all cached data
async function clearCache() {
  try {
    await chrome.storage.local.clear();
    console.log("Cache cleared");
  } catch (e) {
    console.error("Error clearing cache:", e);
  }
}

// Get cache statistics
async function getCacheStats() {
  try {
    const allData = await chrome.storage.local.get(null);
    let urlCount = 0;
    let hashCount = 0;
    let expiredCount = 0;
    
    for (const [key, value] of Object.entries(allData)) {
      if (key.startsWith("url_")) {
        urlCount++;
        if (isExpired(value.timestamp)) expiredCount++;
      } else if (key.startsWith("hash_")) {
        hashCount++;
        if (isExpired(value.timestamp)) expiredCount++;
      }
    }
    
    return {
      urlCount,
      hashCount,
      expiredCount,
      totalCount: urlCount + hashCount
    };
  } catch (e) {
    console.error("Error getting cache stats:", e);
    return { urlCount: 0, hashCount: 0, expiredCount: 0, totalCount: 0 };
  }
}

// Clean up expired entries
async function cleanupExpiredEntries() {
  try {
    const allData = await chrome.storage.local.get(null);
    const keysToRemove = [];
    
    for (const [key, value] of Object.entries(allData)) {
      if ((key.startsWith("url_") || key.startsWith("hash_")) && value.timestamp) {
        if (isExpired(value.timestamp)) {
          keysToRemove.push(key);
        }
      }
    }
    
    if (keysToRemove.length > 0) {
      await chrome.storage.local.remove(keysToRemove);
      console.log(`Cleaned up ${keysToRemove.length} expired cache entries`);
    }
    
    return keysToRemove.length;
  } catch (e) {
    console.error("Error cleaning up cache:", e);
    return 0;
  }
}

// Initialize cache cleanup on startup (only if running in service worker context)
if (typeof chrome !== 'undefined' && chrome.runtime) {
  // Run cleanup on startup
  cleanupExpiredEntries();
  
  // Schedule periodic cleanup (service workers may be terminated, so cleanup on each run)
  // This will run when the service worker wakes up
}


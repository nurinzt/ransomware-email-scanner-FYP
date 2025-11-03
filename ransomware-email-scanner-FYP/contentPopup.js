let scanCancelled = false;

function createOverlay(message = "Processing...", isLoading = true, isSafeEmail = false) {
  const old = document.getElementById("email-scan-overlay");
  if (old) old.remove();

  const overlay = document.createElement("div");
  overlay.id = "email-scan-overlay";
  overlay.style = `
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.85); color: white; font-size: 18px;
    display: flex; flex-direction: column; justify-content: center; align-items: center;
    z-index: 99999; overflow-y: auto; padding: 20px;
  `;

  if (isLoading) {

    // Loading animation
    const img = document.createElement("img");
    const loadingUrl = chrome.runtime.getURL("icons/loading-circle.gif");
    console.log("Attempting to load loading animation from:", loadingUrl);
    img.style = "width: 60px; height: 60px; margin-bottom: 16px; display: block;";
    img.alt = "Loading...";
    img.onerror = () => {
      console.error("Failed to load loading animation:", img.src);
      console.error("Extension ID:", chrome.runtime.id);
      // Fallback: create a simple CSS spinner
      const spinner = document.createElement("div");
      spinner.style = "width: 60px; height: 60px; margin-bottom: 16px; border: 4px solid rgba(255,255,255,0.3); border-top: 4px solid white; border-radius: 50%; animation: spin 1s linear infinite;";
      const existingImg = overlay.querySelector('img');
      if (existingImg) {
        existingImg.replaceWith(spinner);
      } else {
        overlay.insertBefore(spinner, overlay.firstChild);
      }
      
      // Add animation keyframes if not already present
      if (!document.getElementById('spinner-styles')) {
        const style = document.createElement('style');
        style.id = 'spinner-styles';
        style.textContent = '@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }';
        document.head.appendChild(style);
      }
    };
    img.onload = () => console.log("Loading animation loaded successfully");
    overlay.appendChild(img);
    
    // Set src after appending to DOM to ensure proper loading
    img.src = loadingUrl;

    const text = document.createElement("div");
    text.style = "margin-bottom: 12px; text-align: center; max-width: 480px; white-space: pre-line;";
    text.innerHTML = message; // <-- allow HTML for links
    overlay.appendChild(text);

    // Cancel button
    const cancelBtn = document.createElement("button");
    cancelBtn.textContent = "Cancel";
    cancelBtn.style = "margin-top: 8px; padding: 8px 16px; font-size: 16px; cursor: pointer; border-radius: 6px; border: none; background: #e74c3c; color: white;";
    cancelBtn.onclick = () => {
      scanCancelled = true;
      removeOverlay();
    };
    overlay.appendChild(cancelBtn);
  } else {

    const text = document.createElement("div");
    text.style = "margin-bottom: 12px; text-align: left; max-width: 800px; white-space: pre-line; overflow-y: auto; max-height: 80vh;";
    text.innerHTML = message; // <-- allow HTML for links
    overlay.appendChild(text);

    // Button logic: show "Proceed to view email" for safe emails, "Close" for threats
    const actionBtn = document.createElement("button");
    if (isSafeEmail) {
      actionBtn.textContent = "Proceed to view email";
      actionBtn.style = "margin-top: 18px; padding: 8px 16px; font-size: 16px; cursor: pointer; border-radius: 6px; border: none; background: #2ecc71; color: white;";
      actionBtn.onclick = removeOverlay;
    } else {
      actionBtn.textContent = "Close";
      actionBtn.style = "margin-top: 18px; padding: 8px 16px; font-size: 16px; cursor: pointer; border-radius: 6px; border: none; background: #3498db; color: white;";
      actionBtn.onclick = async () => {
        // Remove overlay first
        removeOverlay();
        
        // Ask user permission to delete the email
        const confirmDelete = confirm("Do you want to delete this email?");
        
        if (confirmDelete) {
          // Try to delete the email by clicking Gmail's delete button
          try {
            // Wait a moment for overlay to be removed
            await new Promise(resolve => setTimeout(resolve, 200));
            
            // Look for Gmail delete button - Gmail uses various selectors
            const deleteBtn = document.querySelector('[data-tooltip="Delete"]') ||
                             document.querySelector('[data-tooltip="delete"]') ||
                             document.querySelector('[aria-label*="Delete"]') ||
                             document.querySelector('[aria-label*="delete"]') ||
                             document.querySelector('div[role="button"][aria-label*="Delete"]') ||
                             document.querySelector('div[role="button"][aria-label*="delete"]') ||
                             document.querySelector('[title="Delete"]') ||
                             document.querySelector('[title="delete"]') ||
                             document.querySelector('.T-I.J-J5-Ji.nX.T-I-ax7.L3') ||
                             document.querySelector('[data-tooltip*="Delete"]');
            
            if (deleteBtn) {
              // Try clicking the button
              deleteBtn.click();
              // Wait a bit for the delete action to process
              await new Promise(resolve => setTimeout(resolve, 1000));
            } else {
              // Fallback: try keyboard shortcut (Shift + #)
              console.log("Delete button not found, trying keyboard shortcut");
              try {
                const deleteEvent = new KeyboardEvent('keydown', {
                  key: '#',
                  code: 'Digit3',
                  shiftKey: true,
                  bubbles: true,
                  cancelable: true
                });
                document.dispatchEvent(deleteEvent);
                await new Promise(resolve => setTimeout(resolve, 1000));
              } catch (e) {
                console.error("Keyboard shortcut failed:", e);
              }
            }
          } catch (e) {
            console.error("Error trying to delete email:", e);
          }
        }
        
        // Navigate to Gmail main page (inbox)
        window.location.href = "https://mail.google.com/mail/u/0/#inbox";
      };
    }
    overlay.appendChild(actionBtn);
  }
  
  document.body.appendChild(overlay);
}

function removeOverlay() {
  const el = document.getElementById("email-scan-overlay");
  if (el) el.remove();
  scanCancelled = false;
}

// Helper function to extract malware names and types from vendor results
function extractMalwareInfo(analysisResults) {
  if (!analysisResults || typeof analysisResults !== 'object') {
    return { names: [], types: [] };
  }
  
  const malwareNames = new Map(); // name -> count
  const malwareTypes = new Set();
  
  Object.entries(analysisResults).forEach(([vendor, result]) => {
    if (result.category === 'malicious' || result.category === 'suspicious') {
      const resultName = result.result || '';
      
      if (resultName) {
        // Normalize the result name (remove extra spaces, special chars at start)
        const normalizedName = resultName.trim();
        
        // Count occurrences of each malware name
        const count = malwareNames.get(normalizedName) || 0;
        malwareNames.set(normalizedName, count + 1);
        
        // Extract malware type (common patterns: Trojan, Ransomware, Virus, etc.)
        // Try multiple patterns to catch different naming conventions
        const typePatterns = [
          /^(Trojan|Ransomware|Virus|Worm|Adware|Spyware|Malware|Phishing|Backdoor|Rootkit|Downloader|Dropper|Exploit|Riskware|PUA|PUP|Banker|Stealer|Keylogger|Cryptominer|Miner|CoinMiner|Scareware|FakeAV|Rogue|Bot|Zombie|Hoax|Joke|Filecoder)/i,
          /(Trojan\.|Trojan:)/i,
          /(Win32|Win64|Generic|Heuristic)/i
        ];
        
        for (const pattern of typePatterns) {
          const typeMatch = normalizedName.match(pattern);
          if (typeMatch) {
            // Clean up the type name
            let typeName = typeMatch[1] || typeMatch[0];
            typeName = typeName.replace(/[.:]$/, ''); // Remove trailing dots/colons
            if (typeName && typeName.length > 2) {
              malwareTypes.add(typeName);
            }
            break; // Use first match
          }
        }
      }
    }
  });
  
  // Sort malware names by frequency (most common first)
  const sortedNames = Array.from(malwareNames.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10) // Top 10 most common
    .map(([name, count]) => ({ name, count }));
  
  return {
    names: sortedNames,
    types: Array.from(malwareTypes).slice(0, 10)
  };
}

async function getSHA256(str) {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// --- NEW scanEmail function ---
async function scanEmail() {
  createOverlay("Scanning this email for threats...", true);
  let maliciousUrls = [];
  let maliciousAttachments = [];
  let failedAttachments = [];

  // Improved URL extraction - get from multiple sources
  const emailBodyElement = document.querySelector(".ii.gt");
  let emailBodyText = "";
  let urlSet = new Set(); // Use Set to avoid duplicates
  
  if (emailBodyElement) {
    // Get text content
    emailBodyText = emailBodyElement.innerText || emailBodyElement.textContent || "";
    
    // Also get URLs from link href attributes
    emailBodyElement.querySelectorAll("a[href]").forEach(link => {
      const href = link.getAttribute("href");
      if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
        urlSet.add(href);
      }
    });
    
    // Extract URLs from text using regex
    const textUrls = [...emailBodyText.matchAll(/https?:\/\/[^\s<>\"]+/g)].map(m => m[0]);
    textUrls.forEach(url => urlSet.add(url));
  }
  
  const urls = Array.from(urlSet);
  console.log("Extracted URLs:", urls);

  // --- Collect attachments (Gmail DOM) ---
  let attachments = [];
  document.querySelectorAll('.aQH, .aQa').forEach(att => {
    const filename = att.querySelector('[download], .aV3, .aQy')?.textContent?.trim();
    const downloadLink = att.querySelector('a[download]')?.href;
    if (filename) attachments.push({ filename, downloadLink });
  });

  // --- Scan URLs in email body ---
  for (const url of urls) {
    if (scanCancelled) return;
    await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: "scan-url", url }, res => {
        console.log("VirusTotal response for", url, ":", res);
        
        // Handle errors
        if (res?.error) {
          console.error("Error scanning URL:", url, res.error);
          resolve();
          return;
        }
        
        // Check multiple possible response structures from VirusTotal API v3
        // Analysis response (from polling): data.attributes.stats.malicious
        // URL report (direct lookup): data.attributes.last_analysis_stats.malicious
        let malicious = 0;
        let positives = 0;
        let stats = null;
        
        // Check for analysis stats (from polling analysis endpoint)
        if (res?.data?.attributes?.stats) {
          stats = res.data.attributes.stats;
          malicious = stats.malicious || 0;
          positives = malicious;
        }
        // Check for last analysis stats (from direct URL report lookup)
        else if (res?.data?.attributes?.last_analysis_stats) {
          stats = res.data.attributes.last_analysis_stats;
          malicious = stats.malicious || 0;
          positives = malicious;
        }
        
        // Also check for suspicious results for better detection
        if (stats && malicious === 0) {
          // If there are any suspicious results, treat as potentially malicious
          if ((stats.suspicious || 0) > 0) {
            positives = stats.suspicious;
            malicious = 1; // Treat suspicious as potentially malicious
          }
        }
        
        // Extract detailed information from VirusTotal response
        const attributes = res?.data?.attributes || {};
        const analysisStats = stats || attributes.last_analysis_stats || {};
        const totalEngines = (analysisStats.malicious || 0) + (analysisStats.suspicious || 0) + (analysisStats.harmless || 0) + (analysisStats.undetected || 0) + (analysisStats.timeout || 0);
        
        if (malicious > 0 || (analysisStats.suspicious || 0) > 0) {
          console.log("⚠️ Malicious URL detected:", url, "flagged by", positives, "vendors");
          maliciousUrls.push({
            url,
            positives: positives,
            suspicious: analysisStats.suspicious || 0,
            harmless: analysisStats.harmless || 0,
            undetected: analysisStats.undetected || 0,
            totalEngines: totalEngines,
            // Detailed information
            categories: attributes.categories || {},
            lastAnalysisDate: attributes.last_analysis_date,
            firstSubmissionDate: attributes.first_submission_date,
            lastSubmissionDate: attributes.last_submission_date,
            httpResponseCode: attributes.last_http_response_code,
            httpHeaders: attributes.last_http_response_headers || {},
            bodySha256: attributes.last_http_response_content_sha256,
            contentType: attributes.last_http_response_content_type,
            timesSubmitted: attributes.times_submitted,
            lastAnalysisResults: attributes.last_analysis_results || {},
            // Vendor detection details
            fullResponse: res
          });
        } else {
          console.log("✓ URL appears safe:", url);
        }
        resolve();
      });
    });
  }

  // --- Scan Attachments ---
  for (const att of attachments) {
    if (scanCancelled) return;
    let hash = null;
    let scanError = null;

    try {
      const fileResp = await new Promise(resolve => {
        chrome.runtime.sendMessage(
          { action: "fetch-attachment", url: att.downloadLink },
          resolve
        );
      });

      if (fileResp?.success && fileResp.buffer) {
        const buffer = new Uint8Array(fileResp.buffer).buffer;
        const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
        hash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
      } else {
        scanError = fileResp?.error || "Attachment fetch failed (Gmail may block direct access)";
      }
    } catch (e) {
      scanError = e.message || "Unknown error fetching attachment";
    }

    if (hash) {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: "scan-hash", hash }, res => {
          const attributes = res?.data?.attributes || {};
          const stats = attributes.last_analysis_stats || {};
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          
          if (malicious > 0 || suspicious > 0) {
            const totalEngines = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0) + (stats.timeout || 0);
            
            maliciousAttachments.push({
              filename: att.filename,
              hash: hash,
              positives: malicious,
              suspicious: suspicious,
              harmless: stats.harmless || 0,
              undetected: stats.undetected || 0,
              totalEngines: totalEngines,
              // Detailed information
              typeDescription: attributes.type_description,
              typeTag: attributes.type_tag,
              size: attributes.size,
              md5: attributes.md5,
              sha1: attributes.sha1,
              sha256: attributes.sha256,
              firstSubmissionDate: attributes.first_submission_date,
              lastSubmissionDate: attributes.last_submission_date,
              lastAnalysisDate: attributes.last_analysis_date,
              timesSubmitted: attributes.times_submitted,
              lastAnalysisResults: attributes.last_analysis_results || {},
              // Vendor detection details
              fullResponse: res
            });
          }
          resolve();
        });
      });
    } else {
      failedAttachments.push({ filename: att.filename, error: scanError });
    }
  }

  // --- Final Result Message with Detailed Information ---
  let resultMsg = "";
  let isSafeEmail = false;
  
  if (maliciousUrls.length > 0 || maliciousAttachments.length > 0) {
    resultMsg = "<div style='text-align:left; max-width:700px;'>";
    resultMsg += "<h2 style='color:#e74c3c; margin-bottom:20px;'>⚠️ Threats Detected!</h2>";

    // Aggregate all malware types detected across all threats
    const allMalwareTypes = new Set();
    const allMalwareNames = new Map();
    
    maliciousUrls.forEach(url => {
      const malwareInfo = extractMalwareInfo(url.lastAnalysisResults);
      malwareInfo.types.forEach(type => allMalwareTypes.add(type));
      malwareInfo.names.forEach(({name, count}) => {
        const currentCount = allMalwareNames.get(name) || 0;
        allMalwareNames.set(name, currentCount + count);
      });
    });
    
    maliciousAttachments.forEach(att => {
      const malwareInfo = extractMalwareInfo(att.lastAnalysisResults);
      malwareInfo.types.forEach(type => allMalwareTypes.add(type));
      malwareInfo.names.forEach(({name, count}) => {
        const currentCount = allMalwareNames.get(name) || 0;
        allMalwareNames.set(name, currentCount + count);
      });
    });
    
    // Show summary of detected malware types
    if (allMalwareTypes.size > 0 || allMalwareNames.size > 0) {
      resultMsg += "<div style='background:rgba(231,76,60,0.25); border:2px solid #e74c3c; border-radius:8px; padding:15px; margin-bottom:20px;'>";
      resultMsg += "<div style='color:#fff; font-size:16px; font-weight:bold; margin-bottom:12px;'>🦠 Malware Summary:</div>";
      
      if (allMalwareTypes.size > 0) {
        resultMsg += "<div style='margin-bottom:10px;'>";
        resultMsg += "<div style='color:#f39c12; font-size:14px; font-weight:bold; margin-bottom:6px;'>Detected Malware Types:</div>";
        resultMsg += "<div style='display:flex; flex-wrap:wrap; gap:6px;'>";
        Array.from(allMalwareTypes).forEach(type => {
          resultMsg += `<span style='background:rgba(243,156,18,0.4); color:#fff; padding:6px 12px; border-radius:5px; font-size:13px; font-weight:bold; border:1px solid #f39c12;'>${escapeHtml(type)}</span>`;
        });
        resultMsg += "</div>";
        resultMsg += "</div>";
      }
      
      if (allMalwareNames.size > 0) {
        const topMalwareNames = Array.from(allMalwareNames.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 3);
        
        resultMsg += "<div>";
        resultMsg += "<div style='color:#e74c3c; font-size:14px; font-weight:bold; margin-bottom:6px;'>Most Common Malware Names:</div>";
        resultMsg += "<div>";
        topMalwareNames.forEach(([name, count]) => {
          resultMsg += `<div style='color:#fff; font-size:13px; margin:4px 0;'>• <strong>${escapeHtml(name)}</strong> <span style='color:#bdc3c7;'>(detected ${count} time${count > 1 ? 's' : ''})</span></div>`;
        });
        resultMsg += "</div>";
        resultMsg += "</div>";
      }
      
      resultMsg += "</div>";
    }

    if (maliciousUrls.length > 0) {
      resultMsg += "<h3 style='color:#fff; margin-top:15px; margin-bottom:10px;'>🔗 Malicious Links:</h3>";
      maliciousUrls.forEach((u, index) => {
        resultMsg += formatURLDetails(u, index + 1);
      });
    }

    if (maliciousAttachments.length > 0) {
      resultMsg += "<h3 style='color:#fff; margin-top:20px; margin-bottom:10px;'>📎 Malicious Attachments:</h3>";
      maliciousAttachments.forEach((f, index) => {
        resultMsg += formatFileDetails(f, index + 1);
      });
    }
    
    resultMsg += "</div>";
    isSafeEmail = false;
  } else if (attachments.length > 0) {
    resultMsg = "⚠️ This email has attachments. ";
    if (failedAttachments.length > 0) {
      resultMsg += "\nSome attachments could not be scanned automatically:\n";
      failedAttachments.forEach(f => {
        resultMsg += `- ${f.filename}: ${f.error}\n`;
      });
      resultMsg += "\nPlease scan these files manually using the extension popup after downloading, or ";
      resultMsg += "<a href='https://www.virustotal.com/gui/home/upload' target='_blank' style='color:#fff;text-decoration:underline;font-weight:bold;'>scan on VirusTotal</a>.";
    } else {
      resultMsg += "They appear safe but caution is advised.";
    }
    isSafeEmail = false;
  } else {
    resultMsg = "✅ No threats found in this email.";
    isSafeEmail = true;
  }

  createOverlay(resultMsg, false, isSafeEmail);
}

// Format detailed URL threat information
function formatURLDetails(urlData, index) {
  const details = urlData;
  let html = `<div style='background:rgba(231,76,60,0.2); border-left:4px solid #e74c3c; padding:15px; margin-bottom:15px; border-radius:4px;'>`;
  
  // Detection Summary
  html += `<div style='margin-bottom:12px;'>`;
  html += `<strong style='color:#e74c3c; font-size:16px;'>URL #${index}: ${escapeHtml(details.url)}</strong><br>`;
  html += `<span style='color:#fff; font-size:14px;'>`;
  html += `<strong style='color:#e74c3c;'>${details.positives}/${details.totalEngines}</strong> security vendors flagged this URL as <strong style='color:#e74c3c;'>malicious</strong>`;
  if (details.suspicious > 0) {
    html += ` | <strong style='color:#f39c12;'>${details.suspicious}</strong> flagged as <strong style='color:#f39c12;'>suspicious</strong>`;
  }
  html += `</span>`;
  html += `</div>`;
  
  // Malware Names and Types Section
  const malwareInfo = extractMalwareInfo(details.lastAnalysisResults);
  if (malwareInfo.names.length > 0 || malwareInfo.types.length > 0) {
    html += `<div style='margin-bottom:15px; background:rgba(231,76,60,0.3); padding:12px; border-radius:6px; border:1px solid rgba(231,76,60,0.5);'>`;
    html += `<strong style='color:#fff; font-size:15px; display:block; margin-bottom:10px;'>🦠 Detected Malware Information:</strong>`;
    
    if (malwareInfo.types.length > 0) {
      html += `<div style='margin-bottom:8px;'>`;
      html += `<strong style='color:#f39c12; font-size:13px;'>Malware Types:</strong><br>`;
      html += `<div style='margin-left:10px; margin-top:5px;'>`;
      malwareInfo.types.forEach(type => {
        html += `<span style='background:rgba(243,156,18,0.3); color:#f39c12; padding:4px 8px; margin:2px; border-radius:4px; display:inline-block; font-size:12px; font-weight:bold;'>${escapeHtml(type)}</span>`;
      });
      html += `</div>`;
      html += `</div>`;
    }
    
    if (malwareInfo.names.length > 0) {
      html += `<div>`;
      html += `<strong style='color:#e74c3c; font-size:13px;'>Malware Names (by detection frequency):</strong><br>`;
      html += `<div style='margin-left:10px; margin-top:5px;'>`;
      malwareInfo.names.slice(0, 5).forEach(({name, count}) => {
        html += `<div style='margin:4px 0; font-size:12px;'>`;
        html += `<span style='color:#fff;'><strong>${escapeHtml(name)}</strong></span>`;
        html += `<span style='color:#bdc3c7; margin-left:8px;'>(detected by ${count} vendor${count > 1 ? 's' : ''})</span>`;
        html += `</div>`;
      });
      if (malwareInfo.names.length > 5) {
        html += `<div style='color:#bdc3c7; font-size:11px; margin-top:4px;'>...and ${malwareInfo.names.length - 5} more</div>`;
      }
      html += `</div>`;
      html += `</div>`;
    }
    
    html += `</div>`;
  }
  
  // Categories
  if (details.categories && Object.keys(details.categories).length > 0) {
    html += `<div style='margin-bottom:10px;'>`;
    html += `<strong style='color:#ecf0f1;'>Categories:</strong><br>`;
    html += `<div style='margin-left:15px; margin-top:5px;'>`;
    Object.entries(details.categories).forEach(([vendor, category]) => {
      html += `<span style='color:#bdc3c7;'>• ${vendor}: <span style='color:#fff;'>${escapeHtml(category)}</span></span><br>`;
    });
    html += `</div>`;
    html += `</div>`;
  }
  
  // History
  html += `<div style='margin-bottom:10px;'>`;
  html += `<strong style='color:#ecf0f1;'>History:</strong><br>`;
  html += `<div style='margin-left:15px; margin-top:5px; font-size:13px; color:#bdc3c7;'>`;
  if (details.firstSubmissionDate) {
    html += `• <strong>First Submission:</strong> ${formatDate(details.firstSubmissionDate)}<br>`;
  }
  if (details.lastSubmissionDate) {
    html += `• <strong>Last Submission:</strong> ${formatDate(details.lastSubmissionDate)}<br>`;
  }
  if (details.lastAnalysisDate) {
    html += `• <strong>Last Analysis:</strong> ${formatDate(details.lastAnalysisDate)}<br>`;
  }
  if (details.timesSubmitted) {
    html += `• <strong>Times Submitted:</strong> ${details.timesSubmitted}<br>`;
  }
  html += `</div>`;
  html += `</div>`;
  
  // HTTP Response
  if (details.httpResponseCode || details.contentType || details.bodySha256) {
    html += `<div style='margin-bottom:10px;'>`;
    html += `<strong style='color:#ecf0f1;'>HTTP Response:</strong><br>`;
    html += `<div style='margin-left:15px; margin-top:5px; font-size:13px; color:#bdc3c7;'>`;
    if (details.httpResponseCode) {
      html += `• <strong>Status Code:</strong> <span style='color:#${details.httpResponseCode === 200 ? '2ecc71' : 'e74c3c'};'>${details.httpResponseCode}</span><br>`;
    }
    if (details.contentType) {
      html += `• <strong>Content Type:</strong> ${escapeHtml(details.contentType)}<br>`;
    }
    if (details.bodySha256) {
      html += `• <strong>Body SHA-256:</strong> <code style='background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:3px; font-size:12px;'>${details.bodySha256}</code><br>`;
    }
    html += `</div>`;
    html += `</div>`;
  }
  
  // HTTP Headers
  if (details.httpHeaders && Object.keys(details.httpHeaders).length > 0) {
    html += `<div style='margin-bottom:10px;'>`;
    html += `<strong style='color:#ecf0f1;'>HTTP Headers:</strong><br>`;
    html += `<div style='margin-left:15px; margin-top:5px; font-size:12px; color:#bdc3c7; background:rgba(0,0,0,0.3); padding:8px; border-radius:3px; max-height:150px; overflow-y:auto;'>`;
    Object.entries(details.httpHeaders).forEach(([key, value]) => {
      html += `<strong>${escapeHtml(key)}:</strong> ${escapeHtml(value)}<br>`;
    });
    html += `</div>`;
    html += `</div>`;
  }
  
  // Vendor Results (Top Malicious Detections)
  if (details.lastAnalysisResults && Object.keys(details.lastAnalysisResults).length > 0) {
    const maliciousVendors = Object.entries(details.lastAnalysisResults)
      .filter(([_, result]) => result.category === 'malicious' || result.category === 'suspicious')
      .slice(0, 5); // Show top 5
    
    if (maliciousVendors.length > 0) {
      html += `<div style='margin-bottom:10px;'>`;
      html += `<strong style='color:#ecf0f1;'>Top Vendor Detections:</strong><br>`;
      html += `<div style='margin-left:15px; margin-top:5px; font-size:13px;'>`;
      maliciousVendors.forEach(([vendor, result]) => {
        const color = result.category === 'malicious' ? '#e74c3c' : '#f39c12';
        html += `<span style='color:${color};'>• <strong>${escapeHtml(vendor)}</strong>: ${escapeHtml(result.result || result.category)}</span><br>`;
      });
      html += `</div>`;
      html += `</div>`;
    }
  }
  
  html += `</div>`;
  return html;
}

// Format detailed file threat information
function formatFileDetails(fileData, index) {
  const details = fileData;
  let html = `<div style='background:rgba(231,76,60,0.2); border-left:4px solid #e74c3c; padding:15px; margin-bottom:15px; border-radius:4px;'>`;
  
  // Detection Summary
  html += `<div style='margin-bottom:12px;'>`;
  html += `<strong style='color:#e74c3c; font-size:16px;'>File #${index}: ${escapeHtml(details.filename)}</strong><br>`;
  html += `<span style='color:#fff; font-size:14px;'>`;
  html += `<strong style='color:#e74c3c;'>${details.positives}/${details.totalEngines}</strong> security vendors flagged this file as <strong style='color:#e74c3c;'>malicious</strong>`;
  if (details.suspicious > 0) {
    html += ` | <strong style='color:#f39c12;'>${details.suspicious}</strong> flagged as <strong style='color:#f39c12;'>suspicious</strong>`;
  }
  html += `</span>`;
  html += `</div>`;
  
  // Malware Names and Types Section
  const malwareInfo = extractMalwareInfo(details.lastAnalysisResults);
  if (malwareInfo.names.length > 0 || malwareInfo.types.length > 0) {
    html += `<div style='margin-bottom:15px; background:rgba(231,76,60,0.3); padding:12px; border-radius:6px; border:1px solid rgba(231,76,60,0.5);'>`;
    html += `<strong style='color:#fff; font-size:15px; display:block; margin-bottom:10px;'>🦠 Detected Malware Information:</strong>`;
    
    if (malwareInfo.types.length > 0) {
      html += `<div style='margin-bottom:8px;'>`;
      html += `<strong style='color:#f39c12; font-size:13px;'>Malware Types:</strong><br>`;
      html += `<div style='margin-left:10px; margin-top:5px;'>`;
      malwareInfo.types.forEach(type => {
        html += `<span style='background:rgba(243,156,18,0.3); color:#f39c12; padding:4px 8px; margin:2px; border-radius:4px; display:inline-block; font-size:12px; font-weight:bold;'>${escapeHtml(type)}</span>`;
      });
      html += `</div>`;
      html += `</div>`;
    }
    
    if (malwareInfo.names.length > 0) {
      html += `<div>`;
      html += `<strong style='color:#e74c3c; font-size:13px;'>Malware Names (by detection frequency):</strong><br>`;
      html += `<div style='margin-left:10px; margin-top:5px;'>`;
      malwareInfo.names.slice(0, 5).forEach(({name, count}) => {
        html += `<div style='margin:4px 0; font-size:12px;'>`;
        html += `<span style='color:#fff;'><strong>${escapeHtml(name)}</strong></span>`;
        html += `<span style='color:#bdc3c7; margin-left:8px;'>(detected by ${count} vendor${count > 1 ? 's' : ''})</span>`;
        html += `</div>`;
      });
      if (malwareInfo.names.length > 5) {
        html += `<div style='color:#bdc3c7; font-size:11px; margin-top:4px;'>...and ${malwareInfo.names.length - 5} more</div>`;
      }
      html += `</div>`;
      html += `</div>`;
    }
    
    html += `</div>`;
  }
  
  // File Information
  html += `<div style='margin-bottom:10px;'>`;
  html += `<strong style='color:#ecf0f1;'>File Information:</strong><br>`;
  html += `<div style='margin-left:15px; margin-top:5px; font-size:13px; color:#bdc3c7;'>`;
  if (details.typeDescription) {
    html += `• <strong>Type:</strong> ${escapeHtml(details.typeDescription)}<br>`;
  }
  if (details.typeTag) {
    html += `• <strong>Tag:</strong> ${escapeHtml(details.typeTag)}<br>`;
  }
  if (details.size) {
    html += `• <strong>Size:</strong> ${formatBytes(details.size)}<br>`;
  }
  if (details.md5) {
    html += `• <strong>MD5:</strong> <code style='background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:3px; font-size:11px;'>${details.md5}</code><br>`;
  }
  if (details.sha1) {
    html += `• <strong>SHA-1:</strong> <code style='background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:3px; font-size:11px;'>${details.sha1}</code><br>`;
  }
  if (details.sha256) {
    html += `• <strong>SHA-256:</strong> <code style='background:rgba(0,0,0,0.3); padding:2px 6px; border-radius:3px; font-size:11px;'>${details.sha256}</code><br>`;
  }
  html += `</div>`;
  html += `</div>`;
  
  // History
  html += `<div style='margin-bottom:10px;'>`;
  html += `<strong style='color:#ecf0f1;'>History:</strong><br>`;
  html += `<div style='margin-left:15px; margin-top:5px; font-size:13px; color:#bdc3c7;'>`;
  if (details.firstSubmissionDate) {
    html += `• <strong>First Submission:</strong> ${formatDate(details.firstSubmissionDate)}<br>`;
  }
  if (details.lastSubmissionDate) {
    html += `• <strong>Last Submission:</strong> ${formatDate(details.lastSubmissionDate)}<br>`;
  }
  if (details.lastAnalysisDate) {
    html += `• <strong>Last Analysis:</strong> ${formatDate(details.lastAnalysisDate)}<br>`;
  }
  if (details.timesSubmitted) {
    html += `• <strong>Times Submitted:</strong> ${details.timesSubmitted}<br>`;
  }
  html += `</div>`;
  html += `</div>`;
  
  // Vendor Results (Top Malicious Detections)
  if (details.lastAnalysisResults && Object.keys(details.lastAnalysisResults).length > 0) {
    const maliciousVendors = Object.entries(details.lastAnalysisResults)
      .filter(([_, result]) => result.category === 'malicious' || result.category === 'suspicious')
      .slice(0, 5);
    
    if (maliciousVendors.length > 0) {
      html += `<div style='margin-bottom:10px;'>`;
      html += `<strong style='color:#ecf0f1;'>Top Vendor Detections:</strong><br>`;
      html += `<div style='margin-left:15px; margin-top:5px; font-size:13px;'>`;
      maliciousVendors.forEach(([vendor, result]) => {
        const color = result.category === 'malicious' ? '#e74c3c' : '#f39c12';
        html += `<span style='color:${color};'>• <strong>${escapeHtml(vendor)}</strong>: ${escapeHtml(result.result || result.category)}</span><br>`;
      });
      html += `</div>`;
      html += `</div>`;
    }
  }
  
  html += `</div>`;
  return html;
}

// Helper functions
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatDate(timestamp) {
  if (!timestamp) return 'N/A';
  try {
    // Handle both Unix timestamp (seconds) and milliseconds
    const date = timestamp > 1000000000000 
      ? new Date(timestamp)  // Already in milliseconds
      : new Date(timestamp * 1000);  // Convert seconds to milliseconds
    return date.toLocaleString();
  } catch (e) {
    return String(timestamp);
  }
}

function formatBytes(bytes) {
  if (!bytes) return 'N/A';
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Detect when an email is opened
const observer = new MutationObserver(() => {
  const emailBody = document.querySelector(".ii.gt");
  if (emailBody && !emailBody.dataset.scanned) {
    emailBody.dataset.scanned = "true";
    scanEmail();
  }
});
observer.observe(document.body, { childList: true, subtree: true });

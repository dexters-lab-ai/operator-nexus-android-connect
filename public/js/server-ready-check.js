/**
 * Server Ready Check
 * 
 * This script checks if the backend server is ready before allowing
 * the application to fully load. It prevents the frustrating experience
 * of seeing the page attempt to load and then crash or reload repeatedly
 * when the server isn't ready yet.
 */

(function() {
  // Only run this in development mode
  if (window.location.hostname !== 'localhost' && !window.location.hostname.includes('127.0.0.1')) {
    return;
  }

  const MAX_RETRIES = 30;
  const RETRY_DELAY = 1000; // 1 second
  let retryCount = 0;
  let loadingOverlay = null;
  
  // Block all script execution until server is ready
  window.serverIsReady = false;
  
  // Prevent any assets from loading until server is ready
  const originalCreateElement = document.createElement;
  document.createElement = function(tagName) {
    // Create the element normally
    const element = originalCreateElement.call(document, tagName);
    
    // If it's a script tag, modify its behavior to wait for server ready state
    if (tagName.toLowerCase() === 'script' && !window.serverIsReady) {
      const originalSetAttribute = element.setAttribute;
      element.setAttribute = function(name, value) {
        // If it's the src attribute and we're not ready, hold the execution
        if (name === 'src' && !window.serverIsReady && !value.includes('server-ready-check.js')) {
          console.log('🔄 Delaying script loading until server is ready:', value);
          // Store the src for later
          element._pendingSrc = value;
          // Return the element without setting the src
          return element;
        }
        return originalSetAttribute.call(this, name, value);
      };
    }
    return element;
  };
  
  // Intercept all fetch requests
  const originalFetch = window.fetch;
  window.fetch = function(resource, options) {
    // Allow health check and other critical endpoints to pass through
    const url = typeof resource === 'string' ? resource : resource.url;
    const criticalEndpoints = ['/api/health', '/sockjs-node', '/@vite/client'];
    
    if (criticalEndpoints.some(endpoint => url && url.includes(endpoint))) {
      return originalFetch.apply(this, arguments);
    }
    
    // Block non-critical fetches until server is ready
    if (!window.serverIsReady) {
      console.log('🔄 Blocking fetch until server is ready:', url || resource);
      return new Promise((resolve, reject) => {
        // Store the fetch request to retry later
        window.pendingFetches = window.pendingFetches || [];
        window.pendingFetches.push(() => {
          // Once server is ready, actual fetch will be executed
          originalFetch.call(window, resource, options)
            .then(resolve)
            .catch(reject);
        });
      });
    }
    
    // If server is ready, allow fetch to proceed normally
    return originalFetch.apply(this, arguments);
  };
  
  // Function to unlock all pending scripts and fetches once server is ready
  function unlockPendingScripts() {
    console.log('🚀 Server is ready, unlocking all pending scripts and fetches');
    
    // Find all script elements with pending src
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      if (script._pendingSrc) {
        console.log('⚡ Loading previously blocked script:', script._pendingSrc);
        script.src = script._pendingSrc;
        delete script._pendingSrc;
      }
    });
    
    // Process all pending fetch requests
    if (window.pendingFetches && window.pendingFetches.length > 0) {
      console.log(`⚡ Processing ${window.pendingFetches.length} pending fetch requests`);
      window.pendingFetches.forEach(fetchFn => {
        try {
          fetchFn();
        } catch (error) {
          console.error('Error executing pending fetch:', error);
        }
      });
      window.pendingFetches = [];
    }
    
    // Restore original functions
    setTimeout(() => {
      if (originalCreateElement) document.createElement = originalCreateElement;
      if (originalFetch) window.fetch = originalFetch;
      console.log('✅ DOM APIs restored to normal operation');
    }, 1000);
  }

  // Create and show the loading overlay
  function showLoadingOverlay() {
    if (loadingOverlay) return;

    loadingOverlay = document.createElement('div');
    loadingOverlay.id = 'server-loading-overlay';
    loadingOverlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: #121212;
      color: white;
      z-index: 100000; /* Extremely high z-index to ensure it's above everything */
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: Arial, sans-serif;
      opacity: 1;
      transition: opacity 0.4s ease-out;
      pointer-events: auto; /* Ensure it captures all clicks */
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      text-align: center;
      max-width: 400px;
      padding: 20px;
    `;

    const title = document.createElement('h2');
    title.textContent = 'Starting Server...';
    title.style.cssText = `
      margin-bottom: 15px;
      font-size: 24px;
      font-weight: 600;
    `;

    const spinner = document.createElement('div');
    spinner.style.cssText = `
      border: 3px solid rgba(255, 255, 255, 0.2);
      border-top: 3px solid white;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      margin: 0 auto 20px auto;
      animation: spin 1s linear infinite;
    `;

    // Add animation for the spinner
    const style = document.createElement('style');
    style.textContent = `
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    `;

    const message = document.createElement('p');
    message.id = 'server-loading-message';
    message.textContent = 'Waiting for the backend server to start...';
    message.style.cssText = `
      margin-bottom: 15px;
      line-height: 1.5;
      font-size: 16px;
    `;

    const subMessage = document.createElement('p');
    subMessage.id = 'server-loading-submessage';
    subMessage.textContent = 'This may take a few moments on first startup';
    subMessage.style.cssText = `
      color: rgba(255, 255, 255, 0.6);
      font-size: 14px;
    `;

    const retryCounter = document.createElement('p');
    retryCounter.id = 'server-retry-counter';
    retryCounter.textContent = `Checking server... (Retry 1/${MAX_RETRIES})`;
    retryCounter.style.cssText = `
      margin-top: 20px;
      font-size: 12px;
      color: rgba(255, 255, 255, 0.5);
    `;

    content.appendChild(title);
    content.appendChild(spinner);
    content.appendChild(message);
    content.appendChild(subMessage);
    content.appendChild(retryCounter);
    
    loadingOverlay.appendChild(content);
    document.head.appendChild(style);
    document.body.appendChild(loadingOverlay);
  }

  // Remove the loading overlay with improved cleanup
  function hideLoadingOverlay() {
    // Find the overlay by ID in case the reference was lost
    const overlay = loadingOverlay || document.getElementById('server-loading-overlay');
    
    if (overlay && overlay.parentNode) {
      // First fade it out gracefully
      overlay.style.opacity = '0';
      
      // Then remove it from the DOM after the transition
      setTimeout(() => {
        if (overlay.parentNode) {
          overlay.parentNode.removeChild(overlay);
        }
        
        // Also check for any orphaned overlays by ID as a fallback
        const orphanedOverlay = document.getElementById('server-loading-overlay');
        if (orphanedOverlay) {
          console.warn('Found orphaned server overlay, removing it');
          if (orphanedOverlay.parentNode) {
            orphanedOverlay.parentNode.removeChild(orphanedOverlay);
          }
        }
        
        // Clean up reference
        loadingOverlay = null;
      }, 500);
    }
  }

  // Update the loading message
  function updateLoadingMessage(message, subMessage) {
    const messageEl = document.getElementById('server-loading-message');
    const subMessageEl = document.getElementById('server-loading-submessage');
    const retryCounterEl = document.getElementById('server-retry-counter');
    
    if (messageEl && message) {
      messageEl.textContent = message;
    }
    
    if (subMessageEl && subMessage) {
      subMessageEl.textContent = subMessage;
    }
    
    if (retryCounterEl) {
      retryCounterEl.textContent = `Checking server... (Retry ${retryCount + 1}/${MAX_RETRIES})`;
    }
  }

  // Check if the server is ready by querying the health endpoint
  async function checkServerReady() {
    const startTime = Date.now();
    const requestId = `health-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
    
    console.log(`[${requestId}] Starting health check at ${new Date().toISOString()}`);
    
    try {
      // Add a timestamp to prevent caching
      const timestamp = new Date().getTime();
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
      
      // Construct the API URL based on the current environment
      const getApiBaseUrl = () => {
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
          return 'http://localhost:3420'; // Development port
        }
        return window.location.origin; // Production
      };
      
      const apiBase = getApiBaseUrl();
      const healthUrl = `${apiBase}/api/health?_=${timestamp}`;
      
      console.log(`[${requestId}] Fetching health check from:`, healthUrl);
      
      const response = await fetch(healthUrl, {
        method: 'GET',
        credentials: 'include',  // Important for cookies if using sessions
        mode: 'cors',  // Enable CORS mode
        headers: {
          'Accept': 'application/json',
          'X-Request-ID': requestId,  // Include the request ID
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        },
        credentials: 'include',
        signal: controller.signal,
        mode: 'cors'
      });
      
      clearTimeout(timeoutId);
      
      const responseTime = Date.now() - startTime;
      console.log(`[${requestId}] Response received in ${responseTime}ms`);

      // First check the content type to ensure it's JSON
      const contentType = response.headers.get('content-type') || '';
      const isJson = contentType.includes('application/json');
      
      if (!isJson) {
        const responseText = await response.text();
        console.warn(`[${requestId}] Non-JSON response from server. Status: ${response.status} ${response.statusText}, Content-Type: ${contentType}, Response:`, responseText.substring(0, 200));
        throw new Error(`Expected JSON response but got: ${contentType}`);
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.warn(`[${requestId}] Server error: ${response.status} ${response.statusText}`, errorData);
        throw new Error(`Server error: ${response.status} ${response.statusText}`, { cause: errorData });
      }
      
      const data = await response.json();
      const isReady = data.serverReady === true || data.status === 'ok';
      
      if (!isReady) {
        console.warn(`[${requestId}] Server not ready:`, data);
      } else {
        console.log(`[${requestId}] Server is ready:`, {
          status: data.status,
          serverReady: data.serverReady,
          environment: data.environment,
          version: data.version,
          responseTime: responseTime + 'ms'
        });
      }
      
      return isReady;
    } catch (error) {
      const errorMessage = error.name === 'AbortError' 
        ? 'Health check timed out after 5 seconds' 
        : error.message;
        
      console.warn(`[${requestId}] Error checking server status:`, errorMessage, error.name === 'AbortError' ? '' : error);
      return false;
    }
  }

  // Main function to poll the server until it's ready
  function waitForServer() {
    // Only show the overlay once the document has loaded
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', showLoadingOverlay);
    } else {
      showLoadingOverlay();
    }
    
    // Set up a failsafe cleanup in case something goes wrong
    const failsafeTimeout = setTimeout(() => {
      console.warn('Failsafe cleanup: Removing server overlay after 60 seconds');
      forceCleanupOverlay();
    }, 60000); // 60 seconds max
    
    // Start the connection attempt loop
    attemptConnection();
    
    // Function to attempt connecting to the server with exponential backoff
    async function attemptConnection() {
      try {
        updateLoadingMessage(
          'Connecting to server...',
          `Attempt ${retryCount + 1} of ${MAX_RETRIES}`
        );
        
        const isReady = await checkServerReady();
        
        if (isReady) {
          // Server is ready, continue with app initialization
          window.serverIsReady = true;
          console.log('✅ Server is ready, initializing application...');
          
          // Clear the failsafe timeout since we're handling it properly
          clearTimeout(failsafeTimeout);
          
          // Update UI to show server is ready
          updateLoadingMessage('Server is ready!', 'Loading application...');
          
          // Execute the unlock immediately but delay the overlay removal slightly
          unlockPendingScripts();
          
          // Dispatch an event that the application can listen for
          window.dispatchEvent(new Event('serverReady'));
          
          // Hide the overlay with slight delay
          setTimeout(() => {
            hideLoadingOverlay();
            
            // Double-check that the overlay is gone after hiding
            setTimeout(forceCleanupOverlay, 1000);
          }, 500);
          
          return;
        }
        
        // If we get here, server is not ready yet
        if (retryCount < MAX_RETRIES - 1) {
          retryCount++;
          const delay = Math.min(1000 * Math.pow(2, retryCount), 10000); // Cap at 10s
          console.log(`Server not ready, retrying in ${delay}ms...`);
          setTimeout(attemptConnection, delay);
        } else {
          // Max retries reached
          updateLoadingMessage(
            'Server is taking too long to start',
            'Please refresh the page or check your server logs'
          );
          
          // Add a button to force continue anyway
          const retryCounterEl = document.getElementById('server-retry-counter');
          if (retryCounterEl && !document.getElementById('continue-button')) {
            const continueButton = document.createElement('button');
            continueButton.id = 'continue-button';
            continueButton.textContent = 'Continue Anyway';
            continueButton.style.cssText = `
              padding: 8px 16px;
              margin-top: 15px;
              background: #2a3b8f;
              color: white;
              border: none;
              border-radius: 4px;
              cursor: pointer;
              display: block;
              margin: 10px auto 0;
            `;
            continueButton.onclick = forceCleanupOverlay;
            retryCounterEl.after(continueButton);
          }
          
          clearTimeout(failsafeTimeout);
        }
      } catch (error) {
        console.error('Error during server connection attempt:', error);
        if (retryCount < MAX_RETRIES - 1) {
          retryCount++;
          const delay = Math.min(1000 * Math.pow(2, retryCount), 10000);
          console.log(`Retrying after error in ${delay}ms...`);
          setTimeout(attemptConnection, delay);
        } else {
          updateLoadingMessage(
            'Failed to connect to server',
            'Please check your connection and refresh the page'
          );
          clearTimeout(failsafeTimeout);
        }
      }
    }
    
    // Force cleanup function for when all else fails
    function forceCleanupOverlay() {
      console.warn('Forcing cleanup of server loading overlay');
      
      // Allow the application to continue loading regardless
      window.serverIsReady = true;
      
      // Unlock all pending scripts
      unlockPendingScripts();
      
      // Hide the overlay
      hideLoadingOverlay();
      
      // Dispatch an event that the application can listen for
      window.dispatchEvent(new Event('serverReady'));
    }
  }

  // Start the process
  waitForServer();
})();

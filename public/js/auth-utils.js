/**
 * Handles user logout by:
 * 1. Making a POST request to the logout endpoint
 * 2. Cleaning up WebSocket connections
 * 3. Redirecting to login page
 */
async function handleLogout() {
  try {
    // Clean up WebSocket connection with logout flag
    if (window.WebSocketManager) {
      try {
        // This will handle sending logout notification and cleanup
        window.WebSocketManager.cleanup(true); // true = isLogout
      } catch (wsError) {
        console.warn('Error during WebSocket cleanup:', wsError);
      }
    }
    
    // Clear any stored tokens or user data
    if (window.localStorage) {
      window.localStorage.removeItem('userToken');
      window.localStorage.removeItem('userData');
    }
    
    // Clear session storage
    if (window.sessionStorage) {
      window.sessionStorage.clear();
    }
    
    // Clear cookies
    document.cookie.split(';').forEach(cookie => {
      const [name] = cookie.trim().split('=');
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    });
    
    // Make the logout request
    const response = await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Logout failed with status: ${response.status}`);
    }
    
    // Redirect to login page after a short delay
    setTimeout(() => {
      window.location.href = '/login.html';
    }, 500);
    
  } catch (error) {
    console.error('Logout error:', error);
    // Even if there was an error, still redirect to login
    window.location.href = '/login.html';
  }
}

// Add logout handler to window for global access
if (typeof window !== 'undefined') {
  window.handleLogout = handleLogout;
  
  // Also add it to the window object for backward compatibility
  window.authUtils = {
    logout: handleLogout
  };
}

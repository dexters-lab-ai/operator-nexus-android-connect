import { eventBus } from './events.js';

const AUTH_TOKEN_KEY = 'authToken';
const USER_ID_KEY = 'userId';

// Check if user is authenticated
export const isAuthenticated = () => {
  return !!localStorage.getItem(AUTH_TOKEN_KEY);
};

// Get current user ID
export const getCurrentUserId = () => {
  return localStorage.getItem(USER_ID_KEY) || null;
};

// Set authentication state
export const setAuthState = (userId, token) => {
  if (userId && token) {
    localStorage.setItem(USER_ID_KEY, userId);
    localStorage.setItem(AUTH_TOKEN_KEY, token);
    eventBus.emit('auth-state-changed', { isAuthenticated: true, userId });
  } else {
    clearAuthState();
  }
};

// Clear authentication state
export const clearAuthState = () => {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem(USER_ID_KEY);
  eventBus.emit('auth-state-changed', { isAuthenticated: false, userId: null });
};

// Validate current session with server
export const validateSession = async () => {
  try {
    const response = await fetch('/api/auth/me', {
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    });

    if (response.ok) {
      const data = await response.json();
      if (data.authenticated && data.user) {
        setAuthState(data.user._id, data.token);
        return { isAuthenticated: true, user: data.user };
      }
    }
  } catch (error) {
    console.error('Session validation failed:', error);
  }
  
  clearAuthState();
  return { isAuthenticated: false, user: null };
};

// Initialize auth state on load
export const initializeAuth = async () => {
  return await validateSession();
};

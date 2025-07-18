
        // Simple auth state management
        export const AUTH_TOKEN_KEY = 'authToken';
        export const USER_ID_KEY = 'userId';
        
        export function setAuthState(userId, token) {
          if (userId && token) {
            localStorage.setItem(USER_ID_KEY, userId);
            localStorage.setItem(AUTH_TOKEN_KEY, token);
            return true;
          }
          return false;
        }
        
        export function clearAuthState() {
          localStorage.removeItem(AUTH_TOKEN_KEY);
          localStorage.removeItem(USER_ID_KEY);
        }
        
        export function isAuthenticated() {
          return !!localStorage.getItem(AUTH_TOKEN_KEY);
        }
      
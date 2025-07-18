/**
 * API utilities for OPERATOR
 * Provides consistent interface for all API interactions
 */

// Configuration for API requests
const isBrowser = typeof window !== 'undefined';
const isLocalhost = isBrowser && (window.location.hostname === 'localhost' || 
                                window.location.hostname === '127.0.0.1');

// Get environment from Vite or fall back to window.ENV (set in index.html)
const env = {
  MODE: typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env.MODE : 
       (isBrowser && window.ENV ? window.ENV.MODE : 'production'),
  PROD: typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env.PROD : 
       (isBrowser && window.ENV ? window.ENV.PROD : true),
  VITE_API_URL: typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env.VITE_API_URL : 
               (isBrowser && window.ENV ? window.ENV.VITE_API_URL : '')
};

const isProduction = env.PROD;

// Debug logging for environment
if (isBrowser) {
  console.log('[API Config]', {
    env: env.MODE,
    isProduction,
    isLocalhost,
    hostname: window.location.hostname,
    port: window.location.port,
    VITE_API_URL: env.VITE_API_URL,
    envSource: typeof import.meta !== 'undefined' ? 'vite' : 'window.ENV'
  });
}

// Determine the base API URL
let API_BASE = '';

// 1. Check for explicit API URL from environment first
if (env.VITE_API_URL) {
  API_BASE = env.VITE_API_URL;
  console.log('[API] Using VITE_API_URL from environment:', API_BASE);
} 
// 2. For local development
else if (isLocalhost) {
  const protocol = window.location.protocol;
  const hostname = window.location.hostname;
  API_BASE = `${protocol}//${hostname}:3420`;
  console.log('[API] Using local development URL:', API_BASE);
} 
// 3. For production
else if (isBrowser) {
  API_BASE = window.location.origin;
  console.log('[API] Using production URL:', API_BASE);
}

// Fallback if nothing else worked
if (!API_BASE && isBrowser) {
  API_BASE = window.location.origin;
  console.warn('[API] Using fallback URL:', API_BASE);
}

// Ensure API_BASE doesn't have a trailing slash
API_BASE = API_BASE.replace(/\/+$/, '');

// Common headers for all requests
const DEFAULT_HEADERS = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'X-Requested-With': 'XMLHttpRequest'
};

// Default fetch options
const DEFAULT_OPTIONS = {
  credentials: 'include', // Important: include cookies for auth
  mode: 'cors',
  cache: 'no-store',
  headers: DEFAULT_HEADERS,
  // Add CORS specific headers
  referrerPolicy: 'strict-origin-when-cross-origin'
};

// Log API configuration in development
if (!isProduction) {
  console.log('[API] Environment:', {
    isProduction,
    isLocalhost,
    VITE_API_URL: import.meta.env.VITE_API_URL,
    VITE_WS_URL: import.meta.env.VITE_WS_URL,
    API_BASE,
    location: window.location.href
  });
}

/**
 * General fetch wrapper with error handling
 * @param {string} url - The API endpoint to call
 * @param {Object} options - Fetch options to include
 * @returns {Promise<any>} - Response data
 */
/**
 * Enhanced fetch wrapper with standardized error handling and request/response interception
 * @param {string} url - The API endpoint to call
 * @param {Object} options - Fetch options to include
 * @returns {Promise<any>} - Parsed response data
 */
export async function fetchAPI(url, options = {}) {
  try {
    // Ensure URL is properly formatted
    let endpoint = url.startsWith('/') ? url : `/${url}`;
    if (!endpoint.startsWith('/api/')) {
      endpoint = `/api${endpoint}`;
    }
    
    // Always use the full URL with API_BASE in development and production
    const fullUrl = `${API_BASE}${endpoint}`;
    
    console.log('[API] Request:', {
      method: options.method || 'GET',
      url: fullUrl,
      isProduction,
      isLocalhost,
      API_BASE,
      endpoint
    });
    
    // Merge options with defaults
    const fetchOptions = {
      ...DEFAULT_OPTIONS,
      ...options,
      // Merge headers to preserve default headers
      headers: {
        ...DEFAULT_HEADERS,
        ...(options.headers || {})
      }
    };

    // Log request for debugging
    if (!isProduction) {
      console.log(`[API] ${fetchOptions.method || 'GET'} ${fullUrl}`, {
        options: fetchOptions,
        body: fetchOptions.body ? JSON.parse(fetchOptions.body) : undefined
      });
    }

    const response = await fetch(fullUrl, fetchOptions);
    const responseClone = response.clone(); // Clone for potential re-reading

    // Handle authentication errors
    if (response.status === 401) {
      // Only redirect if not already on login page
      if (!window.location.pathname.includes('login')) {
        window.location.href = '/login.html';
      }
      return null;
    }

    // Handle other error responses
    if (!response.ok) {
      let errorData;
      const contentType = response.headers.get('content-type');
      
      try {
        errorData = await responseClone.json();
      } catch (e) {
        const text = await responseClone.text();
        errorData = { error: text || 'Unknown error occurred' };
      }

      const error = new Error(errorData.error || `HTTP Error: ${response.status}`);
      error.status = response.status;
      error.data = errorData;
      
      // Log detailed error in development
      if (!isProduction) {
        console.error(`[API Error] ${response.status} ${response.statusText}`, {
          url: fullUrl,
          status: response.status,
          error: errorData,
          request: {
            method: fetchOptions.method,
            headers: fetchOptions.headers,
            body: fetchOptions.body ? JSON.parse(fetchOptions.body) : undefined
          }
        });
      }
      
      throw error;
    }

    // Parse successful response
    try {
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        return response.json();
      } else if (contentType.includes('text/')) {
        return response.text();
      } else if (response.status === 204) { // No content
        return null;
      } else {
        // For binary data or other content types
        return response.blob();
      }
    } catch (parseError) {
      console.error('Error parsing API response:', parseError);
      throw new Error('Failed to parse API response');
    }
  } catch (error) {
    // Handle network errors and other fetch-related issues
    if (!error.status) {
      console.error('[API] Network error:', error);
      throw new Error('Network error: Unable to connect to the server');
    }
    throw error; // Re-throw handled errors
  }
}

/**
 * GET request helper with enhanced query parameter handling
 * @param {string} url - The API endpoint
 * @param {Object} params - Query parameters to include
 * @param {Object} options - Additional fetch options
 * @returns {Promise<any>} - Response data
 */
export async function get(url, params = {}, options = {}) {
  // Create URLSearchParams for query string
  const queryParams = new URLSearchParams();
  
  // Add each parameter to the query string if it's not null or undefined
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      // Handle arrays by joining with commas
      if (Array.isArray(value)) {
        value.forEach(item => queryParams.append(key, String(item)));
      } else {
        queryParams.append(key, String(value));
      }
    }
  });
  
  // Build the full URL with query parameters
  const queryString = queryParams.toString();
  const fullUrl = queryString ? `${url}?${queryString}` : url;
  
  // Merge with any additional options
  const fetchOptions = {
    ...options,
    method: 'GET',
    // Remove body for GET requests as it's not allowed
    body: undefined
  };
  
  return fetchAPI(fullUrl, fetchOptions);
}

/**
 * POST request helper with enhanced options
 * @param {string} url - The API endpoint
 * @param {Object|FormData} data - Data to send in request body
 * @param {Object} options - Additional fetch options
 * @returns {Promise<any>} - Response data
 */
export async function post(url, data = {}, options = {}) {
  // Handle FormData differently (for file uploads)
  const isFormData = data instanceof FormData;
  
  const fetchOptions = {
    ...options,
    method: 'POST',
    body: isFormData ? data : JSON.stringify(data)
  };
  
  // Set Content-Type header automatically if not FormData
  if (!isFormData && !fetchOptions.headers?.['Content-Type']) {
    fetchOptions.headers = {
      ...fetchOptions.headers,
      'Content-Type': 'application/json'
    };
  }
  
  return fetchAPI(url, fetchOptions);
}

/**
 * PUT request helper with enhanced options
 * @param {string} url - The API endpoint
 * @param {Object|FormData} data - Data to send in request body
 * @param {Object} options - Additional fetch options
 * @returns {Promise<any>} - Response data
 */
export async function put(url, data = {}, options = {}) {
  // Handle FormData differently (for file uploads)
  const isFormData = data instanceof FormData;
  
  const fetchOptions = {
    ...options,
    method: 'PUT',
    body: isFormData ? data : JSON.stringify(data)
  };
  
  // Set Content-Type header automatically if not FormData
  if (!isFormData && !fetchOptions.headers?.['Content-Type']) {
    fetchOptions.headers = {
      ...fetchOptions.headers,
      'Content-Type': 'application/json'
    };
  }
  
  return fetchAPI(url, fetchOptions);
}

/**
 * PATCH request helper with enhanced options
 * @param {string} url - The API endpoint
 * @param {Object|FormData} data - Data to send in request body
 * @param {Object} options - Additional fetch options
 * @returns {Promise<any>} - Response data
 */
export async function patch(url, data = {}, options = {}) {
  // Handle FormData differently (for file uploads)
  const isFormData = data instanceof FormData;
  
  const fetchOptions = {
    ...options,
    method: 'PATCH',
    body: isFormData ? data : JSON.stringify(data)
  };
  
  // Set Content-Type header automatically if not FormData
  if (!isFormData && !fetchOptions.headers?.['Content-Type']) {
    fetchOptions.headers = {
      ...fetchOptions.headers,
      'Content-Type': 'application/json'
    };
  }
  
  return fetchAPI(url, fetchOptions);
}

/**
 * DELETE request helper with optional body
 * @param {string} url - The API endpoint
 * @param {Object|string} [data] - Optional data to send in request body
 * @param {Object} options - Additional fetch options
 * @returns {Promise<any>} - Response data
 */
export async function del(url, data = null, options = {}) {
  const fetchOptions = {
    ...options,
    method: 'DELETE'
  };
  
  // Add body if data is provided
  if (data !== null && data !== undefined) {
    fetchOptions.body = typeof data === 'object' ? JSON.stringify(data) : String(data);
    
    // Set Content-Type header if not already set and we have a body
    if (!fetchOptions.headers?.['Content-Type']) {
      fetchOptions.headers = {
        ...fetchOptions.headers,
        'Content-Type': typeof data === 'object' ? 'application/json' : 'text/plain'
      };
    }
  }
  
  return fetchAPI(url, fetchOptions);
}

/**
 * Delete the user's own account
 * @returns {Promise<any>} - Response data
 */
export async function deleteAccount() {
  return del('/api/auth/account');
}

/**
 * API service object with endpoint-specific methods
 * All methods automatically handle authentication, CORS, and error handling
 */
export const api = {
  // Chat-related endpoints
  chat: {
    /**
     * Get chat history with pagination
     * @param {number} page - Page number (1-based)
     * @param {number} limit - Items per page
     * @returns {Promise<Array>} - List of chat messages
     */
    getHistory: (page = 1, limit = 50) => 
      get('/chat/history', { page, limit }),
    
    /**
     * Send a new chat message
     * @param {Object} data - Message data { content, attachments?, metadata? }
     * @returns {Promise<Object>} - The sent message with server-generated fields
     */
    send: (data = {}) => 
      post('/chat/message', data, {
        headers: {
          'X-Request-ID': `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
        }
      })
  },
  
  // Task management endpoints
  tasks: {
    /**
     * Get list of active tasks
     * @returns {Promise<Array>} - List of active tasks
     */
    getActive: () => 
      get('/tasks/active'),
    
    /**
     * Create a new task
     * @param {string} command - Command to execute
     * @param {string} url - URL to process
     * @param {Object} [options] - Additional task options
     * @returns {Promise<Object>} - Created task data
     */
    create: (command, url, options = {}) => 
      post('/tasks', { command, url, ...options }),
    
    /**
     * Cancel a running task
     * @param {string} taskId - ID of the task to cancel
     * @returns {Promise<Object>} - Task status after cancellation
     */
    cancel: (taskId) => 
      post(`/tasks/${taskId}/cancel`)
  },
  
  // History endpoints
  history: {
    /**
     * Get paginated history
     * @param {number} page - Page number (1-based)
     * @param {number} limit - Items per page
     * @param {Object} [filters] - Filter criteria
     * @returns {Promise<{items: Array, total: number}>} - Paginated history items
     */
    getAll: (page = 1, limit = 20, filters = {}) => 
      get('/history', { page, limit, ...filters }),
    
    /**
     * Get a specific history item by ID
     * @param {string} id - History item ID
     * @returns {Promise<Object>} - History item details
     */
    getById: (id) => 
      get(`/history/${id}`),
    
    /**
     * Delete a history item
     * @param {string} id - History item ID to delete
     * @returns {Promise<{success: boolean}>} - Deletion status
     */
    delete: (id) => 
      del(`/history/${id}`)
  },
  
  // Authentication endpoints
  auth: {
    /**
     * User login
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<{user: Object, token: string}>} - User data and auth token
     */
    login: (email, password) => 
      post('/auth/login', { email, password }),
    
    /**
     * User registration
     * @param {string} email - User email
     * @param {string} password - User password
     * @param {Object} [userData] - Additional user data
     * @returns {Promise<{user: Object, token: string}>} - Created user data and auth token
     */
    register: (email, password, userData = {}) => 
      post('/auth/register', { email, password, ...userData }),
    
    /**
     * User logout
     * @returns {Promise<{success: boolean}>} - Logout status
     */
    logout: () => 
      post('/auth/logout'),
    
    /**
     * Get current user profile
     * @returns {Promise<Object>} - User profile data
     */
    getProfile: () => 
      get('/auth/me'),
      
    /**
     * Delete user account
     * @param {string} password - Current password for verification
     * @returns {Promise<{success: boolean}>} - Deletion status
     */
    deleteAccount: (password) => 
      del('/auth/account', { password }),
      
    /**
     * Refresh authentication token
     * @returns {Promise<{token: string}>} - New authentication token
     */
    refreshToken: () => 
      post('/auth/refresh-token')
  },
  
  // User settings endpoints
  settings: {
    /**
     * Get user settings
     * @returns {Promise<Object>} - User settings
     */
    get: () => 
      get('/settings'),
      
    /**
     * Update user settings
     * @param {Object} settings - Settings to update
     * @returns {Promise<Object>} - Updated settings
     */
    update: (settings) => 
      put('/settings', settings)
  },
  
  // File upload helper
  upload: {
    /**
     * Upload a file
     * @param {File|Blob} file - File to upload
     * @param {Object} [metadata] - Additional file metadata
     * @param {Function} [onProgress] - Progress callback
     * @returns {Promise<Object>} - Upload result with file details
     */
    file: (file, metadata = {}, onProgress) => {
      const formData = new FormData();
      formData.append('file', file);
      
      if (metadata) {
        Object.entries(metadata).forEach(([key, value]) => {
          formData.append(key, value);
        });
      }
      
      return post('/upload', formData, {
        onUploadProgress: onProgress ? 
          (progressEvent) => {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            onProgress(percentCompleted, progressEvent);
          } : undefined
      });
    }
  }
};

export default api;

import { isAuthenticated, setAuthState } from './utils/auth.js';
import { eventBus } from './utils/events.js';
import api from './utils/api.js';

// Make API available globally for debugging
window.api = api;

let isLogin = true;

function toggleForm() {
  isLogin = !isLogin;
  const formTitle = document.getElementById('form-title');
  const submitBtn = document.getElementById('submit-btn');
  const toggleLink = document.getElementById('toggle-link');
  const errorEl = document.getElementById('error-message');

  formTitle.textContent = isLogin ? 'Login' : 'Register';
  submitBtn.textContent = isLogin ? 'Login' : 'Register';
  toggleLink.textContent = isLogin ? 'Need an account? Register' : 'Already have an account? Login';
  errorEl.style.display = 'none';
  
  // Clear any previous input
  document.getElementById('email').value = '';
  document.getElementById('password').value = '';
}

function showError(message) {
  const errorEl = document.getElementById('error-message');
  if (errorEl) {
    errorEl.textContent = message;
    errorEl.style.display = 'block';
    
    // Auto-hide error after 5 seconds
    setTimeout(() => {
      errorEl.style.display = 'none';
    }, 5000);
  }
  console.error('Login Error:', message);
}

async function submitForm() {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value.trim();
  const errorEl = document.getElementById('error-message');
  const submitBtn = document.getElementById('submit-btn');
  const originalBtnText = submitBtn.textContent;

  if (!email || !password) {
    showError('Please fill out both fields.');
    return;
  }

  try {
    // Show loading state
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
    
    // Use the API utility for the request
    const response = isLogin 
      ? await api.auth.login(email, password)
      : await api.auth.register(email, password);
    
      console.log(response)
    if (response && response.user && response.token) {
      // Update auth state with user data and token
      setAuthState(response.user._id, response.token);
      
      // Redirect to dashboard or intended URL
      const redirectTo = new URLSearchParams(window.location.search).get('redirect') || '/';
      window.location.href = redirectTo;
      return;
    }
    
    throw new Error(response?.error || 'Authentication failed');
  } catch (error) {
    console.error('Auth error:', error);
    showError(error.message || 'An error occurred. Please try again.');
  } finally {
    // Reset button state
    submitBtn.disabled = false;
    submitBtn.textContent = originalBtnText;
  }
}



// Add form submission handler
document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const toggleLink = document.getElementById('toggle-link');
  
  if (loginForm) {
    loginForm.addEventListener('submit', (e) => {
      e.preventDefault();
      submitForm();
    });
  }
  
  if (toggleLink) {
    toggleLink.addEventListener('click', (e) => {
      e.preventDefault();
      toggleForm();
    });
  }
});
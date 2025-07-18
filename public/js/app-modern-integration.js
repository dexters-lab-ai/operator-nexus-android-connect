/**
 * OPERATOR - Modern Application Integration Module
 * This module initializes and integrates all modern UI components
 */

import { eventBus } from '../src/utils/events.js';
// WebSocketManager is now globally available via window.WebSocketManager
import * as App from '../src/api/index.js';
import { stores } from '../src/store/index.js';
import { getAllHistory } from '../src/api/history.js';
import { getMessageHistory } from '../src/api/messages.js';
import { submitNLI } from '../src/api/nli.js';
import { getActiveTasks, cancelTask } from '../src/api/tasks.js';
import { init3DScene } from './3d-scene-manager.js';
import { post } from '../src/utils/api-helpers.js';

// Import base components
import Button from '../src/components/base/Button.js';
import Modal from '../src/components/base/Modal.js';
import Tooltip from '../src/components/base/Tooltip.js';
import Dropdown from '../src/components/base/Dropdown.js';
import Tabs from '../src/components/base/Tabs.js';
import ProgressBar from '../src/components/base/ProgressBar.js';
import Alert from '../src/components/base/Alert.js';

// Import layout components
import NavigationBar from '../src/components/NavigationBar.js';
import Sidebar from '../src/components/Sidebar.js';
import TaskBar from '../src/components/TaskBar.js';
import MessageTimeline from '../src/components/MessageTimeline.js';
import CommandCenter from '../src/components/CommandCenter.js';
import HistoryOverlay from '../src/components/HistoryOverlay.js';
import Notifications from '../src/components/Notifications.js';
import ThemeController from '../src/components/ThemeController.js';
import LayoutManager from '../src/components/LayoutManager.js';

// Import 3D experience
import RoomEntryPoint from '../src/3d/RoomEntryPoint.js';

/**
 * Initialize the modern UI components and integrate them
 * @param {Object} options - Initialization options
 * @returns {Object} Component references and utilities
 */
export async function initializeModernUI(options = {}) {
  // Destructure options and set defaults
  const {
    rootElement = document.body,
    skipRoomExperience = false,
    initialLayoutPreset = 'default',
    modelPath = '/models/roomModel.glb'  // Files in public/ are served from root
  } = options;

  // Initialize debug panel first
  let debugPanel = null;
  function initDebugPanel() {
    debugPanel = document.createElement('div');
    debugPanel.style.cssText = `
      position: fixed;
      bottom: 0;
      left: 0;
      background: rgba(0,0,0,0.7);
      color: white;
      padding: 8px;
      font-family: monospace;
      z-index: 9999;
    `;
    document.body.appendChild(debugPanel);
  }

  function updateDebugPanel(message) {
    if (debugPanel) {
      debugPanel.textContent = message;
    }
  }

  // Initialize debug panel early
  initDebugPanel();

  // Patch fetch to log API calls and errors globally
  const origFetch = window.fetch;
  window.fetch = async (...args) => {
    try {
      const res = await origFetch(...args);
      if (!res.ok) {
        updateDebugPanel(`[API ERROR] ${args[0]}: ${res.status} ${res.statusText}`);
      } else {
        updateDebugPanel(`[API OK] ${args[0]}`);
      }
      return res;
    } catch (err) {
      updateDebugPanel(`[API FAIL] ${args[0]}: ${err.message}`);
      throw err;
    }
  };

  // Initialize NavigationBar first and append to appRoot
  const components = {};
  try {
    const NavBar = await import('../src/components/NavigationBar.js');
    components.navigationBar = NavBar.default({ containerId: 'main-navigation' });
    // Attach to appRoot at the top
    const appRoot = document.getElementById('app-root') || createAppRoot();
    appRoot.insertBefore(components.navigationBar, appRoot.firstChild);
    // Debug styling (optional, remove for production)
    components.navigationBar.style.outline = '2px solid red';
    components.navigationBar.style.position = 'relative';
    components.navigationBar.style.zIndex = '9999';
  } catch (err) {
    console.error('[APP] NavigationBar failed:', err);
    const errorDiv = document.createElement('div');
    errorDiv.textContent = 'NAVBAR ERROR: ' + err.message;
    errorDiv.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      padding: 1rem;
      background: #ff0000;
      color: white;
      z-index: 9999;
    `;
    document.body.prepend(errorDiv);
  }

  // Continue initializing other components as before
  components.layoutManager = null;
  components.sidebar = null;
  components.notifications = null;
  // ... (rest of your initialization logic for these components)


  // Component instances
  // Create root container if needed
  const appRoot = document.getElementById('app-root') || createAppRoot();
  
  /**
   * Create the application root element
   * @returns {HTMLElement} App root element
   */
  function createAppRoot() {
    const root = document.createElement('div');
    root.id = 'app-root';
    rootElement.appendChild(root);
    return root;
  }

  /**
   * Initialize theme controller
   */
  function initThemeController() {
    try {
      components.themeController = ThemeController({
        defaultTheme: 'dark',
        defaultFontSize: 'medium',
        api: { post }
      });
      console.log('[INIT] ThemeController created');
      // Apply saved theme if available
      const savedTheme = localStorage.getItem('operator_theme') || 'dark';
      try {
        components.themeController.setTheme(savedTheme);
      } catch (error) {
        console.error('Failed to set initial theme:', error);
        components.themeController.setTheme('dark', false);
      }
    } catch (err) {
      console.error('[ERROR] ThemeController failed to create:', err);
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'Theme Controller Error',
          message: err.message,
          type: 'error'
        });
      }
    }
  }

  /**
   * Initialize notifications system
   */
  function initNotifications() {
    try {
      components.notifications = Notifications({
        position: 'top-right',
        duration: 5000
      });
      console.log('[INIT] Notifications created');
      appRoot.appendChild(components.notifications);
      console.log('[INIT] Notifications appended to DOM');
    } catch (err) {
      console.error('[ERROR] Notifications failed to create/append:', err);
    }
  }

  /**
   * Initialize layout manager
   */
  function initLayoutManager() {
    try {
      components.layoutManager = LayoutManager({
        containerId: 'layout-manager',
        presets: {
          default: { sidebar: true, width: '240px' },
          centered: { sidebar: false, maxWidth: '800px' },
          focus: { sidebar: false, padding: '0' },
          expanded: { sidebar: true, width: '300px' }
        }
      });
      
      // Setup layout change handler
      eventBus.on('layout-change-requested', ({ preset, callback }) => {
        try {
          if (components.layoutManager?.setLayoutPreset) {
            components.layoutManager.setLayoutPreset(preset);
            callback(true);
          } else {
            console.warn('LayoutManager not properly initialized');
            callback(false);
          }
        } catch (err) {
          console.error('Layout change failed:', err);
          components.notifications?.addNotification({
            title: 'Layout Error',
            message: 'Failed to change layout',
            type: 'error'
          });
          callback(false);
        }
      });
      
      // Add layout styles
      const style = document.createElement('style');
      style.textContent = `
        .dropdown-menu.layout-menu {
          min-width: 280px;
          padding: 8px 0;
        }
        .layout-option {
          display: flex;
          align-items: center;
          padding: 12px 16px;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .layout-option:hover {
          background: rgba(var(--color-primary-rgb), 0.1);
        }
        .layout-option.active {
          background: rgba(var(--color-primary-rgb), 0.05);
        }
        .layout-option.loading {
          opacity: 0.7;
          pointer-events: none;
        }
        .layout-icon {
          margin-right: 12px;
          font-size: 1.2em;
          color: var(--color-primary);
        }
        .layout-info {
          flex: 1;
        }
        .layout-name {
          font-weight: 500;
        }
        .layout-description {
          font-size: 0.85em;
          opacity: 0.8;
          margin-top: 2px;
        }
        .layout-check {
          opacity: 0;
          color: var(--color-primary);
        }
        .layout-option.active .layout-check {
          opacity: 1;
        }
      `;
      document.head.appendChild(style);
      
      console.log('[INIT] LayoutManager initialized');
    } catch (err) {
      console.error('[ERROR] LayoutManager failed:', err);
      components.notifications?.addNotification({
        title: 'Layout Error',
        message: 'Failed to initialize layout manager',
        type: 'error'
      });
    }
  }

  /**
   * Initialize navigation components
   */
  function initNavigationComponents() {
    // ... (existing sidebarItems and logic)
    // For brevity, keep your full sidebarItems and logic here
  }

  // ... (repeat for all other helper/init functions that were previously at module level)

  async function initializeAll() {
    // First initialize theme and notifications
    initThemeController();
    initNotifications();
    // Then initialize layout
    initLayoutManager();
    // Initialize main components
    initNavigationComponents();
    // Create sidebar items
    const sidebarItems = [
      {
        text: 'Dashboard',
        icon: 'fa-tachometer-alt',
        action: () => {
          // Handle dashboard action
          eventBus.emit('navigation-change', { page: 'dashboard' });
        }
      },
      {
        text: 'Commands',
        icon: 'fa-terminal',
        action: () => {
          // Handle commands action
          eventBus.emit('navigation-change', { page: 'commands' });
        }
      },
      {
        text: 'Recent History',
        icon: 'fa-history',
        action: () => {
          // Show history overlay
          eventBus.emit('toggle-history-overlay');
        }
      },
      { type: 'divider', label: 'Resources' },
      {
        text: 'Documentation',
        icon: 'fa-book',
        action: () => {
          // Handle documentation action
          eventBus.emit('navigation-change', { page: 'documentation' });
        }
      },
      {
        text: 'Extensions',
        icon: 'fa-puzzle-piece',
        action: () => {
          // Handle extensions action
          eventBus.emit('navigation-change', { page: 'extensions' });
        }
      }
    ];

    // Create sidebar
    try {
      components.sidebar = Sidebar({
        containerId: 'main-sidebar',
        position: 'left',
        collapsed: false,
        items: sidebarItems
      });
      console.log('[INIT] Sidebar created');
    } catch (err) {
      console.error('[ERROR] Sidebar failed to create:', err);
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'Sidebar Error',
          message: err.message,
          type: 'error'
        });
      }
    }

    // Initialize core UI that should persist
    async function initializePersistentUI() {
      const components = {};
      
      try {
        // Create and mount NavigationBar directly to body
        const NavBar = await import('../src/components/NavigationBar.js');
        components.navigationBar = NavBar.default({ containerId: 'main-navigation' });
        document.body.prepend(components.navigationBar);
        
        // Style for visibility during debug
        components.navigationBar.style.outline = '2px solid red';
        components.navigationBar.style.position = 'fixed';
        components.navigationBar.style.zIndex = '9999';
        
        return components;
      } catch (err) {
        console.error('[APP] Persistent UI failed:', err);
        const errorDiv = document.createElement('div');
        errorDiv.textContent = 'UI Error: ' + err.message;
        errorDiv.style.cssText = `
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          padding: 1rem;
          background: #ff0000;
          color: white;
          z-index: 9999;
        `;
        document.body.prepend(errorDiv);
        return components;
      }
    }

    // Call this early in your bootstrap process
    const persistentUI = await initializePersistentUI();

    // Create back button and inject into navigation bar after launch
    components.backButton = null;
    eventBus.on('application-ready', () => {
      if (!components.backButton) {
        import('../src/components/BackButton.js').then(({ default: BackButton }) => {
          components.backButton = BackButton({
            onBack: () => eventBus.emit('exit-application'),
            containerId: 'back-btn'
          });
          // Insert back button into navigation bar
          if (components.navigationBar && components.navigationBar.appendChild) {
            components.navigationBar.appendChild(components.backButton);
          }
        });
      } else {
        // Already exists, just show it
        components.backButton.style.display = '';
      }
    });
    eventBus.on('exit-application', () => {
      if (components.backButton) components.backButton.style.display = 'none';
    });

    // Add to layout with runtime checks
    if (typeof components.layoutManager.setNavigation === 'function') {
      components.layoutManager.setNavigation(components.navigationBar);
    } else {
      console.error('LayoutManager is missing setNavigation method.');
    }
    if (typeof components.layoutManager.setSidebar === 'function') {
      components.layoutManager.setSidebar(components.sidebar);
    } else {
      console.error('LayoutManager is missing setSidebar method.');
    }
  }

  /**
   * Initialize main content components
   */
  async function initContentComponents() {
    // --- Unified Message Timeline ---
    try {
      // Remove any existing timeline to avoid duplicates
      const oldTimeline = document.getElementById('message-timeline');
      if (oldTimeline) oldTimeline.innerHTML = '';
      // Create and mount MessageTimeline (already imported)
      components.messageTimeline = MessageTimeline({
        containerId: 'message-timeline',
        initialFilter: 'all',
        animated: true // Custom prop for enhanced animation
      });
      // Add cyberpunk/frosty-glass effect
      const timelineEl = document.getElementById('message-timeline');
      if (timelineEl) {
        timelineEl.style.backdropFilter = 'blur(16px) saturate(180%)';
        timelineEl.style.background = 'rgba(30,40,60,0.55)';
        timelineEl.style.borderRadius = '22px';
        timelineEl.style.boxShadow = '0 8px 32px 0 rgba(31,38,135,0.37)';
        timelineEl.style.transition = 'all 0.5s cubic-bezier(.6,.2,.1,1.0)';
      }
      console.log('[INIT] MessageTimeline created');
    } catch (err) {
      console.error('[ERROR] MessageTimeline failed to create:', err);
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'Message Timeline Error',
          message: err.message,
          type: 'error'
        });
      }
    }

    // --- Command Center (NLI chat input) ---
    function initCommandCenter() {
      try {
        components.commandCenter = CommandCenter({
          containerId: 'command-center',
          onSubmit: async (input) => {
            try {
              const response = await submitNLI(input);
              components.notifications.addNotification({
                title: 'Command submitted',
                message: 'Your command is being processed',
                type: 'success'
              });
              return response;
            } catch (error) {
              components.notifications.addNotification({
                title: 'Command failed',
                message: error.message,
                type: 'error'
              });
              throw error;
            }
          },
          onClear: () => {
            components.notifications.addNotification({
              title: 'Input cleared',
              type: 'info'
            });
          }
        });
        
        // Ensure proper styling
        components.commandCenter.style.cssText = `
          position: relative;
          width: 100%;
          max-width: 800px;
          margin: 0 auto;
          padding: 20px;
          background: var(--color-background-secondary);
          border-radius: 12px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        `;
        
        // Add to DOM
        appRoot.appendChild(components.commandCenter);
        
        // Load Font Awesome for icons
        const faLink = document.createElement('link');
        faLink.rel = 'stylesheet';
        faLink.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css';
        faLink.integrity = 'sha512-1ycn6IcaQQ40/MKBW2W4Rhis/DbILU74C1vSrLJxCq57o941Ym01SwNsOMqvEBFlcgUa6xLiPY/NS5R+E6ztJQ==';
        faLink.crossOrigin = 'anonymous';
        document.head.appendChild(faLink);
        
        console.log('[INIT] CommandCenter initialized with NLI input');
      } catch (err) {
        console.error('[ERROR] CommandCenter failed:', err);
        components.notifications?.addNotification({
          title: 'Command Center Error',
          message: err.message,
          type: 'error'
        });
      }
    }
    initCommandCenter();

    // Add to layout with runtime check
    if (typeof components.layoutManager.setContent === 'function') {
      components.layoutManager.setContent({
        messageTimeline: components.messageTimeline,
        commandCenter: components.commandCenter
      });
    } else {
      console.error('LayoutManager is missing setContent method.');
    }

    // --- Chat/NLI Form Handler (migrated from src/app.js) ---
    // Ensure unified input form handler is present
    setTimeout(() => {
      const unifiedForm = document.getElementById('unified-input-form');
      if (unifiedForm && !unifiedForm._hasHandler) {
        const promptInput = unifiedForm.querySelector('input[type="text"], textarea');
        const submitButton = unifiedForm.querySelector('button[type="submit"]');
        unifiedForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          const prompt = promptInput.value.trim();
          if (!prompt) return;
          if (submitButton) submitButton.disabled = true;
          eventBus.emit('notification', { message: 'Sending...', type: 'info' });
          try {
            const response = await fetch('/nli', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
              credentials: 'include',
              body: JSON.stringify({ prompt })
            });
            const data = await response.json();
            if (data.success && data.assistantReply) {
              eventBus.emit('new-message', { role: 'assistant', type: 'chat', content: data.assistantReply, timestamp: new Date() });
            } else if (data.success && data.taskId) {
              eventBus.emit('notification', { message: 'Task started', type: 'success' });
            } else {
              throw new Error(data.error || 'No response');
            }
            promptInput.value = '';
          } catch (err) {
            eventBus.emit('new-message', { role: 'system', type: 'error', content: 'Failed to send message', error: err.message, timestamp: new Date() });
            eventBus.emit('notification', { message: 'Failed to send message', type: 'error' });
          } finally {
            if (submitButton) submitButton.disabled = false;
          }
        });
        unifiedForm._hasHandler = true;
      }
    }, 700);

    // --- Animate timeline on new message ---
    eventBus.on('new-message', (msg) => {
      const timelineEl = document.getElementById('message-timeline');
      if (timelineEl) {
        timelineEl.classList.remove('animate-pop');
        void timelineEl.offsetWidth; // trigger reflow
        timelineEl.classList.add('animate-pop');
        setTimeout(() => timelineEl.classList.remove('animate-pop'), 800);
      }
    });
  }

  /**
   * Initialize overlay components
   */
  function initOverlayComponents() {
    // Create history overlay
    try {
      components.historyOverlay = HistoryOverlay({
        containerId: 'history-overlay'
      });
      console.log('[INIT] HistoryOverlay created');
    } catch (err) {
      console.error('[ERROR] HistoryOverlay failed to create:', err);
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'History Overlay Error',
          message: err.message,
          type: 'error'
        });
      }
    }

    // Add to DOM
    try {
      appRoot.appendChild(components.historyOverlay);
      console.log('[INIT] HistoryOverlay appended to DOM');
    } catch (err) {
      console.error('[ERROR] Failed to append HistoryOverlay:', err);
    }

    // Listen for event to show/hide overlay
    eventBus.on('toggle-history-overlay', () => {
      if (components.historyOverlay && typeof components.historyOverlay.toggle === 'function') {
        components.historyOverlay.toggle();
      } else {
        // fallback: toggle display
        if (components.historyOverlay.style.display === 'block') {
          components.historyOverlay.style.display = 'none';
        } else {
          components.historyOverlay.style.display = 'block';
        }
      }
    });
  }

  /**
   * Initialize task bar
   */
  function initTaskBar() {
    try {
      components.taskBar = TaskBar({
        containerId: 'task-bar'
      });
      console.log('[INIT] TaskBar created');
    } catch (err) {
      console.error('[ERROR] TaskBar failed to create:', err);
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'Task Bar Error',
          message: err.message,
          type: 'error'
        });
      }
    }

    // Add to layout
    try {
      components.layoutManager.setTaskBar(components.taskBar);
      console.log('[INIT] TaskBar set in LayoutManager');
    } catch (err) {
      console.error('[ERROR] Failed to set TaskBar in LayoutManager:', err);
    }
  }

  /**
   * Set up global event handlers
   */
  function setupEventHandlers() {
    // Handle theme changes
    eventBus.on('theme-change', (data) => {
      components.themeController.setTheme(data.theme);
    });

    // Handle layout preset changes
    eventBus.on('layout-preset-requested', (data) => {
      components.layoutManager.setLayoutPreset(data.preset);
    });

    // Handle history overlay toggle
    eventBus.on('toggle-history-overlay', () => {
      components.historyOverlay.toggle();
    });

    // Handle settings toggle
    eventBus.on('toggle-settings', () => {
      // Show settings modal
      const settingsContent = document.createElement('div');
      settingsContent.innerHTML = `
        <div class="settings-tabs">
          <button class="settings-tab active">General</button>
          <button class="settings-tab">Appearance</button>
          <button class="settings-tab">Notifications</button>
          <button class="settings-tab">Advanced</button>
        </div>
        <div class="settings-content">
          <div class="setting-group">
            <div class="setting-label">
              <h3>Theme</h3>
              <p class="setting-description">Choose your preferred interface theme</p>
            </div>
            <div class="setting-control">
              <select class="setting-select" id="theme-select">
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select>
            </div>
          </div>
          <div class="setting-group">
            <div class="setting-label">
              <h3>Font Size</h3>
              <p class="setting-description">Adjust the text size throughout the application</p>
            </div>
            <div class="setting-control">
              <select class="setting-select" id="font-size-select">
                <option value="small">Small</option>
                <option value="medium">Medium</option>
                <option value="large">Large</option>
              </select>
            </div>
          </div>
          <div class="setting-group">
            <div class="setting-label">
              <h3>Animation Effects</h3>
              <p class="setting-description">Enable or disable interface animations</p>
            </div>
            <div class="setting-control">
              <label class="toggle-switch">
                <input type="checkbox" id="animations-toggle" checked>
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>
        </div>
      `;

      // Create modal
      const settingsModal = Modal({
        title: 'Settings',
        content: settingsContent,
        size: 'large',
        className: 'settings-modal',
        footer: Button({
          text: 'Save Changes',
          variant: Button.VARIANTS.PRIMARY,
          onClick: () => {
            // Save settings
            const themeSelect = document.getElementById('theme-select');
            const fontSizeSelect = document.getElementById('font-size-select');
            const animationsToggle = document.getElementById('animations-toggle');

            if (themeSelect) {
              components.themeController.setTheme(themeSelect.value);
            }

            if (fontSizeSelect) {
              components.themeController.setFontSize(fontSizeSelect.value);
            }

            // Close modal
            settingsModal.hide();

            // Show confirmation
            components.notifications.addNotification({
              title: 'Settings Saved',
              message: 'Your preferences have been updated',
              type: 'success'
            });
          }
        })
      });

      // Show the modal
      settingsModal.show();

      // Set current values
      const themeSelect = document.getElementById('theme-select');
      const fontSizeSelect = document.getElementById('font-size-select');

      if (themeSelect) {
        themeSelect.value = components.themeController.getCurrentTheme();
      }

      if (fontSizeSelect) {
        fontSizeSelect.value = components.themeController.getCurrentFontSize();
      }
    });
  }

  /**
   * Initialize all components
   */
  async function initializeAll() {
    // First initialize theme and notifications
    initThemeController();
    initNotifications();

    // Then initialize layout
    initLayoutManager();

    // Initialize main components
    initNavigationComponents();
    initContentComponents();
    initOverlayComponents();
    initTaskBar();

    // Set up event handlers
    setupEventHandlers();

    // --- 3D Room Experience Integration (Bruno Simon style) ---
    // Hide main app UI initially
    if (components.layoutManager?.element) components.layoutManager.element.style.display = 'none';
    if (components.sidebar?.element) components.sidebar.element.style.display = 'none';
    if (components.navigationBar) components.navigationBar.style.display = 'none';

    // Create or get the room container
    let roomContainer = document.getElementById('room-experience-container');
    if (!roomContainer) {
      roomContainer = document.createElement('div');
      roomContainer.id = 'room-experience-container';
      roomContainer.style.position = 'fixed';
      roomContainer.style.top = '0';
      roomContainer.style.left = '0';
      roomContainer.style.width = '100%';
      roomContainer.style.height = '100%';
      roomContainer.style.zIndex = '2000';
      appRoot.appendChild(roomContainer);
    }

    // Mount the 3D experience using Bruno's RoomEntryPoint
    RoomEntryPoint.mount(roomContainer, { modelPath });

    // Listen for the event to transition from 3D to main app
    eventBus.once('launch-application', () => {
      roomContainer.remove();
      // Show the main app UI
      if (components.layoutManager?.element) components.layoutManager.element.style.display = '';
      if (components.sidebar?.element) components.sidebar.element.style.display = '';
      if (components.navigationBar) components.navigationBar.style.display = '';
      // Optionally, emit 'application-ready' if you want
      eventBus.emit('application-ready');
      // Show welcome notification
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'Welcome to OPERATOR',
          message: 'The modern interface is now ready to use',
          type: 'success'
        });
      }
    });
    // For backward compatibility, also listen for 'initialize-application'
    eventBus.once('initialize-application', () => {
      roomContainer.remove();
      if (components.layoutManager?.element) components.layoutManager.element.style.display = '';
      if (components.sidebar?.element) components.sidebar.element.style.display = '';
      if (components.navigationBar) components.navigationBar.style.display = '';
      eventBus.emit('application-ready');
      if (components.notifications) {
        components.notifications.addNotification({
          title: 'Welcome to OPERATOR',
          message: 'The modern interface is now ready to use',
          type: 'success'
        });
      }
    });

    // Notify that all components have been initialized
    eventBus.emit('application-ready');

    // Return component references
    return components;
  }
  
  // Initialize everything and return component references
  return await initializeAll();
}

export default {
  initialize: initializeModernUI
};

// Provide global mountApp entry point for legacy bootstrap
window.mountApp = (selectorOrElement, options = {}) => {
  const container = typeof selectorOrElement === 'string'
    ? document.querySelector(selectorOrElement)
    : selectorOrElement;
  if (!container) throw new Error(`mountApp: container ${selectorOrElement} not found`);
  return initializeModernUI({ rootElement: container, ...options });
};

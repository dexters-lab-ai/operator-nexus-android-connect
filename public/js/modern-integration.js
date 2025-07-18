/**
 * Modern Integration Entry Point
 * 
 * This file serves as the entry point for integrating modern components
 * into the existing application using the "Islands of Interactivity" approach.
 * It creates mount points for modern components and bridges communication
 * between legacy and modern code.
 */

import { App } from '../src/components/App.js';
import { CommandCenter } from '../src/components/CommandCenter.js';
import { MessageTimeline } from '../src/components/MessageTimeline.js';
import { initializeBridge } from './utils/bridge.js';
import { stores } from './store/index.js';
import { eventBus } from '../src/utils/events.js';

// Feature flags to control which components are upgraded
const FEATURE_FLAGS = {
  // Set these to true to enable the modern components
  USE_MODERN_COMMAND_CENTER: false,
  USE_MODERN_TIMELINE: false,
  USE_MODERN_TASK_RESULTS: false,
  USE_MODERN_LAYOUT: false,
  // Development flags
  DEBUG_MODE: true
};

// Log level
const LOG_LEVEL = FEATURE_FLAGS.DEBUG_MODE ? 'debug' : 'info';

/**
 * Initialize the modern integration
 */
export function initializeModernIntegration() {
  // Set up bridge between legacy and modern code
  initializeBridge();
  
  // Initialize logger
  const logger = createLogger('modern-integration', LOG_LEVEL);
  logger.info('Initializing modern integration...');
  
  // Create mount points for modern components if they don't exist
  createMountPoints();
  
  // Initialize modern components based on feature flags
  initializeComponents();
  
  // Set up layout customization features
  if (FEATURE_FLAGS.USE_MODERN_LAYOUT) {
    initializeLayoutSystem();
  }
  
  logger.info('Modern integration initialized successfully');
}

/**
 * Create DOM mount points for modern components
 */
function createMountPoints() {
  const mountPoints = [
    { id: 'modern-command-center-mount', adjacentTo: '.command-center', position: 'after' },
    { id: 'modern-timeline-mount', adjacentTo: '#message-timeline', position: 'after' },
    { id: 'modern-task-results-mount', adjacentTo: '#output-card', position: 'after' }
  ];
  
  mountPoints.forEach(({ id, adjacentTo, position }) => {
    // Check if mount point already exists
    if (!document.getElementById(id)) {
      const adjacentElement = document.querySelector(adjacentTo);
      
      if (adjacentElement) {
        // Create mount point element
        const mountPoint = document.createElement('div');
        mountPoint.id = id;
        mountPoint.classList.add('modern-mount-point');
        
        // Insert mount point
        if (position === 'before') {
          adjacentElement.parentNode.insertBefore(mountPoint, adjacentElement);
        } else if (position === 'after') {
          if (adjacentElement.nextSibling) {
            adjacentElement.parentNode.insertBefore(mountPoint, adjacentElement.nextSibling);
          } else {
            adjacentElement.parentNode.appendChild(mountPoint);
          }
        } else if (position === 'replace') {
          // Hide the original element but keep it for reverting
          adjacentElement.style.display = 'none';
          adjacentElement.classList.add('legacy-hidden');
          adjacentElement.parentNode.insertBefore(mountPoint, adjacentElement);
        }
      }
    }
  });
}

/**
 * Initialize modern components based on feature flags
 */
function initializeComponents() {
  const logger = createLogger('component-init', LOG_LEVEL);
  
  // Initialize Command Center if enabled
  if (FEATURE_FLAGS.USE_MODERN_COMMAND_CENTER) {
    const mountPoint = document.getElementById('modern-command-center-mount');
    
    if (mountPoint) {
      logger.debug('Mounting modern CommandCenter component');
      
      // Hide legacy command center
      const legacyCommandCenter = document.querySelector('.command-center');
      if (legacyCommandCenter) {
        legacyCommandCenter.style.display = 'none';
        legacyCommandCenter.classList.add('legacy-hidden');
      }
      
      // Mount modern component
      CommandCenter.mount(mountPoint, { 
        initialTab: 'nli',
        containerId: 'modern-command-center'
      });
      
      // Add to registry of mounted components
      window.__OPERATOR_MODERN__.mountedComponents = window.__OPERATOR_MODERN__.mountedComponents || {};
      window.__OPERATOR_MODERN__.mountedComponents.commandCenter = true;
    } else {
      logger.error('Mount point for CommandCenter not found');
    }
  }
  
  // Initialize Message Timeline if enabled
  if (FEATURE_FLAGS.USE_MODERN_TIMELINE) {
    const mountPoint = document.getElementById('modern-timeline-mount');
    
    if (mountPoint) {
      logger.debug('Mounting modern MessageTimeline component');
      
      // Hide legacy timeline
      const legacyTimeline = document.querySelector('#message-timeline');
      if (legacyTimeline) {
        legacyTimeline.style.display = 'none';
        legacyTimeline.classList.add('legacy-hidden');
      }
      
      // Mount modern component
      MessageTimeline.mount(mountPoint, {
        containerId: 'modern-message-timeline',
        initialFilter: 'all'
      });
      
      // Add to registry of mounted components
      window.__OPERATOR_MODERN__.mountedComponents = window.__OPERATOR_MODERN__.mountedComponents || {};
      window.__OPERATOR_MODERN__.mountedComponents.messageTimeline = true;
    } else {
      logger.error('Mount point for MessageTimeline not found');
    }
  }
  
  // Initialize Task Results if enabled
  if (FEATURE_FLAGS.USE_MODERN_TASK_RESULTS) {
    const mountPoint = document.getElementById('modern-task-results-mount');
    
    if (mountPoint) {
      logger.debug('Mounting modern TaskResults component');
      
      // Hide legacy task results
      const legacyTaskResults = document.querySelector('#output-card');
      if (legacyTaskResults) {
        legacyTaskResults.style.display = 'none';
        legacyTaskResults.classList.add('legacy-hidden');
      }
      
      // Create and mount task results component (to be implemented)
      // This will be implemented in a future update
      
      // Add to registry of mounted components
      window.__OPERATOR_MODERN__.mountedComponents = window.__OPERATOR_MODERN__.mountedComponents || {};
      window.__OPERATOR_MODERN__.mountedComponents.taskResults = true;
    } else {
      logger.error('Mount point for TaskResults not found');
    }
  }
}

/**
 * Initialize the modern layout system
 */
function initializeLayoutSystem() {
  const logger = createLogger('layout-system', LOG_LEVEL);
  logger.info('Initializing modern layout system');
  
  // Create layout toggle in header if it doesn't exist
  if (!document.getElementById('layout-toggle')) {
    const headerTools = document.querySelector('.header-tools');
    
    if (headerTools) {
      const layoutToggle = document.createElement('button');
      layoutToggle.id = 'layout-toggle';
      layoutToggle.className = 'header-tool';
      layoutToggle.innerHTML = '<i class="fas fa-columns"></i>';
      layoutToggle.title = 'Toggle Layout';
      
      // Add layout dropdown
      const layoutMenu = document.createElement('div');
      layoutMenu.className = 'layout-menu dropdown-menu';
      
      // Layout presets
      const layoutPresets = [
        { id: 'default', name: 'Default', icon: 'fa-columns' },
        { id: 'centered', name: 'Centered', icon: 'fa-align-center' },
        { id: 'focus', name: 'Focus Mode', icon: 'fa-bullseye' },
        { id: 'expanded', name: 'Expanded', icon: 'fa-expand' }
      ];
      
      layoutPresets.forEach(preset => {
        const presetOption = document.createElement('a');
        presetOption.href = '#';
        presetOption.className = 'dropdown-item';
        presetOption.innerHTML = `<i class="fas ${preset.icon}"></i> ${preset.name}`;
        presetOption.dataset.preset = preset.id;
        
        presetOption.addEventListener('click', (e) => {
          e.preventDefault();
          applyLayoutPreset(preset.id);
        });
        
        layoutMenu.appendChild(presetOption);
      });
      
      // Append layout menu to layout toggle
      layoutToggle.appendChild(layoutMenu);
      
      // Toggle dropdown on click
      layoutToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        layoutMenu.classList.toggle('show');
      });
      
      // Close dropdown when clicking elsewhere
      document.addEventListener('click', () => {
        layoutMenu.classList.remove('show');
      });
      
      // Add to header tools
      headerTools.appendChild(layoutToggle);
    }
  }
  
  // Initialize with default layout
  applyLayoutPreset('default');
}

/**
 * Apply a layout preset
 * @param {string} presetId - ID of the preset to apply
 */
function applyLayoutPreset(presetId) {
  const logger = createLogger('layout-system', LOG_LEVEL);
  logger.info(`Applying layout preset: ${presetId}`);
  
  // Update state
  stores.ui.setState({ layoutPreset: presetId });
  
  // Apply layout classes to body
  document.body.className = document.body.className
    .replace(/layout-preset-\w+/g, '')
    .trim();
  document.body.classList.add(`layout-preset-${presetId}`);
  
  // Emit event
  eventBus.emit('layout-preset-changed', { preset: presetId });
  
  // Update UI visually
  const layoutToggle = document.getElementById('layout-toggle');
  if (layoutToggle) {
    const presetOptions = layoutToggle.querySelectorAll('.dropdown-item');
    presetOptions.forEach(option => {
      option.classList.toggle('active', option.dataset.preset === presetId);
    });
  }
}

/**
 * Simple logger function
 * @param {string} context - Logging context
 * @param {string} level - Log level (debug, info, warn, error)
 * @returns {Object} Logger object
 */
function createLogger(context, level = 'info') {
  const LOG_LEVELS = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3
  };
  
  const shouldLog = (messageLevel) => {
    return LOG_LEVELS[messageLevel] >= LOG_LEVELS[level];
  };
  
  return {
    debug: (...args) => {
      if (shouldLog('debug')) {
        //console.debug(`[${context}]`, ...args);
      }
    },
    info: (...args) => {
      if (shouldLog('info')) {
        //console.info(`[${context}]`, ...args);
      }
    },
    warn: (...args) => {
      if (shouldLog('warn')) {
        console.warn(`[${context}]`, ...args);
      }
    },
    error: (...args) => {
      if (shouldLog('error')) {
        console.error(`[${context}]`, ...args);
      }
    }
  };
}

// Expose API for external use
export default {
  initialize: initializeModernIntegration,
  applyLayoutPreset,
  setFeatureFlag: (flag, value) => {
    if (flag in FEATURE_FLAGS) {
      FEATURE_FLAGS[flag] = value;
      
      // Re-initialize components if needed
      if (value === true) {
        initializeComponents();
      }
    }
  },
  getFeatureFlags: () => ({ ...FEATURE_FLAGS })
};

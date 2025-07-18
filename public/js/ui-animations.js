/**
 * OPERATOR - Advanced UI Animations & Interactions
 * Uses modern animation techniques for fluid, responsive UI elements
 */

// Initialize core animation system
document.addEventListener('DOMContentLoaded', () => {
  console.log('UI Animation System Loaded');
  initializeAnimations();
  setupHistoryOverlay();
  setupActiveTasksAnimations();
  setupThreeJSBackground();
});

// Core Animation System
function initializeAnimations() {
  // Add smooth entrance animations to all major UI components
  document.querySelectorAll('.card, .command-center, .message-timeline, .task-results').forEach(el => {
    el.classList.add('animate-in');
  });

  // Setup hover effects on interactive elements
  document.querySelectorAll('.btn, .tab-btn, nav a').forEach(el => {
    el.addEventListener('mouseenter', () => {
      el.classList.add('hover-effect');
    });
    el.addEventListener('mouseleave', () => {
      el.classList.remove('hover-effect');
    });
  });

  // Setup pulse animations for notifications and alerts
  document.querySelectorAll('.notification, .alert').forEach(el => {
    el.classList.add('pulse-animation');
  });
}

// History Overlay System
function setupHistoryOverlay() {
  const historyLink = document.getElementById('history-link');
  const historyOverlay = document.getElementById('history-overlay');
  const historyClose = document.getElementById('history-overlay-close');
  
  if (!historyLink || !historyOverlay) return;
  
  // Open history overlay with animation
  historyLink.addEventListener('click', (e) => {
    e.preventDefault();
    document.body.classList.add('overlay-active');
    historyOverlay.classList.add('active');
    
    // Animate history cards entrance
    const cards = historyOverlay.querySelectorAll('.history-card');
    cards.forEach((card, index) => {
      setTimeout(() => {
        card.classList.add('animate-in');
      }, 100 + (index * 50));
    });
    
    loadHistoryCards();
  });
  
  // Close history overlay
  historyClose.addEventListener('click', () => {
    document.body.classList.remove('overlay-active');
    historyOverlay.classList.remove('active');
    
    const cards = historyOverlay.querySelectorAll('.history-card');
    cards.forEach(card => {
      card.classList.remove('animate-in');
    });
  });
}

// Load history cards with API data
async function loadHistoryCards() {
  const historyContainer = document.getElementById('history-cards-container');
  if (!historyContainer) return;
  
  try {
    const response = await fetch('/history', {
      credentials: 'include',
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });
    
    if (!response.ok) {
      throw new Error('Failed to load history');
    }
    
    const data = await response.json();
    
    if (!data.items || data.items.length === 0) {
      historyContainer.innerHTML = '<div class="empty-state"><i class="fas fa-history"></i><p>No history yet</p></div>';
      return;
    }
    
    historyContainer.innerHTML = '';
    
    data.items.forEach(item => {
      const historyCard = document.createElement('div');
      historyCard.className = 'history-card';
      historyCard.dataset.taskId = item._id;
      
      const timestamp = new Date(item.timestamp);
      const formattedTime = `${timestamp.toLocaleTimeString()} ${timestamp.toLocaleDateString()}`;
      
      historyCard.innerHTML = `
        <div class="history-card-inner">
          <div class="history-card-front">
            <h4><i class="fas fa-history"></i> ${item.command.length > 30 ? item.command.substring(0, 30) + '...' : item.command}</h4>
            <p>URL: ${item.url || 'N/A'}</p>
            <span class="timestamp">${formattedTime}</span>
          </div>
          <div class="history-card-back">
            <div class="action-buttons">
              <button class="btn btn-icon rerun-btn" data-id="${item._id}"><i class="fas fa-redo"></i></button>
              <button class="btn btn-icon view-btn" data-id="${item._id}"><i class="fas fa-eye"></i></button>
              <button class="btn btn-icon delete-btn" data-id="${item._id}"><i class="fas fa-trash"></i></button>
            </div>
          </div>
        </div>
      `;
      
      // Add flip animation on hover
      historyCard.addEventListener('mouseenter', () => {
        historyCard.classList.add('flip');
      });
      
      historyCard.addEventListener('mouseleave', () => {
        historyCard.classList.remove('flip');
      });
      
      // Setup action buttons
      historyCard.querySelector('.rerun-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        rerunHistoryTask(item._id, item.url, item.command);
      });
      
      historyCard.querySelector('.view-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        viewHistoryDetails(item._id);
      });
      
      historyCard.querySelector('.delete-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        deleteHistoryTask(item._id);
      });
      
      historyContainer.appendChild(historyCard);
    });
    
  } catch (error) {
    console.error('Error loading history:', error);
    historyContainer.innerHTML = '<div class="error-state"><i class="fas fa-exclamation-triangle"></i><p>Failed to load history</p></div>';
  }
}

// View history details in a modal
function viewHistoryDetails(taskId) {
  const historyDetailsModal = document.getElementById('history-details-modal');
  if (!historyDetailsModal) return;
  
  fetch(`/history/${taskId}`, {
    credentials: 'include',
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
  })
  .then(response => {
    if (!response.ok) throw new Error('Failed to load task details');
    return response.json();
  })
  .then(data => {
    const modalContent = historyDetailsModal.querySelector('.modal-content');
    
    let resultContent = '';
    if (data.result && typeof data.result === 'object') {
      resultContent = `<pre>${JSON.stringify(data.result, null, 2)}</pre>`;
    } else if (data.result) {
      resultContent = `<p>${data.result}</p>`;
    } else {
      resultContent = '<p class="text-muted">No result data available</p>';
    }
    
    modalContent.innerHTML = `
      <h3>Task Details</h3>
      <div class="detail-group">
        <label>Command:</label>
        <p>${data.command}</p>
      </div>
      <div class="detail-group">
        <label>URL:</label>
        <p>${data.url || 'N/A'}</p>
      </div>
      <div class="detail-group">
        <label>Status:</label>
        <span class="status-badge ${data.status}">${data.status}</span>
      </div>
      <div class="detail-group">
        <label>Time:</label>
        <p>${new Date(data.timestamp).toLocaleString()}</p>
      </div>
      <div class="detail-group">
        <label>Result:</label>
        <div class="result-content">${resultContent}</div>
      </div>
    `;
    
    // Show modal with animation
    historyDetailsModal.classList.add('show');
    
    // Setup close button
    historyDetailsModal.querySelector('.close-modal').addEventListener('click', () => {
      historyDetailsModal.classList.remove('show');
    });
  })
  .catch(error => {
    console.error('Error loading task details:', error);
    showNotification('Failed to load task details', 'error');
  });
}

// Active Tasks Animations
function setupActiveTasksAnimations() {
  // Observe active tasks for progress bar animations
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        const activeTasks = document.querySelectorAll('.active-task');
        activeTasks.forEach(task => {
          const progressBar = task.querySelector('.task-progress');
          if (progressBar) {
            // Smooth transition for progress bar updates
            progressBar.style.transition = 'width 0.5s ease-out';
            
            // Add pulse animation for processing tasks
            if (task.querySelector('.task-status.processing')) {
              task.classList.add('pulse-subtle');
            } else {
              task.classList.remove('pulse-subtle');
            }
          }
        });
      }
    });
  });
  
  const config = { childList: true, subtree: true };
  observer.observe(document.getElementById('active-tasks-container') || document.body, config);
}

// ThreeJS Background
function setupThreeJSBackground() {
  const { THREE, GLTFLoader } = window;
  
  if (!THREE) {
    console.error('Three.js not loaded');
    return;
  }
  
  const canvas = document.getElementById('three-canvas');
  if (!canvas) return;

  // Scene setup
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  
  // Lighting
  const light = new THREE.AmbientLight(0xffffff, 0.5);
  scene.add(light);
  
  // Load room model
  try {
    const dracoLoader = new THREE.DRACOLoader();
    dracoLoader.setDecoderPath('/draco/');
    
    const loader = new GLTFLoader();
    loader.setDRACOLoader(dracoLoader);
    
    const modelPath = '/models/roomModel.glb';
    
    loader.load(
      modelPath,
      (gltf) => {
        if (!gltf?.scene) {
          console.warn(`Model loaded but invalid at ${modelPath}`);
          return;
        }
        scene.add(gltf.scene);
      },
      undefined,
      (error) => console.error(`Failed to load model at ${modelPath}:`, error)
    );
  } catch (error) {
    console.error('3D initialization failed:', error);
  }
};

// Collapsible sections
document.addEventListener('DOMContentLoaded', () => {
  const collapsibleSections = document.querySelectorAll('.collapsible-section');
  
  collapsibleSections.forEach(section => {
    const header = section.querySelector('.section-header');
    const content = section.querySelector('.section-content');
    
    header.addEventListener('click', () => {
      section.classList.toggle('collapsed');
      
      if (section.classList.contains('collapsed')) {
        content.style.maxHeight = '0';
      } else {
        content.style.maxHeight = content.scrollHeight + 'px';
      }
    });
  });
});

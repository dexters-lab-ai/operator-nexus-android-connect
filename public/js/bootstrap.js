import { eventBus } from '/src/utils/events.js';

(async () => {
  // Get splash elements
  const loadingProgress = document.getElementById('loading-progress');
  const loadingText = document.querySelector('.loading-text');

  // Enhanced loading progress handler
  eventBus.on('room-loading-progress', ({ progress, step }) => {
    console.debug(`[LOADING] Progress: ${progress}% - ${step}`);
    
    const numericProgress = Math.max(0, Math.min(100, Number(progress) || 0));
    const cleanStep = step ? step.toString().replace(/^.*[\\\/]/, '').replace(/\.\w+$/, '').replace(/_/g, ' ') : 'Loading';
      
    if (loadingProgress) {
      loadingProgress.style.width = `${numericProgress}%`;
      loadingProgress.setAttribute('aria-valuenow', numericProgress);
    }
    
    if (loadingText) {
      loadingText.textContent = `[${numericProgress}%] ${cleanStep}`;
    }
  });

  // Final completion handler with transition
  eventBus.on('room-loading-complete', () => {
    console.debug('[LOADING] All assets loaded');
    // ensure splash bar at 100%
    if (loadingProgress) {
      loadingProgress.style.width = '100%';
      loadingProgress.setAttribute('aria-valuenow', 100);
    }
    if (loadingText) loadingText.textContent = '[100%] Complete';
    setTimeout(() => {
      const splash = document.getElementById('splash-screen');
      if (splash) {
        splash.style.transition = 'opacity 0.5s ease';
        splash.style.opacity = '0';
        setTimeout(() => {
          splash.remove();
          console.debug('[LOADING] Splash screen removed');
        }, 500);
      }
    }, 2000);
  });

  // Preload UI integration module to register PWA event handlers and mountApp helper
  await import('/js/app-modern-integration.js');
  // Mount the PWA shell into the main app container; UI remains hidden until launch event triggers
  try {
    await window.mountApp('#app-container');
    console.log('[bootstrap] Modern UI shell successfully mounted to #app-container');
  } catch (err) {
    console.error('[bootstrap] Error mounting modern UI shell:', err);
  }
  // Create and mount 3D Room Experience
  const { RoomEntryPoint } = await import('/src/3d/RoomEntryPoint.js');
  const webglContainer = document.getElementById('webgl-container');
  webglContainer.innerHTML = '';
  const entryPoint = RoomEntryPoint({ container: webglContainer });
  webglContainer.appendChild(entryPoint);

  // Initialize room experience
  await entryPoint.initialize();
  
  // UI launch is handled by RoomEntryPoint.setupEventListeners -> launch-application -> initialize-application
})();

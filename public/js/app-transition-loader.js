/**
 * Application Transition Loader
 * 
 * Displays a cute animated neon doodle during the transition from 3D world 
 * to PWA application load.
 */

(function() {
  let appLoader = null;
  let transitionStarted = false;
  let animationFrame = null;
  
  // Create and inject the loader styles
  function injectStyles() {
    const styleEl = document.createElement('style');
    styleEl.id = 'app-transition-loader-styles';
    styleEl.textContent = `
      .app-transition-loader {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        background-color: #121212 !important;
        display: flex !important;
        flex-direction: column !important;
        justify-content: center !important;
        align-items: center !important;
        z-index: 99999 !important;
        opacity: 0 !important;
        transition: opacity 0.3s ease !important;
      }
      
      .app-transition-loader.visible {
        opacity: 1 !important;
      }
      
      .app-transition-loader-content {
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
      }
      
      .app-transition-loader-canvas-container {
        width: 200px !important;
        height: 200px !important;
        margin-bottom: 20px !important;
        position: relative !important;
      }
      
      .app-transition-loader-canvas {
        width: 100% !important;
        height: 100% !important;
      }
      
      .app-transition-loader-text {
        margin-top: 15px !important;
        font-family: "SF Mono", SFMono-Regular, ui-monospace, Menlo, Consolas, monospace !important;
        font-size: 12px !important;
        color: rgba(255, 255, 255, 0.7) !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        text-shadow: 0 0 10px rgba(120, 70, 255, 0.8) !important;
      }
      
      .app-transition-loader-glow {
        position: absolute !important;
        width: 100% !important;
        height: 100% !important;
        top: 0 !important;
        left: 0 !important;
        filter: blur(20px) !important;
        opacity: 0.5 !important;
        z-index: -1 !important;
      }
    `;
    
    document.head.appendChild(styleEl);
  }
  
  // Create the loader HTML structure
  function createLoader() {
    appLoader = document.createElement('div');
    appLoader.className = 'app-transition-loader';
    
    const content = document.createElement('div');
    content.className = 'app-transition-loader-content';
    
    const canvasContainer = document.createElement('div');
    canvasContainer.className = 'app-transition-loader-canvas-container';
    
    const canvas = document.createElement('canvas');
    canvas.className = 'app-transition-loader-canvas';
    canvas.width = 400; // High resolution for crisp lines
    canvas.height = 400;
    
    const glowCanvas = document.createElement('canvas');
    glowCanvas.className = 'app-transition-loader-glow';
    glowCanvas.width = 400;
    glowCanvas.height = 400;
    
    const text = document.createElement('div');
    text.className = 'app-transition-loader-text';
    text.textContent = 'Starting OPERATOR';
    text.style.opacity = '0';
    text.style.transition = 'opacity 1s ease-in-out';
    
    canvasContainer.appendChild(canvas);
    canvasContainer.appendChild(glowCanvas);
    content.appendChild(canvasContainer);
    content.appendChild(text);
    appLoader.appendChild(content);
    
    document.body.appendChild(appLoader);
    
    // Trigger reflow before adding visible class for smooth fade-in
    void appLoader.offsetWidth;
    appLoader.classList.add('visible');
    
    // Start the animation
    startDoodleAnimation(canvas, glowCanvas, text);
  }
  
  // Create the animated neon doodle
  function startDoodleAnimation(canvas, glowCanvas, textElement) {
    const ctx = canvas.getContext('2d');
    const glowCtx = glowCanvas.getContext('2d');
    
    // Animation parameters
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    
    // Neon colors
    const colors = [
      '#ff00ff', // Magenta
      '#00ffff', // Cyan
      '#ffff00', // Yellow
      '#ff9500', // Orange
      '#7846ff', // Purple
      '#00ff7f'  // Green
    ];
    
    // Doodle parameters
    let points = [];
    let time = 0;
    let frame = 0;
    let doodlePhase = 0; // 0: initial drawing, 1: morph to shape, 2: pulse
    let doodleComplete = false;
    
    // Initialize doodle points
    function initDoodle() {
      // Create a happy face doodle
      points = [];
      
      // Face outline
      for (let i = 0; i < 20; i++) {
        const angle = (i / 20) * Math.PI * 2;
        const radius = 80 + Math.sin(i * 5) * 5;
        points.push({
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          vx: 0,
          vy: 0,
          color: colors[i % colors.length],
          size: 3 + Math.random() * 2,
          speed: 0.5 + Math.random() * 0.5
        });
      }
      
      // Eyes
      const eyeSize = 15;
      const eyeDistance = 40;
      
      // Left eye
      for (let i = 0; i < 8; i++) {
        const angle = (i / 8) * Math.PI * 2;
        points.push({
          x: centerX - eyeDistance + Math.cos(angle) * eyeSize,
          y: centerY - 15 + Math.sin(angle) * eyeSize,
          vx: 0,
          vy: 0,
          color: colors[2],
          size: 3,
          speed: 0.4
        });
      }
      
      // Right eye
      for (let i = 0; i < 8; i++) {
        const angle = (i / 8) * Math.PI * 2;
        points.push({
          x: centerX + eyeDistance + Math.cos(angle) * eyeSize,
          y: centerY - 15 + Math.sin(angle) * eyeSize,
          vx: 0,
          vy: 0,
          color: colors[3],
          size: 3,
          speed: 0.4
        });
      }
      
      // Smile
      for (let i = 0; i < 12; i++) {
        const t = i / 11;
        const angle = Math.PI * (0.2 + t * 0.6);
        const radius = 50;
        points.push({
          x: centerX + Math.cos(angle) * radius,
          y: centerY + 10 + Math.sin(angle) * radius,
          vx: 0,
          vy: 0,
          color: colors[0],
          size: 4,
          speed: 0.6
        });
      }
    }
    
    // Animation loop
    function animate() {
      // Clear canvas
      ctx.clearRect(0, 0, width, height);
      glowCtx.clearRect(0, 0, width, height);
      
      // Update time
      time += 0.01;
      frame++;
      
      // Create cycling color effect
      const colorShift = time * 0.5;
      const shiftedColors = colors.map((color, i) => {
        // Skip color shifting in first phase to make it less distracting
        if (doodlePhase === 0) return color;
        
        // Convert hex to RGB
        const r = parseInt(color.substring(1, 3), 16);
        const g = parseInt(color.substring(3, 5), 16);
        const b = parseInt(color.substring(5, 7), 16);
        
        // Add sine wave color cycling
        const cycle = (i / colors.length) + colorShift;
        const factor = 0.2 + (doodlePhase === 2 ? 0.3 : 0.1); // More intense in pulse phase
        
        // Calculate new RGB values with cycling
        const nr = Math.min(255, Math.max(0, r * (1 + Math.sin(cycle) * factor)));
        const ng = Math.min(255, Math.max(0, g * (1 + Math.sin(cycle + 2) * factor)));
        const nb = Math.min(255, Math.max(0, b * (1 + Math.sin(cycle + 4) * factor)));
        
        return `rgb(${Math.floor(nr)}, ${Math.floor(ng)}, ${Math.floor(nb)})`;
      });
      
      // Update doodle phase
      if (frame === 50) { // Show text after a short delay
        textElement.style.opacity = '1';
      }
      
      if (frame > 150 && doodlePhase === 0) {
        doodlePhase = 1; // Start morphing
      }
      
      if (frame > 300 && doodlePhase === 1) {
        doodlePhase = 2; // Start pulsing
      }
      
      // Add cyberpunk text glow effect
      if (frame % 100 === 0 && doodlePhase === 2) {
        const randomColor = colors[Math.floor(Math.random() * colors.length)];
        textElement.style.textShadow = `0 0 10px ${randomColor} !important`;
      }
      
      // Draw connections between points for the neon effect
      for (let i = 0; i < points.length; i++) {
        const point = points[i];
        const colorIndex = i % colors.length;
        const currentColor = shiftedColors ? shiftedColors[colorIndex] : point.color;
        
        // Update point position with some wobble
        if (doodlePhase >= 1) {
          point.x += Math.sin(time * point.speed + i) * 0.5;
          point.y += Math.cos(time * point.speed + i) * 0.5;
        }
        
        // Draw the line to next point
        const nextIdx = (i + 1) % points.length;
        const nextPoint = points[nextIdx];
        
        // Only connect points within same shape group
        if ((i < 20 && nextIdx < 20) || 
            (i >= 20 && i < 28 && nextIdx >= 20 && nextIdx < 28) ||
            (i >= 28 && i < 36 && nextIdx >= 28 && nextIdx < 36) ||
            (i >= 36 && nextIdx >= 36)) {
          
          // Draw main line on canvas with pulsing effect in phase 2
          ctx.beginPath();
          ctx.moveTo(point.x, point.y);
          ctx.lineTo(nextPoint.x, nextPoint.y);
          ctx.strokeStyle = currentColor;
          
          // Add thickness pulsing in phase 2
          let pulseEffect = 1;
          if (doodlePhase === 2) {
            pulseEffect = 1 + Math.sin(time * 3 + i * 0.1) * 0.2;
          }
          ctx.lineWidth = point.size * pulseEffect;
          ctx.stroke();
          
          // Draw glow effect with more intense color
          glowCtx.beginPath();
          glowCtx.moveTo(point.x, point.y);
          glowCtx.lineTo(nextPoint.x, nextPoint.y);
          glowCtx.strokeStyle = currentColor;
          glowCtx.lineWidth = point.size * 4 * (doodlePhase === 2 ? pulseEffect : 1);
          glowCtx.stroke();
        }
        
        // Draw point
        ctx.beginPath();
        ctx.arc(point.x, point.y, point.size / 2, 0, Math.PI * 2);
        ctx.fillStyle = currentColor;
        ctx.fill();
        
        // Draw glow point
        glowCtx.beginPath();
        glowCtx.arc(point.x, point.y, point.size * 3, 0, Math.PI * 2);
        glowCtx.fillStyle = currentColor;
        glowCtx.fill();
      }
      
      // Continue animation
      animationFrame = requestAnimationFrame(animate);
    }
    
    // Start animation
    initDoodle();
    animate();
  }
  
  // Public API
  window.AppTransitionLoader = {
    // Start the loader
    start: function() {
      if (transitionStarted) return;
      transitionStarted = true;
      
      injectStyles();
      createLoader();
      console.log('[AppTransitionLoader] Started transition animation');
    },
    
    // Stop the loader
    stop: function() {
      if (!appLoader) return;
      
      // Cancel animation frame
      if (animationFrame) {
        cancelAnimationFrame(animationFrame);
        animationFrame = null;
      }
      
      appLoader.classList.remove('visible');
      setTimeout(() => {
        if (appLoader && appLoader.parentNode) {
          appLoader.parentNode.removeChild(appLoader);
          appLoader = null;
        }
        
        // Clean up styles
        const styles = document.getElementById('app-transition-loader-styles');
        if (styles && styles.parentNode) {
          styles.parentNode.removeChild(styles);
        }
        
        transitionStarted = false;
        console.log('[AppTransitionLoader] Stopped transition animation');
      }, 300);
    }
  };
  
  // Look for the Launch Operator button to hook our loader
  document.addEventListener('DOMContentLoaded', function() {
    // Find the Launch Operator button by either id, class or text content
    const launchButtons = document.querySelectorAll('button, .btn, [role="button"]');
    launchButtons.forEach(btn => {
      if (btn.textContent && btn.textContent.toLowerCase().includes('launch operator')) {
        console.log('[AppTransitionLoader] Found Launch OPERATOR button, attaching click handler');
        btn.addEventListener('click', () => {
          window.AppTransitionLoader.start();
        });
      }
    });
  });
  
  // Automatically detect loadAssets call
  const originalLoadAssets = window.loadAssets;
  if (typeof originalLoadAssets === 'function') {
    window.loadAssets = function() {
      window.AppTransitionLoader.stop();
      return originalLoadAssets.apply(this, arguments);
    };
  }
})();

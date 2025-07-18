// sentinel-animation.js - Modern Three.js Sentinel Robot Animation
// Based on the cinematic sci-fi robot with horizontal laser eyes

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.132.2/build/three.module.js';
import { RGBELoader } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/loaders/RGBELoader.js';
import { EffectComposer } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/postprocessing/UnrealBloomPass.js';
import { ShaderPass } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/postprocessing/ShaderPass.js';
import { GammaCorrectionShader } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/shaders/GammaCorrectionShader.js';
import { GLTFLoader } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/loaders/GLTFLoader.js';
import { DRACOLoader } from 'https://cdn.jsdelivr.net/npm/three@0.132.2/examples/jsm/loaders/DRACOLoader.js';

// Global variables
let canvas, renderer, scene, camera;
let sentinel, sentinelEye, laserBeam;
let composer, bloomPass;
let clock;
let mixer, flyingAction;
let state = 'idle'; // 'idle', 'alert', 'firing', 'disperse'
let animationFrameId = null;
let earthMesh, atmosphereMesh, stars;

// Initialize the animation system
function init(containerId) {
  // Setup container
  const container = document.getElementById(containerId);
  if (!container) {
    console.error("Container element not found");
    return false;
  }
  
  // Create clock
  clock = new THREE.Clock();
  
  // Setup renderer
  canvas = document.createElement('canvas');
  container.appendChild(canvas);
  
  renderer = new THREE.WebGLRenderer({
    canvas: canvas,
    antialias: true,
    powerPreference: 'high-performance'
  });
  
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(container.clientWidth, container.clientHeight);
  renderer.outputEncoding = THREE.sRGBEncoding;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.0;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  
  // Setup scene
  scene = new THREE.Scene();
  
  // Setup camera
  camera = new THREE.PerspectiveCamera(
    40,
    container.clientWidth / container.clientHeight,
    0.1,
    1000
  );
  camera.position.set(0, 0, 10);
  
  // Load environment map
  loadEnvironmentMap();
  
  // Create celestial background
  createCelestialBackground();
  
  // Add lights
  setupLighting();
  
  // Load sentinel robot model
  loadModel('https://raw.githubusercontent.com/mrdoob/three.js/master/examples/models/gltf/DamagedHelmet/DamagedHelmet.gltf')
    .then((gltfScene) => {
      sentinel = gltfScene;
      scene.add(sentinel);
      
      // Create eye visor (horizontal laser eye like in the screenshot)
      const eyeGeometry = new THREE.BoxGeometry(1.6, 0.15, 0.1);
      sentinelEye = new THREE.Mesh(eyeGeometry, new THREE.MeshBasicMaterial({
        color: 0xff2200,
        transparent: true,
        opacity: 0.9
      }));
      sentinelEye.position.set(0, 2, 0.7);
      sentinel.add(sentinelEye);
      
      // Create laser beam (initially invisible)
      const laserGeometry = new THREE.CylinderGeometry(0.05, 0.05, 100, 8);
      const laserMaterial = new THREE.MeshBasicMaterial({
        color: 0xff3300,
        transparent: true,
        opacity: 0,
        emissive: 0xff0000,
        emissiveIntensity: 10
      });
      
      laserBeam = new THREE.Mesh(laserGeometry, laserMaterial);
      laserBeam.position.z = 50;
      laserBeam.rotation.x = Math.PI / 2;
      sentinelEye.add(laserBeam);
      
      // Add subtle glow around the eye
      const glowGeometry = new THREE.PlaneGeometry(2, 0.5);
      const glowMaterial = new THREE.MeshBasicMaterial({
        color: 0xff3300,
        transparent: true,
        opacity: 0.5,
        blending: THREE.AdditiveBlending
      });
      
      const eyeGlow = new THREE.Mesh(glowGeometry, glowMaterial);
      eyeGlow.position.z = 0.71;
      sentinelEye.add(eyeGlow);
      
      // Position the sentinel
      sentinel.position.set(0, 0, 0);
      
      // Setup post-processing
      setupPostProcessing();
      
      // Add event listeners
      window.addEventListener('resize', onWindowResize);
      
      // Start animation loop
      animate();
    })
    .catch((error) => {
      console.error('Error loading sentinel model:', error);
    });
  
  return true;
}

// Load HDR environment map
function loadEnvironmentMap() {
  const rgbeLoader = new RGBELoader();
  rgbeLoader.setDataType(THREE.HalfFloatType);
  
  rgbeLoader.load('https://raw.githubusercontent.com/mrdoob/three.js/dev/examples/textures/equirectangular/venice_sunset_1k.hdr', function(texture) {
    const envMap = new THREE.PMREMGenerator(renderer).fromEquirectangular(texture).texture;
    scene.environment = envMap;
    texture.dispose();
  });
}

// Create celestial background with Earth/planet and stars
function createCelestialBackground() {
  // Create Earth-like planet
  const earthGeometry = new THREE.SphereGeometry(25, 64, 64);
  const earthMaterial = new THREE.MeshPhysicalMaterial({
    color: 0x0077aa,
    roughness: 0.7,
    metalness: 0.2,
    emissive: 0x002244,
    emissiveIntensity: 0.2
  });
  
  earthMesh = new THREE.Mesh(earthGeometry, earthMaterial);
  earthMesh.position.set(0, -20, -40);
  scene.add(earthMesh);
  
  // Create atmosphere glow
  const atmosphereGeometry = new THREE.SphereGeometry(27, 64, 64);
  const atmosphereMaterial = new THREE.MeshBasicMaterial({
    color: 0x6caed8,
    transparent: true,
    opacity: 0.3,
    side: THREE.BackSide
  });
  
  atmosphereMesh = new THREE.Mesh(atmosphereGeometry, atmosphereMaterial);
  atmosphereMesh.position.copy(earthMesh.position);
  scene.add(atmosphereMesh);
  
  // Create stars
  const starGeometry = new THREE.BufferGeometry();
  const starCount = 1000;
  const starPositions = new Float32Array(starCount * 3);
  const starSizes = new Float32Array(starCount);
  
  for (let i = 0; i < starCount; i++) {
    const i3 = i * 3;
    // Create stars in a large sphere around the scene
    const radius = 50 + Math.random() * 100;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    
    starPositions[i3] = radius * Math.sin(phi) * Math.cos(theta);
    starPositions[i3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
    starPositions[i3 + 2] = radius * Math.cos(phi);
    
    starSizes[i] = 0.1 + Math.random() * 0.3;
  }
  
  starGeometry.setAttribute('position', new THREE.BufferAttribute(starPositions, 3));
  starGeometry.setAttribute('size', new THREE.BufferAttribute(starSizes, 1));
  
  const starMaterial = new THREE.PointsMaterial({
    color: 0xffffff,
    size: 0.2,
    transparent: true,
    opacity: 0.8,
    sizeAttenuation: true
  });
  
  stars = new THREE.Points(starGeometry, starMaterial);
  scene.add(stars);
}

// Setup lighting
function setupLighting() {
  // Ambient light
  const ambientLight = new THREE.AmbientLight(0x111122, 0.5);
  scene.add(ambientLight);
  
  // Main directional light (sunlight effect)
  const mainLight = new THREE.DirectionalLight(0xffffee, 2);
  mainLight.position.set(30, 10, 20);
  mainLight.castShadow = true;
  mainLight.shadow.mapSize.width = 2048;
  mainLight.shadow.mapSize.height = 2048;
  mainLight.shadow.camera.near = 0.1;
  mainLight.shadow.camera.far = 100;
  mainLight.shadow.bias = -0.0005;
  scene.add(mainLight);
  
  // Rim light to highlight edges (from behind)
  const rimLight = new THREE.DirectionalLight(0x6ca0ff, 1.5);
  rimLight.position.set(-5, 2, -10);
  scene.add(rimLight);
  
  // Add point light for the sentinel's eye
  const eyeLight = new THREE.PointLight(0xff0000, 2, 10);
  eyeLight.position.set(0, 0, 2);
  scene.add(eyeLight);
}

// Load model with animations
function loadModel(modelPath) {
  return new Promise((resolve, reject) => {
    const loader = new GLTFLoader();
    
    // Set up DRACO decoder if needed
    if (typeof DRACOLoader !== 'undefined') {
      const dracoLoader = new DRACOLoader();
      dracoLoader.setDecoderPath('https://www.gstatic.com/draco/v1/decoders/');
      loader.setDRACOLoader(dracoLoader);
    }
    
    loader.load(
      modelPath,
      (gltf) => {
        console.log('[ANIM] Model loaded with', gltf.animations?.length, 'animations');
        
        // Process animations
        if (gltf.animations && gltf.animations.length) {
          mixer = new THREE.AnimationMixer(gltf.scene);
          
          // Play all animations by default
          gltf.animations.forEach((clip) => {
            const action = mixer.clipAction(clip);
            action.play();
          });
          
          console.log('[ANIM] All animations started');
        }
        
        resolve(gltf.scene);
      },
      undefined,
      (error) => {
        console.error('[ANIM] Error loading model:', error);
        reject(error);
      }
    );
  });
}

// Setup post-processing effects
function setupPostProcessing() {
  composer = new EffectComposer(renderer);
  
  const renderPass = new RenderPass(scene, camera);
  composer.addPass(renderPass);
  
  // Add bloom effect
  bloomPass = new UnrealBloomPass(
    new THREE.Vector2(window.innerWidth, window.innerHeight),
    0.8,   // strength
    0.3,   // radius
    0.7    // threshold
  );
  composer.addPass(bloomPass);
  
  // Add gamma correction
  const gammaCorrectionPass = new ShaderPass(GammaCorrectionShader);
  composer.addPass(gammaCorrectionPass);
}

// Animation loop
function animate() {
  animationFrameId = requestAnimationFrame(animate);
  
  const delta = clock.getDelta();
  const elapsedTime = clock.getElapsedTime();
  
  // Update mixer for animations
  if (mixer) mixer.update(delta);
  
  // Update sentinel
  updateSentinel(delta, elapsedTime);
  
  // Update background elements
  updateBackground(delta, elapsedTime);
  
  // Render scene
  composer.render();
}

// Update sentinel animations
function updateSentinel(delta, elapsedTime) {
  if (!sentinel || !sentinelEye) return;
  
  // Handle different states
  switch (state) {
    case 'idle':
      sentinelEye.material.emissiveIntensity = 1.0 + Math.sin(elapsedTime * 2) * 0.2;
      sentinelEye.material.opacity = 0.7 + Math.sin(elapsedTime * 2) * 0.1;
      if (laserBeam) laserBeam.material.opacity = 0;
      bloomPass.strength = 0.8;
      break;
      
    case 'alert':
      sentinelEye.material.emissiveIntensity = 1.5 + Math.sin(elapsedTime * 8) * 0.5;
      sentinelEye.material.opacity = 0.9 + Math.sin(elapsedTime * 8) * 0.1;
      if (laserBeam) laserBeam.material.opacity = Math.max(0, Math.sin(elapsedTime * 6) - 0.7) * 0.3;
      bloomPass.strength = 1.0 + Math.sin(elapsedTime * 4) * 0.2;
      break;
      
    case 'firing':
      sentinelEye.material.emissiveIntensity = 3.0;
      sentinelEye.material.opacity = 1.0;
      if (laserBeam) {
        laserBeam.material.opacity = 0.8 + Math.sin(elapsedTime * 20) * 0.2;
        // Add subtle shake when firing
        sentinel.position.x = Math.sin(elapsedTime * 60) * 0.02;
        sentinel.position.z = Math.cos(elapsedTime * 50) * 0.02;
      }
      bloomPass.strength = 1.5;
      break;
  }
}

// Update background elements
function updateBackground(delta, elapsedTime) {
  // Rotate earth slowly
  if (earthMesh) {
    earthMesh.rotation.y += delta * 0.05;
  }
  
  // Pulse atmosphere
  if (atmosphereMesh) {
    atmosphereMesh.material.opacity = 0.2 + Math.sin(elapsedTime * 0.5) * 0.1;
    atmosphereMesh.scale.set(
      1.0 + Math.sin(elapsedTime * 0.2) * 0.01,
      1.0 + Math.sin(elapsedTime * 0.2) * 0.01,
      1.0 + Math.sin(elapsedTime * 0.2) * 0.01
    );
  }
  
  // Twinkle stars
  if (stars && stars.geometry.attributes.size) {
    const sizes = stars.geometry.attributes.size.array;
    for (let i = 0; i < sizes.length; i++) {
      const originalSize = 0.1 + (i % 3) * 0.1;
      sizes[i] = originalSize + Math.sin(elapsedTime * 3 + i) * 0.05;
    }
    stars.geometry.attributes.size.needsUpdate = true;
  }
}

// Handle window resize
function onWindowResize() {
  const container = canvas.parentElement;
  if (!container) return;
  
  camera.aspect = container.clientWidth / container.clientHeight;
  camera.updateProjectionMatrix();
  
  renderer.setSize(container.clientWidth, container.clientHeight);
  composer.setSize(container.clientWidth, container.clientHeight);
}

// Set sentinel to alert mode
function setAlertMode() {
  state = 'alert';
}

// Set sentinel to idle mode
function setIdleMode() {
  state = 'idle';
}

// Fire laser beam
function fireLaser(duration = 3000) {
  state = 'firing';
  
  setTimeout(() => {
    if (state === 'firing') {
      state = 'alert';
    }
  }, duration);
}

// Disperse and reset the sentinel
function disperseAndReset() {
  // We'd implement particle dispersion here in a full version
  // For now, just reset the state
  state = 'idle';
}

// Clean up resources
function dispose() {
  if (animationFrameId) {
    cancelAnimationFrame(animationFrameId);
  }
  
  window.removeEventListener('resize', onWindowResize);
  
  if (renderer) {
    renderer.dispose();
  }
  
  if (composer) {
    composer.dispose();
  }
  
  // Dispose of geometries and materials
  scene.traverse(object => {
    if (object.geometry) object.geometry.dispose();
    
    if (object.material) {
      if (Array.isArray(object.material)) {
        object.material.forEach(material => material.dispose());
      } else {
        object.material.dispose();
      }
    }
  });
  
  if (canvas && canvas.parentElement) {
    canvas.parentElement.removeChild(canvas);
  }
}

// Export public API
export {
  init,
  setAlertMode,
  setIdleMode,
  fireLaser,
  disperseAndReset,
  dispose
};
import { RoomEntryPoint } from '../src/3d/RoomEntryPoint.js';

export function init3DScene() {
  return new RoomEntryPoint({
    container: document.getElementById('scene-container'),
    modelPath: '/models/roomModel.glb',  // Files in public/ are served from root
    dracoPath: '/draco/'  // Files in public/ are served from root
  });
}

// BackButton.js
/**
 * Back Button Component
 * Destroys the React app and restores the 3D world with smooth transitions.
 */
export default function BackButton({ onBack, containerId = 'back-btn' } = {}) {
  const btn = document.createElement('button');
  btn.id = containerId;
  btn.className = 'btn btn-back fade-in';
  btn.innerHTML = '<i class="fas fa-arrow-left"></i> Back to 3D Room';

  btn.onclick = async () => {
    btn.disabled = true;
    btn.classList.add('fade-out');
    setTimeout(async () => {
      if (typeof onBack === 'function') await onBack();
    }, 350);
  };

  // Fade-in animation
  setTimeout(() => btn.classList.remove('fade-in'), 400);
  return btn;
}

export function initializeBridge() {
  return {
    send: (event, data) => window.postMessage({ type: event, data }, '*'),
    receive: (handler) => window.addEventListener('message', handler)
  };
}

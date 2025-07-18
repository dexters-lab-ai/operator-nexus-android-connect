
        // Simple event bus
        const events = new Map();
        
        export const eventBus = {
          on(event, callback) {
            if (!events.has(event)) {
              events.set(event, new Set());
            }
            events.get(event).add(callback);
            return () => this.off(event, callback);
          },
          
          off(event, callback) {
            if (!events.has(event)) return;
            events.get(event).delete(callback);
          },
          
          emit(event, data) {
            if (!events.has(event)) return;
            events.get(event).forEach(cb => {
              try {
                cb(data);
              } catch (e) {
                console.error('Event handler error:', e);
              }
            });
          }
        };
      
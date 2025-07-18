// ======================================
// 0. LOAD ENVIRONMENT VARIABLES
// ======================================
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// 1. CORE IMPORTS
// ======================================
import fs from 'fs';
import { randomBytes } from 'crypto';
import express from 'express';
import { createServer } from 'http';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';
import { WebSocket, WebSocketServer } from 'ws';
import winston from 'winston';
import pRetry from 'p-retry';
import { v4 as uuidv4 } from 'uuid';
import { Semaphore } from 'async-mutex';
import puppeteer from 'puppeteer';
import puppeteerExtra from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { PuppeteerAgent } from '@midscene/web/puppeteer';
import { getPuppeteerLaunchOptions, getDebugLaunchOptions } from './src/utils/puppeteerConfig.js';
import pcControl from './src/utils/pcControl.js';
import androidControl from './src/utils/androidControl.js';
import androidConfig from './src/config/androidControlConfig.js';
import OpenAI from 'openai';
import { AbortError } from 'p-retry';
import jwt from 'jsonwebtoken';
import cookie from 'cookie';

// Timeout constants
const TIMEOUTS = {
  ELEMENT_WAIT: 30000, // 30 seconds
  PAGE_LOAD: 60000,    // 60 seconds
  NETWORK_IDLE: 10000,  // 10 seconds
  ACTION: 15000        // 15 seconds
};

// Create Express app
const app = express();

// ======================================
// 0.1 HEALTH CHECK ENDPOINT
// ======================================
// Health check endpoint - must be the first route to ensure it's never overridden
// CORS preflight handler for /api/health
app.options('/api/health', (req, res) => {
  const origin = req.headers.origin || '';
  const isAllowedOrigin = origin.endsWith('.ondigitalocean.app') || 
                       origin.endsWith('.dexter-ai.io') || 
                       origin.includes('localhost:') || 
                       origin.includes('127.0.0.1:');
  
  if (isAllowedOrigin) {
    // Always set CORS headers for preflight
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Expose-Headers', 'Content-Type, Authorization, X-Request-ID, Cache-Control, Pragma, X-Requested-With');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    res.header('Vary', 'Origin');
    
    // For preflight requests, respond with 204 No Content
    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }
  }
  
  return res.status(204).end();
});

app.get('/api/health', (req, res) => {
  try {
    const origin = req.headers.origin || '';
    const isAllowedOrigin = origin.endsWith('.ondigitalocean.app') ||
                         origin.endsWith('.dexter-ai.io') || 
                         origin.includes('localhost:') || 
                         origin.includes('127.0.0.1:');
    
    // Set CORS headers
    if (isAllowedOrigin) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Expose-Headers', 'Content-Type, Authorization, X-Request-ID, Cache-Control, Pragma, X-Requested-With');
      res.header('Vary', 'Origin');
    }
    
    // Set response headers
    res.set('Content-Type', 'application/json');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');
    
    // Basic health check data
    const healthData = {
      status: 'ok',
      serverReady: true,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
      nodeVersion: process.version,
      requestId: uuidv4(),
      headers: process.env.NODE_ENV === 'development' ? {
        origin: req.headers.origin,
        host: req.headers.host,
        'user-agent': req.headers['user-agent']
      } : undefined
    };
    
    return res.status(200).json(healthData);
  } catch (error) {
    console.error('Health check error:', error);
    
    // Ensure we can still set headers
    if (!res.headersSent) {
      res.set('Content-Type', 'application/json');
      
      // Set CORS headers even in error case
      const origin = req.headers.origin || '';
      if (origin.endsWith('.ondigitalocean.app') || 
          origin.endsWith('.dexter-ai.io') || 
          origin.includes('localhost:') || 
          origin.includes('127.0.0.1:')) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Vary', 'Origin');
      }
      
      res.status(500).json({
        status: 'error',
        serverReady: false,
        error: error.message,
        timestamp: new Date().toISOString(),
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
      });
    } else {
      // If headers were already sent, log the error but don't try to send another response
      console.error('Headers already sent when trying to send error response');
    }
  }
});

// Track connection attempts and failures
const connectionAttempts = new Map();

// Track active connections and unsent messages
const userConnections = new Map(); // Maps userId -> Set of WebSocket connections
const unsentMessages = new Map(); // Maps userId -> Array of pending messages

/**
 * Update a WebSocket connection's user ID and authentication state
 * @param {WebSocket} ws - WebSocket connection
 * @param {string} newUserId - New user ID
 * @param {boolean} isAuthenticated - Whether the user is authenticated
 */
function updateUserConnection(ws, newUserId, isAuthenticated) {
  const oldUserId = ws.userId;
  
  // If user ID hasn't changed, just update auth status
  if (oldUserId === newUserId) {
    ws.isAuthenticated = isAuthenticated;
    return;
  }

  // Remove from old user's connections
  if (oldUserId && userConnections.has(oldUserId)) {
    const oldUserWsSet = userConnections.get(oldUserId);
    oldUserWsSet.delete(ws);
    if (oldUserWsSet.size === 0) {
      userConnections.delete(oldUserId);
    }
  }

  // Add to new user's connections
  if (!userConnections.has(newUserId)) {
    userConnections.set(newUserId, new Set());
  }
  userConnections.get(newUserId).add(ws);

  // Update connection properties
  ws.userId = newUserId;
  ws.isAuthenticated = isAuthenticated;

  console.log(`[WebSocket] Updated connection ${ws.connectionId} from userId=${oldUserId} to userId=${newUserId}`, {
    isAuthenticated,
    timestamp: new Date().toISOString()
  });
}

// Create WebSocket server and handle HTTP upgrade
let wss;

/**
 * Check if an origin is allowed
 * 
 * This function allows all origins since we're using Cloudflare for security.
 * Security is handled at the Cloudflare level using WAF, rate limiting, and other security features.
 */
function isOriginAllowed(origin) {
  // Allow all origins - security is handled by Cloudflare
  return true;
}

function setupWebSocketServer(server) {
  // Create WebSocket server with configuration
  const wss = new WebSocket.Server({ 
    noServer: true, // Handle upgrade manually
    perMessageDeflate: {
      zlibDeflateOptions: { chunkSize: 1024, memLevel: 7, level: 3 },
      clientNoContextTakeover: true,
      serverNoContextTakeover: true,
      serverMaxWindowBits: 10,
      concurrencyLimit: 10,
      threshold: 1024
    },
    clientTracking: true,
    verifyClient: (info, done) => {
      // This runs before the upgrade request is accepted
      // We'll handle session validation during the upgrade
      done(true);
    }
  });

  // Store the server instance globally for cleanup
  global.wss = wss;

  // WebSocket server event listeners
  wss.on('listening', () => {
    console.log('[WebSocket] Server ready');
    
    // Set up periodic cleanup of dead connections and check connection health
    setInterval(() => {
      const now = Date.now();
      
      // Check all user connections
      for (const [userId, connections] of userConnections.entries()) {
        for (const ws of connections) {
          // Check if connection is still alive
          if (ws.isAlive === false) {
            console.log(`[WebSocket] Terminating dead connection for user ${userId}`);
            ws.terminate();
            connections.delete(ws);
            continue;
          }
          
          // Mark as not alive until next ping
          ws.isAlive = false;
          ws.ping();
        }
        
        // Remove user entry if no more connections
        if (connections.size === 0) {
          userConnections.delete(userId);
          unsentMessages.delete(userId);
        }
      }
    }, 30000); // Check every 30 seconds
  });

  wss.on('error', (error) => {
    console.error('[WebSocket] Server error:', error.message);
    if (process.env.NODE_ENV === 'development') {
      console.error(error.stack);
    }
  });
  
  // WebSocket connection handler - individual connection management is handled in the upgrade handler
  wss.on('connection', (ws) => {
    // Connection logging is handled in the upgrade handler
    // All event handlers are set up in the upgrade handler to avoid duplication
  });

  // WebSocket connection tracking
  const connectionAttempts = new Map();
  const WS_UPGRADE_TIMEOUT = 30000; // 30 seconds
  const WS_MAX_CONNECTIONS_PER_IP = 10;
  const WS_RATE_LIMIT_WINDOW = 60000; // 1 minute

  // Handle HTTP server upgrade for WebSocket connections
  server.on('upgrade', (request, socket, head) => {
    const clientIp = request.socket.remoteAddress || 'unknown';
    const now = Date.now();
    
    // Rate limiting
    const attempts = connectionAttempts.get(clientIp) || [];
    const recentAttempts = attempts.filter(t => now - t < WS_RATE_LIMIT_WINDOW);
    recentAttempts.push(now);
    connectionAttempts.set(clientIp, recentAttempts);
    
    if (recentAttempts.length > WS_MAX_CONNECTIONS_PER_IP) {
      console.warn(`[WebSocket] Rate limiting connection from ${clientIp} (${recentAttempts.length} attempts)`);
      socket.write('HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\n\r\n');
      socket.destroy();
      return;
    }

    // Set a more generous timeout with keep-alive
    socket.setTimeout(WS_UPGRADE_TIMEOUT, () => {
      if (!socket.destroyed) {
        console.warn(`[WebSocket] Upgrade timeout from ${clientIp}`);
        socket.write('HTTP/1.1 408 Request Timeout\r\n\r\n');
        socket.destroy();
      }
    });
    
    // Enable TCP keep-alive
    socket.setKeepAlive(true, 30000); // 30s keep-alive

    // Skip session validation for health checks
    if (request.url === '/health') {
      socket.write('HTTP/1.1 200 OK\r\n\r\n');
      return socket.destroy();
    }
    
    // Add CORS headers for WebSocket upgrade
    const origin = request.headers.origin;
    if (origin && isOriginAllowed(origin)) {
      request.headers['access-control-allow-origin'] = origin;
      request.headers['access-control-allow-credentials'] = 'true';
    }

    // Handle WebSocket upgrade with session validation
    sessionMiddleware(request, {}, async (err) => {
      if (err) {
        console.error('[WebSocket] Session middleware error:', err);
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        return socket.destroy();
      }
      
      try {
        // Ensure session exists
        if (!request.session) {
          request.session = {};
        }
        
        const session = request.session;
        let userId = session.userId || session.user; // Handle both formats
        let isNewSession = !userId;
        
        // Only create guest session for new sessions that aren't API requests
        if (isNewSession && !request.url.startsWith('/api/')) {
          userId = `guest_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          session.userId = userId; // Use consistent property name
          session.user = userId; // Keep both for backward compatibility
          console.log('[WebSocket] Created new guest session:', userId);
          
          // Save the session before proceeding
          await new Promise((resolve, reject) => {
            session.save((err) => {
              if (err) {
                console.error('[WebSocket] Error saving session:', err);
                return reject(err);
              }
              resolve();
            });
          });
        }
        
        if (!userId) {
          console.error('[WebSocket] No user ID in session');
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          return socket.destroy();
        }
        
        // Determine if user is authenticated
        const isAuthenticated = userId && !userId.startsWith('guest_');
        
        // Proceed with WebSocket upgrade
        wss.handleUpgrade(request, socket, head, (ws) => {
          // Clear the timeout as we've successfully upgraded
          socket.setTimeout(0);
          
          // Connection metadata
          const connectionId = `${Date.now()}-${randomBytes(4).toString('hex')}`;
          const clientIp = request.socket.remoteAddress;
          
          // Store connection info using consistent property names
          ws.userId = userId;
          ws.isAuthenticated = isAuthenticated;
          ws.connectedAt = Date.now();
          ws.lastPong = Date.now();
          ws.isAlive = true;
          ws.connectionId = connectionId;
          
          console.log(`[WebSocket] New connection: ${connectionId} (${isAuthenticated ? 'authenticated' : 'guest'})`);
          
          // Add to user connections tracking
          if (!userConnections.has(userId)) {
            userConnections.set(userId, new Set());
          }
          userConnections.get(userId).add(ws);
          
          // Log connection count for this user
          console.log(`[WebSocket] User ${userId} now has ${userConnections.get(userId).size} active connections`);
          
          // Set up ping/pong for connection health
          ws.on('pong', () => {
            const now = Date.now();
            ws.isAlive = true;
            ws.lastPong = now;
            ws.lastActivity = now;
            ws.waitingForPong = false;
            
            // Clear any pending ping timeout
            if (ws.pingTimeout) {
              clearTimeout(ws.pingTimeout);
              ws.pingTimeout = null;
            }
            
            // Set a new ping timeout
            ws.pingTimeout = setTimeout(() => {
              if (ws.readyState !== WebSocket.OPEN) return;
              
              if (ws.waitingForPong) {
                // No pong received in time, terminate connection
                console.log(`[WebSocket] No pong received from ${ws.userId}, terminating connection`);
                ws.terminate();
              } else {
                // Send a ping if connection is still open
                if (ws.readyState === WebSocket.OPEN) {
                  try {
                    ws.waitingForPong = true;
                    ws.ping();
                    
                    // Set a shorter timeout to wait for the pong
                    ws.pingTimeout = setTimeout(() => {
                      if (ws.waitingForPong && ws.readyState === WebSocket.OPEN) {
                        console.log(`[WebSocket] No pong received from ${ws.userId} after ping, terminating connection`);
                        ws.terminate();
                      }
                    }, 5000); // 5 seconds to receive pong
                  } catch (error) {
                    console.error(`[WebSocket] Error sending ping to ${ws.userId}:`, error.message);
                    ws.terminate();
                  }
                }
              }
            }, 30000); // Send ping every 30 seconds
          });
          
          // Set up ping interval for this connection
          const setupPingInterval = (ws) => {
            // Clear any existing interval
            if (ws.pingInterval) {
              clearInterval(ws.pingInterval);
            }
            
            // Set up new interval to send pings
            ws.pingInterval = setInterval(() => {
              if (ws.readyState === WebSocket.OPEN) {
                try {
                  ws.ping();
                } catch (error) {
                  console.error(`[WebSocket] Error sending ping:`, error);
                }
              }
            }, 45000); // Send ping every 45 seconds (less than the 60s timeout)
          };
          
          // Initialize ping interval
          setupPingInterval(ws);
          
          // Send initial ping to start the keepalive
          ws.ping(JSON.stringify({ type: 'ping', timestamp: Date.now() }));

          // Connection is already tracked in userConnections
          console.log(`[WebSocket] New ${isAuthenticated ? 'auth' : 'guest'} connection: ${connectionId}`);
          
          // Send welcome message
          const welcomeMsg = {
            type: 'connection_established',
            connectionId,
            userId,
            isAuthenticated,
            timestamp: Date.now()
          };
          
          ws.send(JSON.stringify(welcomeMsg));
          
          // Send connection ack with user info (required by frontend)
          ws.send(JSON.stringify({
            event: 'connection_ack',
            timestamp: new Date().toISOString(),
            userId: userId,
            connectionCount: userConnections.get(userId).size
          }));
          
          // Send any queued messages for this user
          if (unsentMessages.has(userId)) {
            const queued = unsentMessages.get(userId);
            console.log(`[WebSocket] Sending ${queued.length} queued messages to user ${userId}`);
            queued.forEach(msg => {
              try {
                ws.send(JSON.stringify(msg));
              } catch (error) {
                console.error(`[WebSocket] Error sending queued message to user ${userId}:`, error);
              }
            });
            unsentMessages.delete(userId);
          }
          
          // Handle incoming messages
          const handleMessage = (message) => {
            try {
              const now = Date.now();
              ws.lastActivity = now; // Update last activity timestamp
              
              // Parse message if it's JSON
              let data;
              try {
                data = JSON.parse(message);
              } catch (e) {
                // Not a JSON message, ignore
                return;
              }
              
              // Log message with connection details (filter out pings from logs)
              if (data.type !== 'ping' && data.type !== 'pong') {
                console.log(`[WebSocket] Message from ${connectionId} (${userId}):`, data);
              }
              
              // Handle application-level ping (client-initiated)
              if (data.type === 'ping') {
                // Update connection timestamp
                ws.lastPong = now;
                ws.isAlive = true;
                
                // Clear any pending ping timeout
                if (ws.pingTimeout) {
                  clearTimeout(ws.pingTimeout);
                  ws.pingTimeout = null;
                }
                
                // Clear waitingForPong flag if set
                ws.waitingForPong = false;
                
                // Send pong response
                try {
                  ws.send(JSON.stringify({
                    type: 'pong',
                    timestamp: now,
                    originalTimestamp: data.timestamp || now
                  }));
                } catch (error) {
                  console.error(`[${connectionId}] Error sending pong:`, error);
                }
                return;
              }
              
              // Handle application-level pong (response to our ping)
              if (data.type === 'pong') {
                ws.waitingForPong = false;
                ws.lastPong = now;
                ws.isAlive = true;
                
                // Clear any pending ping timeout
                if (ws.pingTimeout) {
                  clearTimeout(ws.pingTimeout);
                  ws.pingTimeout = null;
                }
                
                // Log RTT if we have the original timestamp
                if (data.originalTimestamp) {
                  const rtt = now - data.originalTimestamp;
                  if (process.env.NODE_ENV !== 'production') {
                    // Received pong, connection healthy
                  }
                }
                return;
              }
              
              // Handle authentication state updates
              if (data.type === 'update_auth_state') {
                const { userId: newUserId, isAuthenticated: newAuthState } = data;
                
                // Validate input
                if (typeof newAuthState !== 'boolean') {
                  console.error('[WebSocket] Invalid auth update - isAuthenticated must be boolean');
                  ws.send(JSON.stringify({
                    type: 'auth_error',
                    error: 'Invalid authentication data',
                    timestamp: Date.now()
                  }));
                  return;
                }
                
                if (!newUserId) {
                  console.error('[WebSocket] Invalid auth update - userId is required');
                  ws.send(JSON.stringify({
                    type: 'auth_error',
                    error: 'User ID is required',
                    timestamp: Date.now()
                  }));
                  return;
                }
                
                // Update the connection with new auth state
                updateUserConnection(ws, newUserId, newAuthState);
                
                // Acknowledge the auth update
                ws.send(JSON.stringify({
                  type: 'auth_state_updated',
                  success: true,
                  userId: ws.userId,
                  isAuthenticated: ws.isAuthenticated,
                  timestamp: Date.now()
                }));
                
                console.log(`[WebSocket] Auth state updated for ${connectionId}:`, {
                  userId: ws.userId,
                  isAuthenticated: ws.isAuthenticated,
                  userConnections: userConnections.get(ws.userId)?.size || 0
                });
                
                return;
              }
              
              // Handle other message types here...
              
            } catch (error) {
              console.error(`[WebSocket] Error processing message from ${connectionId}:`, error);
            }
          };
          
          // Set up message handler
          ws.on('message', handleMessage);
          
          /**
           * Clean up WebSocket connection resources
           */
          const cleanupConnection = () => {
            if (!ws || !connectionId) return;
            
            console.log(`[WebSocket] Cleaning up connection: ${connectionId} (${userId || 'unknown'})`);
            
            // Clear ping interval if it exists
            if (ws.pingInterval) {
              clearInterval(ws.pingInterval);
              ws.pingInterval = null;
            }
            
            // Clear ping timeout if it exists
            if (ws.pingTimeout) {
              clearTimeout(ws.pingTimeout);
              ws.pingTimeout = null;
            }
            
            // Remove from user connections
            if (userId && userConnections.has(userId)) {
              const userWsSet = userConnections.get(userId);
              if (userWsSet) {
                userWsSet.delete(ws);
                
                if (userWsSet.size === 0) {
                  userConnections.delete(userId);
                  console.log(`[WebSocket] Removed last connection for user ${userId}`);
                }
              }
            }
            
            // Clean up any message queue if it exists
            if (ws.messageQueue) {
              ws.messageQueue = null;
            }
            
            // Clear any event listeners to prevent memory leaks
            ws.removeAllListeners('pong');
            ws.removeAllListeners('ping');
            ws.removeAllListeners('message');
            ws.removeAllListeners('close');
            ws.removeAllListeners('error');
            
            // Clear any ping intervals or timeouts
            if (ws.pingInterval) {
              clearInterval(ws.pingInterval);
              ws.pingInterval = null;
            }
            if (ws.pingTimeout) {
              clearTimeout(ws.pingTimeout);
              ws.pingTimeout = null;
            }
            
            // Force close the connection if it's still open
            if (ws.readyState === WebSocket.OPEN) {
              try {
                ws.terminate();
              } catch (e) {
                console.error(`[${connectionId}] Error terminating connection:`, e);
              }
            }
            
            console.log(`[WebSocket] Connection cleanup complete for ${connectionId}`);
          };
          
          // Handle connection close
          const handleClose = (code, reason) => {
            const closeInfo = {
              connectionId,
              userId,
              code,
              reason: reason?.toString() || 'No reason provided',
              wasClean: ws.readyState === ws.CLOSED,
              connectedAt: ws.connectedAt ? new Date(ws.connectedAt).toISOString() : 'unknown',
              duration: ws.connectedAt ? `${((Date.now() - ws.connectedAt) / 1000).toFixed(2)}s` : 'unknown'
            };
            
            console.log(`[WebSocket] Connection closed: ${connectionId}`);
            
            // Clean up resources
            cleanupConnection();
            
            // Log connection statistics
            const activeUsers = userConnections.size;
            console.log(`[WebSocket] Connection stats - Active: ${activeUsers}`);
          };
          
          // Handle errors
          const handleError = (error) => {
            const errorInfo = {
              connectionId,
              userId,
              error: error.message,
              stack: error.stack,
              timestamp: new Date().toISOString()
            };
            
            console.error(`[WebSocket] Connection error: ${error.message || 'Unknown error'}`);
            
            // Clean up resources
            cleanupConnection();
            
            // Force close the connection if not already closed
            if (ws.readyState === ws.OPEN) {
              try {
                ws.terminate();
              } catch (terminateError) {
                console.error(`[WebSocket] Error terminating connection ${connectionId}:`, terminateError);
              }
            }
          };
          
          // Set up close and error handlers
          ws.on('close', handleClose);
          ws.on('error', handleError);
          
          // Set up ping interval for this connection
          const pingInterval = setInterval(() => {
            if (ws.readyState === ws.OPEN) {
              try {
                ws.ping();
                console.log(`[${connectionId}] Sent ping`);
              } catch (error) {
                console.error(`[${connectionId}] Error sending ping:`, error);
                ws.terminate();
              }
            }
          }, 30000); // Send a ping every 30 seconds
          
          // Store the interval ID for cleanup
          ws.pingInterval = pingInterval;
          
          // Set up a one-time handler for when the connection is closed
          const onClose = () => {
            clearInterval(pingInterval);
            // Remove all event listeners to prevent memory leaks
            ws.removeAllListeners('pong');
            ws.removeAllListeners('ping');
            ws.removeAllListeners('message');
            ws.removeAllListeners('close');
            ws.removeAllListeners('error');
            
            // Clean up any remaining intervals or timeouts
            if (ws.pingInterval) {
              clearInterval(ws.pingInterval);
              ws.pingInterval = null;
            }
            if (ws.pingTimeout) {
              clearTimeout(ws.pingTimeout);
              ws.pingTimeout = null;
            }
          };
          
          ws.once('close', onClose);
          ws.once('error', onClose);
        });
      } catch (error) {
        console.error('[WebSocket] Upgrade error:', error);
        if (!socket.destroyed) {
          socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
          socket.destroy();
        }
      }
    });
  });
  
  // Constants for ping/pong timing
  const PING_INTERVAL = 30000; // 30 seconds between pings
  const PONG_TIMEOUT = 45000;  // 45 seconds to wait for pong before timeout
  
  // Track all ping intervals for cleanup
  const pingIntervals = new Map();
  
  // Clean up all intervals when server closes
  wss.on('close', () => {
    console.log('WebSocket server closing, cleaning up intervals...');
    for (const [connectionId, interval] of pingIntervals.entries()) {
      clearInterval(interval);
      pingIntervals.delete(connectionId);
    }
  });
  
  // Helper function to setup ping interval for a connection
  function setupPingInterval(ws) {
    // Clear any existing interval
    if (ws.pingInterval) {
      clearInterval(ws.pingInterval);
    }
    
    // Set up new interval for checking connection health
    ws.pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          // Check if we've received any activity recently
          const now = Date.now();
          const timeSinceLastActivity = now - (ws.lastActivity || 0);
          
          // If no activity for too long, terminate the connection
          if (timeSinceLastActivity > 60000) { // 60 seconds of no activity
            console.log(`[${ws.connectionId}] No activity for ${Math.floor(timeSinceLastActivity/1000)}s, disconnecting`);
            ws.terminate();
            return;
          }
          
          // If we're waiting for a pong and it's been too long, terminate
          if (ws.waitingForPong && ws.lastPingTime && (now - ws.lastPingTime > 10000)) {
            console.log(`[${ws.connectionId}] No pong received in ${now - ws.lastPingTime}ms, disconnecting`);
            ws.terminate();
            return;
          }
          
          // Only send a new ping if we're not already waiting for a pong
          if (!ws.waitingForPong) {
            ws.waitingForPong = true;
            ws.lastPingTime = now;
            
            // Send a simple ping (no data to minimize traffic)
            ws.ping(null, (err) => {
              if (err) {
                console.error(`[${ws.connectionId}] Error sending ping:`, err);
                ws.waitingForPong = false;
              }
            });
          }
          
        } catch (error) {
          console.error(`[${ws.connectionId}] Error in connection check:`, error);
        }
      }
    }, 30000); // Check connection every 30 seconds
    
    // Store interval for cleanup
    pingIntervals.set(ws.connectionId, ws.pingInterval);
    
    // Clean up interval when connection closes
    const cleanup = () => {
      if (ws.pingInterval) {
        clearInterval(ws.pingInterval);
        pingIntervals.delete(ws.connectionId);
      }
      if (ws.pingTimeout) {
        clearTimeout(ws.pingTimeout);
      }
    };
    
    ws.once('close', cleanup);
    ws.once('error', cleanup);
  };
  
  return wss;
}

// ======================================
// 2. MODEL IMPORTS
// ======================================
import User from './src/models/User.js';
import Message from './src/models/Message.js';
import Task from './src/models/Task.js';
import ChatHistory from './src/models/ChatHistory.js';
import Billing from './src/models/Billing.js';

// ======================================
// 3. UTILS & REPORT GENERATORS
// ======================================
import { stripLargeFields } from './src/utils/stripLargeFields.js';
import { generateReport } from './src/utils/reportGenerator.js';
import { editMidsceneReport } from './src/utils/midsceneReportEditor.js';
import * as reportHandlers from './src/utils/reportFileFixer.js';
import executionHelper from './src/utils/execution-helper.js';
const { determineExecutionMode } = executionHelper;

// ======================================
// 4. CONFIGURATION & ENVIRONMENT
// ======================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// List of environment variables that should be available to the client
const clientEnvVars = [
  'API_URL',
  'FRONTEND_URL'
];

// Load environment variables based on NODE_ENV
const envFile = process.env.NODE_ENV === 'production'
  ? path.resolve(__dirname, '.env.production')
  : path.resolve(__dirname, '.env.development');

console.log('Loading environment from:', envFile);
console.log('File exists:', fs.existsSync(envFile));

// Load the environment file
const result = dotenv.config({ path: envFile });

// Ensure VITE_ prefixed variables are set for the client
clientEnvVars.forEach(key => {
  // If VITE_ prefixed version exists, use it
  if (process.env[`VITE_${key}`]) {
    // If non-prefixed version doesn't exist, create it for server-side use
    if (!process.env[key]) {
      process.env[key] = process.env[`VITE_${key}`];
    }
  } 
  // If non-prefixed version exists, ensure VITE_ prefixed version is set for client
  else if (process.env[key]) {
    process.env[`VITE_${key}`] = process.env[key];
  }
});

// Log all relevant environment variables for debugging
const relevantVars = {};
Object.entries(process.env).forEach(([key, value]) => {
  if (key.includes('VITE_') || key.includes('API_') || key.includes('WS_') || key.includes('FRONTEND_')) {
    relevantVars[key] = value;
  }
});
console.log('Environment variables loaded:', relevantVars);

if (result.error) {
  console.error('Error loading .env file:', result.error);
  process.exit(1);
}

// Import environment configuration
import config from './src/config/env.js';

// Global unhandled promise rejection handler for Puppeteer errors
process.on('unhandledRejection', (reason, promise) => {
  if (reason && reason.message && reason.message.includes('Request is already handled')) {
    logger.debug('[Puppeteer] Ignoring known issue: Request is already handled');
  } else {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  }
});

// ======================================
// 5. CONSTANTS & GLOBALS
// ======================================
const PORT = config.port;
const NODE_ENV = config.nodeEnv;
const MAX_CONCURRENT_BROWSERS = 5;
const OPENAI_API_KAIL = process.env.OPENAI_API_KAIL;

// Track active browser sessions (singleton instance)
// Engine configuration
const ENGINE_KEY_MAPPING = {
  'gpt-4o': 'openai',
  'qwen-2.5-vl-72b': 'qwen',
  'gemini-2.5-pro': 'google',
  'ui-tars': 'uitars',
};

const KEY_ENGINE_MAPPING = Object.entries(ENGINE_KEY_MAPPING).reduce((acc, [engine, keyType]) => {
  acc[keyType] = engine;
  return acc;
}, {});

// ======================================
// 6. LOGGER SETUP
// ======================================
// Ensure run/report directories exist
const NEXUS_RUN_DIR = path.join(__dirname, 'nexus_run');
fs.mkdirSync(NEXUS_RUN_DIR, { recursive: true });
const REPORT_DIR = path.join(NEXUS_RUN_DIR, 'report');
fs.mkdirSync(REPORT_DIR, { recursive: true });
const LOG_DIR = path.join(NEXUS_RUN_DIR, 'logs');
fs.mkdirSync(LOG_DIR, { recursive: true });
const ARTIFACTS_DIR = path.join(NEXUS_RUN_DIR, 'artifacts');
fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });

// Export paths for use elsewhere in the application
global.NEXUS_PATHS = {
  RUN_DIR: NEXUS_RUN_DIR,
  REPORT_DIR: REPORT_DIR,
  LOG_DIR: LOG_DIR,
  ARTIFACTS_DIR: ARTIFACTS_DIR
};

// Logger Configuration - Simplified
const logger = winston.createLogger({
  level: 'warn', // Default to warn level
  format: winston.format.combine(
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.errors({ stack: NODE_ENV !== 'production' }),
    winston.format.splat(),
    winston.format.simple()
  ),
  defaultMeta: { service: 'nexus-backend' },
  transports: [
    new winston.transports.Console()
  ]
});

// Only log startup message if not in test environment
if (process.env.NODE_ENV !== 'test') {
  logger.info(`Nexus run directory structure prepared at ${NEXUS_RUN_DIR}`);
}

/**
 * Helper function to conditionally log debug messages.
 */

function debugLog(msg, data = null) {
  if (NODE_ENV !== 'production') {
    if (data) {
      logger.debug(msg, data);
    } else {
      logger.debug(msg);
    }
  }
}

// ======================================
// 7. DATABASE CONNECTION & UTILITIES
// ======================================
import { connectDB, closeDB } from './src/config/database.js';

// Set mongoose options
mongoose.set('strictQuery', true);

/**
 * Connect to MongoDB with retry logic and proper error handling
 * @returns {Promise<boolean>} True if connection was successful
 */
async function connectToDatabase() {
  const startTime = Date.now();
  try {
    await connectDB();
    console.log(`Connected to MongoDB in ${Date.now() - startTime}ms`);
    return true;
  } catch (err) {
    console.error('MongoDB connection error:', err);
    
    // Check if connection has gone away or if it's a network issue
    const isTemporaryError = 
      err.name === 'MongoNetworkError' || 
      err.message.includes('topology was destroyed') || 
      err.message.includes('ECONNREFUSED') ||
      err.message.includes('timed out');
    
    if (!isTemporaryError) {
      // If it's a permanent error (like auth failure), abort retries
      throw new AbortError(`MongoDB permanent connection error: ${err.message}`);
    }
    
    // For temporary errors, throw the original error to allow retry
    throw err;
  }
}

/**
 * Ensure database indexes are created with proper error handling
 */
async function ensureIndexes() {
  try {
    await Promise.all([
      User.createIndexes(),
      Task.createIndexes(),
      Message.createIndexes(),
      ChatHistory.createIndexes(),
      Billing.createIndexes()
    ]);
    
    logger.info('Database indexes ensured');
  } catch (error) {
    logger.error('Error ensuring database indexes:', error);
    // Don't fail the application if index creation fails
    // The application can still function, but queries might be slower
  }
}

/**
 * Checks if a browser session is healthy and operational
 * @param {Object} session - Browser session object
 * @returns {Promise<boolean>} - True if session is healthy
 */
async function isBrowserSessionHealthy(session) {
  if (!session || !session.browser) return false;
  
  try {
    const pages = await session.browser.pages();
    return Array.isArray(pages) && pages.length > 0 && pages[0].isClosed !== true;
  } catch (err) {
    logger.error(`Browser health check failed: ${err.message}`);
    return false;
  }
}

/**
 * Get a human-readable display name for an engine
 * @param {string} engineId - The engine ID
 * @returns {string} - Human-readable display name
 */
function getEngineDisplayName(engineId) {
  const displayNames = {
    'gpt-4o': 'OpenAI GPT-4o',
    'qwen-2.5-vl-72b': 'Qwen 2.5',
    'gemini-2.5-pro': 'Google Gemini',
    'ui-tars': 'UI-TARS'
  };
  return displayNames[engineId] || engineId;
}

// ======================================
// 8. EXPRESS APP & MIDDLEWARE - IN ORDER
// ======================================
// Session configuration with secure settings
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true, // Allow uninitialized sessions for guests
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    domain: process.env.NODE_ENV === 'production' ? 
      (process.env.COOKIE_DOMAIN || '.dexter-ai.io') : undefined,
    path: '/'  // Ensure cookie is sent for all paths
  },
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    ttl: 7 * 24 * 60 * 60, // 7 days
    autoRemove: 'interval',
    autoRemoveInterval: 60, // Check for expired sessions every 60 minutes
    collectionName: 'sessions',
    stringify: false,
    touchAfter: 3600, // 1 hour - only update session if it's been modified
    crypto: {
      secret: process.env.SESSION_ENCRYPTION_KEY || 'your-encryption-key'
    }
  }),
  name: 'nexus.sid',
  unset: 'destroy',
  proxy: true, // Trust the reverse proxy (e.g., Nginx, Cloudflare)
  rolling: true, // Reset the cookie maxAge on every request
  saveUninitialized: true, // Save new sessions
  genid: function(req) {
    // Generate guest ID if no user is logged in
    if (!req.session || !req.session.user) {
      return `guest_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    }
    return uuidv4(); // Use UUIDs for authenticated session IDs
  }
});

// Initialize Puppeteer
puppeteerExtra.use(StealthPlugin());

// ======================================
// 8.1 BODY PARSERS (MUST come before any route handlers)
// ======================================
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// ======================================
// 8.2 SESSION MIDDLEWARE
// ======================================
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1); // Trust first proxy
}
app.use(sessionMiddleware);

// ======================================
// 8.3 GUEST SESSION HANDLING
// ======================================
app.use((req, res, next) => {
  // Skip session creation for WebSocket upgrade, API validation, and socket.io requests
  if (req.path === '/api/auth/validate-session' || 
      req.path.startsWith('/socket.io/') || 
      req.headers.upgrade === 'websocket') {
    return next();
  }
  
  // Only create guest session for non-API routes
  if (!req.session.user && !req.path.startsWith('/api/')) {
    req.session.user = `guest_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
    console.log('Created guest session:', req.session.user);
  }
  next();
});

// Skip logging for 404s on specific endpoints
app.use((req, res, next) => {
  const skipLogging = 
    (req.path === '/api/user/available-engines' && req.method === 'GET' && res.statusCode === 404);
  
  // If we should skip logging, override the end method
  if (skipLogging) {
    const originalEnd = res.end;
    res.end = function (chunk, encoding) {
      res.end = originalEnd;
      return res.end(chunk, encoding);
    };
  }
  
  next();
});

// 8.4 Enhanced CORS Middleware for all environments
app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Always allow requests with no origin (like mobile apps or curl requests)
  if (!origin) return next();
  
  // Allow localhost and 127.0.0.1 in development
  const isLocalhost = origin.includes('localhost:') || origin.includes('127.0.0.1:');
  
  // In production, allow any *.ondigitalocean.app subdomain
  if (isProduction || isLocalhost) {
    if (isProduction ? origin.endsWith('.ondigitalocean.app') || origin.endsWith('.dexter-ai.io') : true) {
      // Set CORS headers
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID, Cache-Control, Pragma, Content-Range, X-Total-Count');
      res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
      res.setHeader('Vary', 'Origin');
      
      // Handle preflight requests
      if (req.method === 'OPTIONS') {
        return res.status(204).end();
      }
      return next();
    }
  } 
  // In development, allow common localhost origins
  else {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:3420',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:3420',
      `http://${req.headers.host}`,
      `https://${req.headers.host}`
    ];
    
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-Request-ID');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Range, X-Total-Count, X-Request-ID');
      res.setHeader('Vary', 'Origin');
      
      if (req.method === 'OPTIONS') {
        return res.status(204).end();
      }
      return next();
    }
  }
  
  // If we get here, the origin is not allowed
  if (isProduction) {
    // In production, block unauthorized origins
    return res.status(403).json({ 
      error: 'Not allowed by CORS',
      message: 'The origin is not allowed to access this resource',
      allowedOrigins: []
    });
  }
  
  // 8.5 CSP Middleware - Configured to work with CORS and session configurations
  const cspDirectives = [
    `default-src 'self' data: blob:`,
    `connect-src 'self' ${isAllowedOrigin ? origin : ''} ws: wss: data: blob: ${isProduction ? '' : 'http://localhost:*'}`,
    // Allow WebGL and WebAssembly
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' data: blob: https:`,
    // Allow inline styles and external stylesheets
    `style-src 'self' 'unsafe-inline' data: blob: https:`,
    // Allow images and media from any source
    `img-src 'self' data: blob: https: *`,
    // Allow fonts from any source
    `font-src 'self' data: blob: https: *`,
    // Allow media from any source
    `media-src 'self' data: blob: https: *`,
    // Allow WebWorkers
    `worker-src 'self' blob: data: https:`,
    // Allow WebGL and WebGPU contexts
    `child-src 'self' blob: data: https:`,
    // Allow iframes
    `frame-src 'self' data: blob: https:`,
    // Required for WebGL and WebGPU
    `script-src-elem 'self' 'unsafe-inline' 'unsafe-eval' https:`,
    `style-src-elem 'self' 'unsafe-inline' https:`,
    // Allow WebGL and WebGPU
    `worker-src 'self' blob: data:`,
    // Allow WebAssembly
    `wasm-unsafe-eval 'self'`,
    // Allow WebGL and WebGPU
    `require-trusted-types-for 'script'`
  ].join('; ') + ';';
  
  // Set security headers
  res.setHeader('Content-Security-Policy', cspDirectives);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Feature-Policy', "geolocation 'self'; microphone 'none'; camera 'none'");
  
  next();
});

// 8.6 CDN and cookie fixer middleware
// 8.7 Request Logging - only log server errors (5xx) and skip common non-error paths
app.use((req, res, next) => {
  const start = Date.now();
  const { method, url, ip } = req;
  
  // Skip logging for common non-error paths
  const skipPaths = [
    '/api/health',
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    '/static/',
    '/assets/',
    '/_next/',
    '/__nextjs_',
    '/_nuxt/'
  ];
  
  if (skipPaths.some(path => url.startsWith(path))) {
    return next();
  }
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const { statusCode } = res;
    const contentLength = res.get('Content-Length') || 0;
    
    // Log 5xx errors (server errors) and 404s for non-API routes in development
    const shouldLog = 
      statusCode >= 500 || 
      (process.env.NODE_ENV === 'development' && statusCode === 404 && !url.startsWith('/api/'));
    
    if (shouldLog) {
      const logData = {
        method,
        url,
        status: statusCode,
        duration: `${duration}ms`,
        contentLength: contentLength ? `${contentLength}b` : '0b',
        ip,
        userAgent: req.headers['user-agent']
      };
      
      // Use appropriate log level based on status code
      if (statusCode >= 500) {
        logger.error('Server error', logData);
      } else {
        logger.warn('Client error', logData);
      }
    }
  });
  
  next();
});

// ======================================
// 9. SERVER INITIALIZATION
// ======================================

let httpServer;

async function startApp() {
  try {
    // Connect to MongoDB with retry logic
    await pRetry(connectToDatabase, {
      retries: 5,
      minTimeout: 2000,
      onFailedAttempt: error => {
        console.log(`MongoDB connection attempt ${error.attemptNumber} failed. Retrying...`);
      }
    });
    
    console.log('✅ MongoDB connected');
    
    // Clear database and ensure indexes
    await clearDatabaseOnce();
    await ensureIndexes();
    
    // Create HTTP server
    httpServer = createServer(app);
    
    // Initialize WebSocket server with the HTTP server
    const wss = setupWebSocketServer(httpServer);
    
    // Store server instances globally for cleanup
    global.httpServer = httpServer;
    global.wss = wss;
    
    // Get port from environment or use default 3420 for development
    const PORT = process.env.PORT || 3420;
    
    // Handle server errors
    httpServer.on('error', (error) => {
      console.error('HTTP server error:', error);
      if (error.syscall !== 'listen') {
        throw error;
      }
      
      // Handle specific listen errors with friendly messages
      switch (error.code) {
        case 'EACCES':
          console.error(`Port ${PORT} requires elevated privileges`);
          process.exit(1);
          break;
        case 'EADDRINUSE':
          console.error(`Port ${PORT} is already in use`);
          process.exit(1);
          break;
        default:
          throw error;
      }
    });
    
    // Handle process termination
    const gracefulShutdown = () => {
      console.log('\n🛑 Shutting down gracefully...');
      
      // Close WebSocket server
      if (wss) {
        console.log('Closing WebSocket server...');
        wss.close(() => {
          console.log('WebSocket server closed');
        });
      }
      
      // Close HTTP server
      if (httpServer) {
        console.log('Closing HTTP server...');
        httpServer.close(() => {
          console.log('HTTP server closed');
          process.exit(0);
        });
      }
      
      // Force exit after timeout
      setTimeout(() => {
        console.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };
    // Start the server
    return new Promise((resolve, reject) => {
      const HOST = process.env.HOST || '0.0.0.0';  // Default to all interfaces
      
      // Handle server errors
      httpServer.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
          console.error(`❌ Port ${PORT} is already in use. Please check for other running instances.`);
          // Try to find and list processes using the port
          require('child_process').exec(`netstat -ano | findstr :${PORT}`, (err, stdout) => {
            if (stdout) {
              console.log('Processes using port:', stdout);
            }
          });
        }
        reject(error);
      });

      httpServer.listen(PORT, HOST, () => {
        const protocol = process.env.NODE_ENV === 'production' ? 'wss' : 'ws';
        const host = process.env.NODE_ENV === 'production' 
          ? process.env.APP_DOMAIN || 'operator.dexter-ai.io'
          : 'localhost';
        
        // To:
        const wsPath = '/ws';
        const wsUrl = `${protocol}://${host}${process.env.NODE_ENV === 'production' ? '' : `:${PORT}`}${wsPath}`;

        console.log(`\n🚀 Server running on port ${PORT}`);
        console.log(`🌐 WebSocket available at ${wsUrl}`);
        console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}\n`);

        const ROBOT_ICON = '\u001b[38;5;39m🤖\u001b[0m'; // Bright blue robot
        const LAB_ICON = '\u001b[38;5;208m🧪\u001b[0m';   // Orange lab flask
        const GEAR_ICON = '\u001b[38;5;220m⚙️\u001b[0m';   // Yellow gear

        console.log(`\n${ROBOT_ICON}  \u001b[1mO.P.E.R.A.T.O.R - Nexus Server started successfully!\u001b[0m`);
        console.log(`================================`);
        console.log(`${LAB_ICON}  Environment: \u001b[36m${process.env.NODE_ENV || 'development'}\u001b[0m`);
        console.log(`${GEAR_ICON}  Port: \u001b[33m${PORT}\u001b[0m`);
        console.log(`${ROBOT_ICON}  API URL: \u001b[32m${config.apiUrl}\u001b[0m`);
        console.log(`${LAB_ICON}  Frontend URL: \u001b[35m${config.frontendUrl}\u001b[0m`);
        console.log(`${ROBOT_ICON}  WebSocket URL: \u001b[34m${wsUrl}\u001b[0m`);
        console.log(`================================\n`);
        
        // Update config with the correct WebSocket URL
        if (config) {
          config.wsUrl = wsUrl;
        }
        
        // Store the server and WebSocket instances globally for cleanup
        global.httpServer = httpServer;
        global.wss = wss;
        
        resolve(httpServer);
      });
    }).catch(error => {
      console.error('Failed to start server:', error.message);
      if (error.code === 'EADDRINUSE') {
        console.log('\nTo fix this issue, try one of these commands in a new terminal:');
        console.log('1. Kill all Node.js processes: taskkill /F /IM node.exe');
        console.log('2. Or find and kill the specific process using port 3420:');
        console.log('   netstat -ano | findstr :3420');
        console.log('   taskkill /F /PID <PID> (replace <PID> with the process ID from above)');
      }
      process.exit(1);
    });
  } catch (err) {
    console.error('Failed to start application:', err);
    process.exit(1);
  }
}

// ====================================
// 10. ROUTES & MIDDLEWARE
// ======================================

import authRoutes from './src/routes/auth.js';
import taskRoutes from './src/routes/tasks.js';
import billingRoutes from './src/routes/billing.js';
import yamlMapsRoutes from './src/routes/yaml-maps.js';
import userRoutes from './src/routes/user.js';
import historyRouter from './src/routes/history.js';
import customUrlsRouter from './src/routes/customUrls.js';
import settingsRouter from './src/routes/settings.js';
import { requireAuth } from './src/middleware/requireAuth.js';
import messagesRouter from './src/routes/messages.js';
import { setStaticFileHeaders } from './src/middleware/staticAssets.js';
import serveStaticAssets from './src/middleware/staticAssets.js';

// 1. API ROUTES (must come before static files and catch-all)
// =================================================
app.use('/api/yaml-maps', yamlMapsRoutes);

// Authentication guard middleware
/*
const guard = (req, res, next) => {
  // Skip authentication for static files and login page
  if (
    req.path === '/api/health' ||
    req.path.startsWith('/css/') || 
    req.path.startsWith('/assets/') ||
    req.path.startsWith('/js/') ||
    req.path.startsWith('/images/') ||
    req.path.endsWith('.css') ||
    req.path.endsWith('.js') ||
    req.path.endsWith('.png') ||
    req.path.endsWith('.jpg') ||
    req.path.endsWith('.jpeg') ||
    req.path.endsWith('.gif') ||
    req.path.endsWith('.svg') ||
    req.path.endsWith('.woff') ||
    req.path.endsWith('.woff2') ||
    req.path.endsWith('.ttf') ||
    req.path.endsWith('.eot') ||
    req.path === '/login.html' ||
    req.path === '/'
  ) {
    return next();
  }
  
  // Require authentication for all other routes
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
};
*/

// ======================================
// 2. API ROUTES
// =================================================

// Public API routes (no auth required)
app.use('/api/auth', authRoutes);


// API: Who Am I (userId sync endpoint) - Moved to robust implementation below

// Protected API routes (require authentication)
app.use('/api/settings', requireAuth, settingsRouter);
app.use('/api/history', requireAuth, historyRouter);
app.use('/api/tasks', requireAuth, taskRoutes);
app.use('/api/custom-urls', requireAuth, customUrlsRouter);
app.use('/api/yaml-maps', requireAuth, yamlMapsRoutes);
app.use('/api/billing', requireAuth, billingRoutes);
app.use('/api/user', requireAuth, userRoutes);
app.use('/api/messages', requireAuth, messagesRouter);

// ======================================
// 2. API ROUTES (must come before static files)
// ======================================

// GET /api/nli route - CORS is handled by the corsMiddleware
app.get('/api/nli', requireAuth, async (req, res) => {
  // Set SSE-specific headers
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no' // Disable buffering for nginx
  });

  const userId = req.session.user;
  const prompt = req.query.prompt;
  const requestedEngine = req.query.engine || req.session.browserEngine;

  // Validate prompt
  if (typeof prompt !== 'string' || !prompt.trim()) {
    const errorData = {
      event: 'error',
      content: 'Prompt query parameter is required.',
      isError: true,
      timestamp: new Date().toISOString()
    };
    res.write(`data: ${JSON.stringify(errorData)}\n\n`);
    res.write(`data: ${JSON.stringify({
      event: 'thoughtComplete',
      text: 'Error: Prompt is required',
      isError: true,
      errorType: 'validation',
      timestamp: new Date().toISOString()
    })}\n\n`);
    res.end();
    return;
  }

  // Engine validation and setup (existing code)
  if (requestedEngine) {
    const validEngines = ['gpt-4o', 'qwen-2.5-vl-72b', 'gemini-2.5-pro', 'ui-tars'];
    if (!validEngines.includes(requestedEngine)) {
      const errorData = {
        event: 'error',
        content: 'Invalid engine specified',
        isError: true,
        errorType: 'validation',
        timestamp: new Date().toISOString()
      };
      res.write(`data: ${JSON.stringify(errorData)}\n\n`);
      res.write(`data: ${JSON.stringify({
        event: 'thoughtComplete',
        text: 'Error: Invalid engine specified',
        isError: true,
        errorType: 'validation',
        timestamp: new Date().toISOString()
      })}\n\n`);
      res.end();
      return;
    }
    req.session.browserEngine = requestedEngine;
    console.log(`[NLI] Updated browser engine to: ${requestedEngine}`);

    const keyInfo = await checkEngineApiKey(userId, requestedEngine);
    if (!keyInfo.hasKey) {
      const errorData = {
        event: 'authError',
        content: `No API key available for ${requestedEngine}. Please configure one in Settings.`,
        isError: true,
        errorType: 'auth',
        keyInfo,
        timestamp: new Date().toISOString()
      };
      res.write(`data: ${JSON.stringify(errorData)}\n\n`);
      res.write(`data: ${JSON.stringify({
        event: 'thoughtComplete',
        text: `Error: No API key available for ${requestedEngine}`,
        isError: true,
        errorType: 'auth',
        timestamp: new Date().toISOString()
      })}\n\n`);
      res.end();
      return;
    }

    if (keyInfo.usingDefault) {
      notifyApiKeyStatus(userId, keyInfo);
    }
  }

  // Clean up tempEngine (existing code)
  if (req.session.tempEngine) {
    console.log(`[NLI] Removing deprecated tempEngine=${req.session.tempEngine} from session`);
    if (!req.session.browserEngine) {
      req.session.browserEngine = req.session.tempEngine;
      console.log(`[NLI] Migrated tempEngine to browserEngine=${req.session.browserEngine}`);
    }
    delete req.session.tempEngine;
    req.session.save();
  }

  // Classify prompt
  let classification;
  try {
    classification = await openaiClassifyPrompt(prompt, userId);
  } catch (err) {
    console.error('Classification error:', err);
    
    // Error response will use the headers already set at the start of the route
    
    const isQuotaErr = isQuotaError(err);
    const isAuthErr = isAuthError(err);
    
    let errorEvent = {
      event: 'error',
      content: 'Error classifying prompt. Please try again later.'
    };
    
    if (isQuotaErr) {
      console.error('[NLI] Quota error during classification');
      errorEvent = {
        event: 'quotaExceeded',
        content: 'API quota exceeded. Please check your account status or try again later.'
      };
    } else if (isAuthErr) {
      console.error('[NLI] Auth error during classification');
      errorEvent = {
        event: 'authError',
        content: 'Authentication error. Please verify your API key in Settings > API Keys.'
      };
    }
    
    // FIXED: Proper SSE event format and flushing
    res.write(`data: ${JSON.stringify(errorEvent)}\n\n`);
    if (res.flush) res.flush();
    
    res.write(`data: ${JSON.stringify({
      event: 'thoughtComplete',
      text: errorEvent.content,
      isError: true,
      errorType: errorEvent.event
    })}\n\n`);
    if (res.flush) res.flush();
    
    res.end();
    return;
  }

  const userDoc = await User.findById(userId).lean();
  const userEmail = userDoc?.email;

  if (classification === 'task') {
    // Using the SSE headers already set at the start of the route

    // Task creation code (existing)
    let chatHistory = await ChatHistory.findOne({ userId }) || new ChatHistory({ userId, messages: [] });
    chatHistory.messages.push({ role: 'user', content: prompt, timestamp: new Date() });
    await chatHistory.save();

    const taskId = new mongoose.Types.ObjectId();
    const runId = uuidv4();
    const runDir = path.join(NEXUS_RUN_DIR, runId);
    fs.mkdirSync(runDir, { recursive: true });

    const engineToProvider = {
      'gpt-4o': 'openai',
      'qwen-2.5-vl-72b': 'qwen',
      'gemini-2.5-pro': 'google',
      'ui-tars': 'uitars'
    };

    const executionModePreference = userDoc.settings?.executionMode || 'step-planning';
    const engine = req.session.browserEngine || 'gpt-4o';
    const provider = engineToProvider[engine] || 'openai';
    const executionMode = determineExecutionMode(provider, prompt, executionModePreference);

    await new Task({ 
      _id: taskId, 
      userId, 
      command: prompt, 
      status: 'pending', 
      progress: 0, 
      startTime: new Date(), 
      runId,
      executionMode,
      engine
    }).save();

    await User.updateOne({ _id: userId }, { 
      $push: { 
        activeTasks: { 
          _id: taskId.toString(), 
          command: prompt, 
          status: 'pending', 
          startTime: new Date(),
          executionMode,
          engine
        } 
      } 
    });

    // Send task start event with proper SSE formatting
    const taskStartEvent = {
      event: 'taskStart',
      payload: {
        taskId: taskId.toString(),
        command: prompt,
        startTime: new Date().toISOString()
      }
    };
    res.write(`data: ${JSON.stringify(taskStartEvent)}\n\n`);
    if (res.flush) res.flush();

    // FIXED: Proper cleanup and timeout handling
    let interval;
    let timeoutId;
    let taskCompleted = false;

    // Start task processing with proper error handling
    (async () => {
      try {
        await processTask(userId, userEmail, taskId.toString(), runId, runDir, prompt, null, null);
        taskCompleted = true;
      } catch (err) {
        console.error('Error in processTask:', err);
        
        // Ensure we have a proper error message
        const errorMessage = err?.message || 'Error processing task';
        const errorCode = err?.code || 'PROCESS_TASK_ERROR';
        
        // Send error event to client
        if (res.writable) {
          res.write(`data: ${JSON.stringify({ 
            event: 'taskError',
            taskId: taskId.toString(),
            error: errorMessage,
            code: errorCode,
            timestamp: new Date().toISOString()
          })}\n\n`);
          if (res.flush) res.flush();
        }
        
        // Update task status in database
        await updateTaskInDatabase(taskId, {
          status: 'failed',
          error: errorMessage,
          completedAt: new Date()
        });
        
        // Clean up
        cleanup();
      }
    })();
    
    const cleanup = () => {
      if (interval) {
        clearInterval(interval);
        interval = null;
      }
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      if (!res.writableEnded) {
        try {
          res.end();
        } catch (e) {
          console.error('Error ending response:', e);
        }
      }
    };

    // Set timeout for the entire operation
    timeoutId = setTimeout(() => {
      console.error(`Task ${taskId} timed out after 15 minutes`);
      if (res.writable) {
        res.write(`data: ${JSON.stringify({
          event: 'error',
          taskId: taskId.toString(),
          error: 'Operation timed out after 15 minutes'
        })}\n\n`);
        if (res.flush) res.flush();
      }
      cleanup();
    }, 15 * 60 * 1000);

    // Handle client disconnect
    req.on('close', cleanup);
    req.on('error', cleanup);

    // Poll for task updates
    interval = setInterval(async () => {
      try {
        const task = await Task.findById(taskId).lean();
        if (!task) {
          console.error(`Task ${taskId} not found`);
          res.write(`data: ${JSON.stringify({ 
            event: 'taskError', 
            taskId: taskId.toString(), 
            error: 'Task not found' 
          })}\n\n`);
          if (res.flush) res.flush();
          return cleanup();
        }

        const done = ['completed', 'error'].includes(task.status);
        const evtName = done ? 'taskComplete' : 'stepProgress';

        let resultWithLinks = task.result || {};
        if (done) {
          resultWithLinks = {
            ...resultWithLinks,
            landingReportUrl: resultWithLinks.landingReportUrl || resultWithLinks.runReport || null,
            nexusReportUrl: resultWithLinks.nexusReportUrl || null,
            runReport: resultWithLinks.runReport || resultWithLinks.landingReportUrl || null,
            reportUrl: resultWithLinks.reportUrl || resultWithLinks.nexusReportUrl || 
                      resultWithLinks.landingReportUrl || resultWithLinks.runReport || 
                      (resultWithLinks.screenshot ? resultWithLinks.screenshot : null)
          };
        }

        // FIXED: Proper event writing and flushing
        res.write(`data: ${JSON.stringify({
          event: evtName,
          payload: {
            taskId: taskId.toString(),
            status: task.status,
            progress: task.progress || 0,
            result: resultWithLinks,
            timestamp: new Date()
          }
        })}\n\n`);
        if (res.flush) res.flush();

        if (done) {
          cleanup();
        }
      } catch (err) {
        console.error('Error polling task status:', err);
        res.write(`data: ${JSON.stringify({
          event: 'taskError',
          taskId: taskId.toString(),
          error: 'Error checking task status'
        })}\n\n`);
        if (res.flush) res.flush();
        cleanup();
      }
    }, 1000);

  } else {
    // Chat response handling with proper SSE setup
    try {
      // SSE headers are already set at the start of the route

      console.log('[NLI] Starting chat stream...');

      try {
        // Stream with proper error handling and flushing
        for await (const event of streamNliThoughts(userId, prompt)) {
          if (!res.writable) {
            console.log('[NLI] Response stream ended, stopping iteration');
            break;
          }
          
          console.log('[NLI] Sending event:', event.event, event.text ? event.text.substring(0, 50) + '...' : '');
          const message = `data: ${JSON.stringify({
            ...event,
            timestamp: new Date().toISOString()
          })}\n\n`;
          res.write(message);
          
          // Always flush after writing
          if (res.flush) {
            res.flush();
          }
        }

        if (res.writable && !res.writableEnded) {
          console.log('[NLI] Stream completed successfully');
          res.write(`data: ${JSON.stringify({
            event: 'complete',
            content: 'Stream completed successfully',
            timestamp: new Date().toISOString()
          })}\n\n`);
          if (res.flush) res.flush();
          res.end();
        }
      } catch (streamError) {
        console.error('[NLI] Error in streaming:', streamError);

        // Error handling functions (existing code)
        function isQuotaError(err) {
          if (!err) return false;
          const errorStr = (err.message || '').toLowerCase() + 
                          (err.code ? ' ' + String(err.code).toLowerCase() : '') +
                          (err.error?.code ? ' ' + String(err.error.code).toLowerCase() : '') +
                          (err.error?.message ? ' ' + String(err.error.message).toLowerCase() : '');
          const quotaIndicators = [
            'quota', 'rate limit', 'rate_limit', 'too many requests',
            'insufficient_quota', 'billing', 'credit', 'limit reached',
            '429', 'usage limit', 'usage_limit', 'quota exceeded',
            'insufficient_quota', 'billing_not_active', 'quota_exceeded',
            'exceeded quota', 'quota limit', 'quota_limit', 'quota reached',
            'insufficient_quota', 'exceeded your current quota', 'account has insufficient funds'
          ];
          return quotaIndicators.some(indicator => 
            errorStr.includes(indicator.toLowerCase())
          );
        }

        function isAuthError(err) {
          if (!err) return false;
          const errorStr = (err.message || '').toLowerCase() + 
                          (err.code ? ' ' + String(err.code).toLowerCase() : '') +
                          (err.error?.code ? ' ' + String(err.error.code).toLowerCase() : '') +
                          (err.error?.message ? ' ' + String(err.error.message).toLowerCase() : '');
  
          const authIndicators = [
            'auth', 'api key', 'api_key', 'invalid', 'unauthorized', 'forbidden',
            'invalid api key', 'invalid_api_key', 'invalid_request_error', '401', '403',
            'authentication', 'authorization', 'no api key', 'missing api key'
          ];
  
          return [401, 403].includes(err?.status) || 
                 authIndicators.some(term => errorStr.includes(term));
        }

        let errorEvent = {
          event: 'error',
          content: 'An error occurred while generating the response.'
        };

        if (isQuotaError(streamError)) {
          console.error('[NLI] Quota error detected');
          const errorMsg = streamError.message || 'API quota exceeded. Please check your account status or try again later.';
          errorEvent = {
            event: 'quotaExceeded',
            content: errorMsg,
            text: `🚫 API Quota Exceeded: ${errorMsg} r, read the docs: https://platform.openai.com/docs/guides/error-codes/api-errors.`,
            isError: true,
            errorType: 'quotaExceeded',
            timestamp: new Date().toISOString()
          };
        } else if (isAuthError(streamError)) {
          console.error('[NLI] Auth error detected');
          const errorMsg = streamError.message || 'Authentication error. Please verify your API key in Settings > API Keys.';
          errorEvent = {
            event: 'authError',
            content: errorMsg,
            text: `🔑 Authentication Error: ${errorMsg}`,
            isError: true,
            errorType: 'authError',
            timestamp: new Date().toISOString()
          };
        } else {
          // For other errors, include more details
          const errorMsg = streamError.message || 'An error occurred while generating the response.';
          errorEvent = {
            event: 'error',
            content: errorMsg,
            text: `❌ Error: ${errorMsg}`,
            isError: true,
            errorType: 'error',
            timestamp: new Date().toISOString()
          };
        }

        if (res.writable && !res.writableEnded) {
          try {
            console.log('[NLI] Sending error event to client:', errorEvent);
            
            // Send the error event
            res.write(`data: ${JSON.stringify(errorEvent)}\n\n`);
            if (res.flush) res.flush();
            
            // Send a thoughtComplete event with the error details
            const completeEvent = {
              event: 'thoughtComplete',
              text: errorEvent.text || errorEvent.content,
              isError: true,
              errorType: errorEvent.errorType || 'error',
              timestamp: new Date().toISOString()
            };
            
            res.write(`data: ${JSON.stringify(completeEvent)}\n\n`);
            if (res.flush) res.flush();
            
            console.log('[NLI] Error events sent to client');
          } catch (writeError) {
            console.error('[NLI] Error writing error event to client:', writeError);
          } finally {
            // Ensure we close the connection
            if (!res.writableEnded) {
              res.end();
            }
          }
        } else {
          console.log('[NLI] Response stream not writable, could not send error');
          if (!res.writableEnded) {
            res.end();
          }
        }
      }
      
      // FIXED: Always end the response
      if (!res.writableEnded) {
        res.end();
      }
      
    } catch (error) {
      console.error('Error in NLI route:', error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: 'Error generating response' });
      } else if (res.writable && !res.writableEnded) {
        res.write(`data: ${JSON.stringify({
          event: 'error',
          content: 'An unexpected error occurred.'
        })}\n\n`);
        if (res.flush) res.flush();
        res.end();
      }
    }
  }
});

app.post('/api/nli', requireAuth, async (req, res) => {
  // Set SSE-specific headers
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no' // Disable buffering for nginx
  });
  
  // Helper function to send error response
  const sendErrorResponse = (status, error, errorType = 'error') => {
    const errorData = {
      event: errorType,
      content: error,
      isError: true,
      errorType,
      timestamp: new Date().toISOString()
    };
    
    if (res.writable && !res.writableEnded) {
      res.write(`data: ${JSON.stringify(errorData)}\n\n`);
      res.write(`data: ${JSON.stringify({
        event: 'thoughtComplete',
        text: error,
        isError: true,
        errorType,
        timestamp: new Date().toISOString()
      })}\n\n`);
      res.end();
      return true;
    }
    
    if (!res.headersSent) {
      return res.status(status).json({ success: false, error, errorType });
    }
    
    return false;
  };

  // Helper function to send SSE event
  const sendSSEEvent = (event, data) => {
    if (res.writable && !res.writableEnded) {
      const eventData = {
        ...data,
        event,
        timestamp: new Date().toISOString()
      };
      res.write(`data: ${JSON.stringify(eventData)}\n\n`);
      if (typeof res.flush === 'function') {
        res.flush();
      }
      return true;
    }
    return false;
  };

  // Accept both { prompt } and legacy { inputText }
  let prompt = req.body.prompt;
  if (!prompt && req.body.inputText) {
    prompt = req.body.inputText;
    console.debug('[DEBUG] /nli: Using legacy inputText as prompt');
  }
  
  // Validate prompt
  if (typeof prompt !== 'string') {
    console.error('[ERROR] /nli: Prompt must be a string');
    return sendErrorResponse(400, 'Prompt must be a string.');
  }

  // Sanitize and validate prompt
  prompt = prompt.trim();
  if (prompt.length === 0) {
    console.error('[ERROR] /nli: Prompt is empty after trim');
    return sendErrorResponse(400, 'Prompt cannot be empty.');
  }
  
  const MAX_PROMPT_LENGTH = 5000;
  if (prompt.length > MAX_PROMPT_LENGTH) {
    console.error(`[ERROR] /nli: Prompt too long (${prompt.length} chars)`);
    return sendErrorResponse(400, `Prompt too long (max ${MAX_PROMPT_LENGTH} chars).`);
  }

  const userId = req.session.user;
  let user;
  try {
    user = await User.findById(userId).select('email openaiApiKey').lean();
    if (!user) {
      console.error(`[ERROR] /nli: User not found: ${userId}`);
      return sendErrorResponse(400, 'User not found');
    }
  } catch (err) {
    console.error('[ERROR] /nli: Error fetching user:', err);
    return sendErrorResponse(500, 'Error fetching user data');
  }
  
  // Initialize SSE response
  initSSE();
  
  // Add a heartbeat to keep the connection alive
  const heartbeat = setInterval(() => {
    if (res.writable && !res.writableEnded) {
      res.write(':heartbeat\n\n');
    }
  }, 30000);
  
  // Cleanup function
  const cleanup = () => {
    clearInterval(heartbeat);
    if (res.writable && !res.writableEnded) {
      res.end();
    }
  };
  
  // Handle client disconnect
  req.on('close', () => {
    console.log('[NLI] Client disconnected, cleaning up...');
    cleanup();
  });

  let classification;
  try {
    classification = await openaiClassifyPrompt(prompt, userId);
  } catch (err) {
    console.error('Classification error', err);
    classification = 'task';
  }

  if (classification === 'task') {
    // fetch user for email
    const userDoc = await User.findById(userId).lean();
    const userEmail = userDoc?.email;
    // persist user in chat history
    let chatHistory = await ChatHistory.findOne({ userId }) || new ChatHistory({ userId, messages: [] });
    chatHistory.messages.push({ role: 'user', content: prompt, timestamp: new Date() });
    await chatHistory.save();

    const taskId = new mongoose.Types.ObjectId();
    const runId  = uuidv4();
    const runDir = path.join(NEXUS_RUN_DIR, runId);
    fs.mkdirSync(runDir, { recursive: true });

    // … save Task + push to User.activeTasks …
    await new Task({ _id: taskId, userId, command: prompt, status: 'pending', progress: 0, startTime: new Date(), runId }).save();
    await User.updateOne({ _id: userId }, { $push: { activeTasks: { _id: taskId.toString(), command: prompt, status: 'pending', startTime: new Date() } } });

    sendWebSocketUpdate(userId, { event: 'taskStart', payload: { taskId: taskId.toString(), command: prompt, startTime: new Date() } });
    
    // CRITICAL FIX: Always provide a valid default URL for tasks initiated through NLI route
    // This ensures thought bubbles are handled correctly as with direct task execution
    const defaultUrl = "https://www.google.com";
    processTask(userId, userEmail, taskId.toString(), runId, runDir, prompt, defaultUrl, null);
    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    res.flushHeaders();
    res.write('data: ' + JSON.stringify({ event: 'taskStart', payload: { taskId: taskId.toString(), command: prompt, startTime: new Date() } }) + '\n\n');
    // Set up cleanup and timeout handlers
    let interval;
    const cleanup = () => {
      if (interval) clearInterval(interval);
      if (timeout) clearTimeout(timeout);
      if (!res.writableEnded) {
        try {
          res.end();
        } catch (e) {
          console.error('Error ending response:', e);
        }
      }
    };

    // Set a 15-minute timeout for the entire operation
    const timeout = setTimeout(() => {
      console.error(`Task ${taskId} timed out after 15 minutes`);
      if (res.writable) {
        res.write('data: ' + JSON.stringify({
          event: 'error',
          taskId: taskId.toString(),
          error: 'Operation timed out after 15 minutes'
        }) + '\n\n');
      }
      cleanup();
    }, 15 * 60 * 1000);

    // Handle client disconnect
    req.on('close', cleanup);
    req.on('error', cleanup);

    // Poll for task updates
    interval = setInterval(async () => {
      try {
        const task = await Task.findById(taskId).lean();
        if (!task) {
          console.error(`Task ${taskId} not found`);
          res.write('data: ' + JSON.stringify({
            event: 'taskError',
            taskId: taskId.toString(),
            error: 'Task not found'
          }) + '\n\n');
          return cleanup();
        }

        const done = ['completed', 'error'].includes(task.status);
        const evtName = done ? 'taskComplete' : 'stepProgress';
        const payload = {
          taskId: taskId.toString(),
          progress: task.progress,
          result: task.result,
          error: task.error,
          status: task.status
        };

        if (res.writable) {
          res.write('data: ' + JSON.stringify({
            event: evtName,
            ...payload
          }) + '\n\n');
          // @ts-ignore
          if (res.flush) res.flush();
        }

        if (done) {
          clearTimeout(timeout);
          cleanup();
        }
      } catch (err) {
        console.error('Task polling error:', err);
        if (res.writable) {
          res.write('data: ' + JSON.stringify({
            event: 'error',
            taskId: taskId.toString(),
            error: 'Error checking task status: ' + (err.message || 'Unknown error')
          }) + '\n\n');
        }
        cleanup();
      }
    }, 2000);
  } else {
    // Set up chat streaming with proper cleanup
    const controller = new AbortController();
    const { signal } = controller;

    // Set a 5-minute timeout for the entire operation
    const timeout = setTimeout(() => {
      console.error(`Chat stream for user ${userId} timed out after 5 minutes`);
      controller.abort('Operation timed out after 15 minutes');
    }, 15 * 60 * 1000);

    const cleanup = () => {
      clearTimeout(timeout);
      if (!res.writableEnded) {
        try {
          res.end();
        } catch (e) {
          console.error('Error ending response:', e);
        }
      }
    };

    // Handle client disconnect
    req.on('close', () => {
      console.log(`Client disconnected during chat stream for user ${userId}`);
      controller.abort('Client disconnected');
      cleanup();
    });

    req.on('error', (err) => {
      console.error('Request error during chat stream:', err);
      controller.abort('Request error: ' + err.message);
      cleanup();
    });

    try {
      // Set headers for SSE
      res.set({
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      });
      res.flushHeaders();

      // Stream the response
      for await (const evt of streamNliThoughts(userId, prompt, { signal })) {
        if (!res.writable) break;
        
        const message = 'data: ' + JSON.stringify(evt) + '\n\n';
        res.write(message);
        // @ts-ignore
        if (res.flush) res.flush();
      }

      // Send completion event if stream ends normally
      if (res.writable) {
        res.write('data: ' + JSON.stringify({
          event: 'complete',
          content: 'Stream completed successfully'
        }) + '\n\n');
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log(`Chat stream aborted for user ${userId}:`, error.message);
      } else {
        console.error('Error in chat stream:', error);
        if (res.writable) {
          res.write('data: ' + JSON.stringify({
            event: 'error',
            content: 'Error generating response: ' + (error.message || 'Unknown error')
          }) + '\n\n');
        }
      }
    } finally {
      cleanup();
    }
    res.end();
  }
});

// ======================================
// 3. STATIC ASSETS (served last, after all API routes)
// ======================================

// Special handling for model files in development
if (NODE_ENV !== 'production') {
  // In development, only serve backend assets
  const devModelsPath = path.join(__dirname, 'src', 'models');
  if (fs.existsSync(devModelsPath)) {
    app.use('/models', express.static(devModelsPath, {
      setHeaders: setStaticFileHeaders,
      index: false,
      fallthrough: false,
      dotfiles: 'ignore'
    }));
    logger.info(`Serving development models from ${devModelsPath}`);
  }
  
  // In development, don't serve static frontend files - let Vite handle them
  console.log('[Dev] Running in development mode - Vite will serve frontend assets');
} else {
  // In production, serve static files from dist and public
  app.use(express.static(path.join(__dirname, 'dist'), {
    index: false,
    setHeaders: setStaticFileHeaders
  }));
  
  app.use(express.static(path.join(__dirname, 'public'), {
    index: false,
    setHeaders: setStaticFileHeaders
  }));
}

// ======================================
// 4. APPLICATION ROUTES (HTML routes)
// ======================================

// Serve index.html for root route with authentication check
app.get('/', (req, res) => {
  // In development, if we're in a container with Vite running on port 3000
  if (process.env.NODE_ENV === 'development' && process.env.DOCKER === 'true') {
    // In container, Vite is on the same host but different port
    console.log('[Docker Dev] Redirecting to Vite dev server for root route');
    return res.redirect('http://localhost:3000');
  }
  
  // In production, serve index.html from dist
  res.sendFile(path.join(__dirname, 'dist', 'index.html'), {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    }
  });
});

// Serve old.html without authentication
app.get('/old.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'old.html'), {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    }
  });
});

// Support legacy /logout path
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Logout error:', err);
    res.redirect('/login.html');
  });
});

// Serve other HTML pages with authentication
const pages = ['history', 'guide', 'settings'];
pages.forEach(page => {
  app.get(`/${page}.html`, (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', `${page}.html`));
  });
});

// Favicon
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/assets/images/dail-fav.png'));
});


// 2. STATIC FILES (must come before authentication)
// =================================================
// In development, we don't serve static files from the backend
// as they are handled by Vite dev server on port 3000
if (process.env.NODE_ENV !== 'development') {
  // Serve static files from dist in production
  app.use(express.static(path.join(__dirname, 'dist'), {
    setHeaders: (res, path) => {
      // Set CORS headers for all static files
      res.setHeader('Access-Control-Allow-Origin', '*');
      
      // Set proper content type based on file extension
      const ext = path.split('.').pop().toLowerCase();
      if (ext === 'css') {
        res.setHeader('Content-Type', 'text/css');
      } else if (ext === 'js') {
        res.setHeader('Content-Type', 'application/javascript');
      } else if (['png', 'jpg', 'jpeg', 'gif', 'svg'].includes(ext)) {
        res.setHeader('Content-Type', `image/${ext === 'jpg' ? 'jpeg' : ext}`);
      }
    }
  }));
  
  // Serve webfonts from public/webfonts with correct MIME types
  app.use('/webfonts', express.static(path.join(__dirname, 'public', 'webfonts'), {
    setHeaders: (res, filePath) => {
      // Set appropriate content type based on file extension
      const ext = path.extname(filePath).toLowerCase().substring(1);
      if (ext === 'woff2') {
        res.setHeader('Content-Type', 'font/woff2');
      } else if (ext === 'woff') {
        res.setHeader('Content-Type', 'font/woff');
      } else if (ext === 'ttf') {
        res.setHeader('Content-Type', 'font/ttf');
      } else if (ext === 'eot') {
        res.setHeader('Content-Type', 'application/vnd.ms-fontobject');
      } else if (ext === 'svg') {
        res.setHeader('Content-Type', 'image/svg+xml');
      }
      // Add caching headers
      res.setHeader('Cache-Control', 'public, max-age=31536000');
    }
  }));

  // Serve public directory for other static assets with proper MIME types
  app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
      // Set proper content type based on file extension
      const ext = path.extname(filePath).toLowerCase();
      if (ext === '.svg') {
        res.setHeader('Content-Type', 'image/svg+xml');
      } else if (ext === '.css') {
        res.setHeader('Content-Type', 'text/css');
      } else if (ext === '.js') {
        res.setHeader('Content-Type', 'application/javascript');
      } else if (['.png', '.jpg', '.jpeg', '.gif'].includes(ext)) {
        res.setHeader('Content-Type', `image/${ext.slice(1)}`);
      } else if (ext === '.ico') {
        res.setHeader('Content-Type', 'image/x-icon');
      }
    }
  }));
  
  // Serve CSS files from dist/css and its subdirectories
  app.use('/css', express.static(path.join(__dirname, 'dist', 'css'), {
    setHeaders: (res, filePath) => {
      // Only set Content-Type for CSS files
      if (filePath.endsWith('.css')) {
        res.setHeader('Content-Type', 'text/css');
      } else if (filePath.endsWith('.svg')) {
        res.setHeader('Content-Type', 'image/svg+xml');
      }
    },
    // Enable directory listing to serve files from subdirectories
    index: false,
    redirect: false
  }));
  
  // Serve static files from dist directory with proper MIME types
  app.use(express.static(path.join(__dirname, 'dist'), {
    setHeaders: (res, filePath) => {
      // Set proper content type based on file extension
      const ext = path.extname(filePath).toLowerCase();
      if (ext === '.css') {
        res.setHeader('Content-Type', 'text/css');
      } else if (ext === '.svg') {
        res.setHeader('Content-Type', 'image/svg+xml');
      } else if (ext === '.js') {
        res.setHeader('Content-Type', 'application/javascript');
      } else if (['.png', '.jpg', '.jpeg', '.gif'].includes(ext)) {
        res.setHeader('Content-Type', `image/${ext.slice(1)}`);
      } else if (ext === '.ico') {
        res.setHeader('Content-Type', 'image/x-icon');
      }
    }
  }));
  
  console.log('Serving static files from:', path.join(__dirname, 'dist'));
}

// ======================================
// 8.4 REPORT SERVING MIDDLEWARE
// ======================================
// Set up report serving and redirector middleware
// This must be after static file serving to ensure proper routing
reportHandlers.setupReportServing(app);
reportHandlers.setupReportRedirector(app);
console.log('Report serving middleware initialized');

// Serve nexus_run directory with proper caching
app.use('/nexus_run', express.static(NEXUS_RUN_DIR, {
  setHeaders: (res, path) => {
    // Ensure proper caching for static files
    res.setHeader('Cache-Control', 'public, max-age=31536000');
  }
}));

// Legacy redirect for midscene_run -> nexus_run
app.use('/midscene_run', (req, res) => {
  const subPath = req.path;
  const newPath = `/nexus_run${subPath}`;
  res.redirect(301, newPath);
});


// =====================================================
// 3. 404 & SPA Catch All HANDLERS 
// ====================================================
// 404 handler for API routes (must come after all other routes but before error handlers)
// API 404 handler - will be moved to the end of the file
const api404Handler = (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
};

// SPA Catch-All Route - will be moved to the end of the file
const spaCatchAll = (req, res, next) => {
  // Skip API routes and files with extensions
  if (req.path.startsWith('/api/') || req.path.match(/\.[a-z0-9]+$/i)) {
    return next();
  }
  
  // In containerized development, redirect to Vite dev server for frontend routes
  if (process.env.NODE_ENV === 'development' && process.env.DOCKER === 'true') {
    const viteUrl = `http://localhost:3000${req.path}`;
    console.log(`[Docker Dev] Redirecting to Vite dev server: ${viteUrl}`);
    return res.redirect(viteUrl);
  }
  
  // In production, serve index.html from dist
  res.sendFile(path.join(__dirname, 'dist', 'index.html'), {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Content-Type-Options': 'nosniff'
    }
  });
};

// 404 handler - will be moved to the end of the file
const html404Handler = (req, res) => {
  // In development, let the frontend handle 404s
  if (process.env.NODE_ENV === 'development' && process.env.DOCKER === 'true') {
    return res.redirect(`http://localhost:3000${req.path}`);
  }
  
  if (req.accepts('html')) {
    const errorPage = path.join(__dirname, 'dist', '404.html');
    if (fs.existsSync(errorPage)) {
      return res.status(404).sendFile(errorPage);
    }
    return res.status(404).send('Page not found');
  } else if (req.accepts('json')) {
    return res.status(404).json({ error: 'Not Found' });
  } else {
    return res.status(404).type('txt').send('Not Found');
  }
};

// Error handler 1 - will be moved to the end of the file
const errorHandler1 = (err, req, res, next) => {
  // If headers have already been sent, delegate to the default Express error handler
  if (res.headersSent) {
    return next(err);
  }
  
  logger.error(`Unhandled error: ${err.stack}`);
  
  // Set the response status code
  const statusCode = err.statusCode || 500;
  
  // Send JSON response
  res.status(statusCode).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

// Error handler 2 - will be moved to the end of the file
const errorHandler2 = (err, req, res, next) => {
  // If headers have already been sent, delegate to the default Express error handler
  if (res.headersSent) {
    return next(err);
  }

  const errorId = uuidv4();
  const errorDetails = {
    id: errorId,
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  };
  
  // Log the error with context
  logger.error(`[${errorId}] ${err.message}`, {
    error: err.stack,
    ...errorDetails
  });
  
  // Don't leak stack traces in production
  const errorResponse = process.env.NODE_ENV === 'production' 
    ? { 
        error: 'Internal Server Error',
        message: 'An unexpected error occurred',
        errorId
      }
    : {
        error: err.name,
        message: err.message,
        stack: err.stack,
        ...errorDetails
      };
  
  res.status(err.status || 500).json(errorResponse);
};

// ======================================
// 10.1 ANDROID DEVICE ENDPOINTS
// ======================================
// In server.js, add these routes after your other API routes
app.get('/api/user/settings/adb', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('adbSettings');
    res.json(user.adbSettings || {});
  } catch (error) {
    console.error('Error fetching ADB settings:', error);
    res.status(500).json({ message: 'Error fetching ADB settings' });
  }
});

app.post('/api/user/settings/adb', requireAuth, async (req, res) => {
  try {
    const { remoteAdbHost, remoteAdbPort, customAdbPath, networkSettings } = req.body;
    
    const update = {
      'adbSettings.remoteAdbHost': remoteAdbHost,
      'adbSettings.remoteAdbPort': remoteAdbPort,
      'adbSettings.customAdbPath': customAdbPath,
      'adbSettings.networkSettings': networkSettings,
      updatedAt: Date.now()
    };

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: update },
      { new: true }
    ).select('adbSettings');

    res.json(user.adbSettings);
  } catch (error) {
    console.error('Error saving ADB settings:', error);
    res.status(500).json({ message: 'Error saving ADB settings' });
  }
});

// ======================================
// 10.1 ANDROID DEVICE ENDPOINTS
// ======================================

/**
 * @api {get} /api/android/status Get Android device status
 * @apiName GetAndroidStatus
 * @apiGroup Android
 * @apiDescription Get the status of ADB and connected Android devices
 * 
 * @apiSuccess {Boolean} installed Whether ADB is installed and accessible
 * @apiSuccess {String} version ADB version information
 * @apiSuccess {Object[]} devices List of connected Android devices
 * @apiSuccess {String} devices.id Device ID/UDID
 * @apiSuccess {String} devices.name Display name of the device
 * @apiSuccess {String} devices.state Connection state of the device
 * @apiSuccess {String} [error] Error message if any
 */
app.get('/api/android/status', async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Content-Type', 'application/json');

  try {
    console.log('Fetching Android device status...');
    const status = await androidControl.checkAdbStatus();
    console.log('Android status:', JSON.stringify(status, null, 2));
    
    const response = {
      installed: status.installed || false,
      version: status.version || null,
      devices: Array.isArray(status.devices) ? status.devices : [],
      status: 'success',
      timestamp: new Date().toISOString()
    };
    
    res.json(response);
  } catch (error) {
    console.error('Error getting Android status:', error);
    res.status(500).json({
      installed: false,
      version: null,
      devices: [],
      error: error.message || 'Failed to get Android status',
      status: 'error',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @api {post} /api/android/connect Connect to an Android device
 * @apiName ConnectAndroidDevice
 * @apiGroup Android
 * @apiDescription Connect to a specific Android device by ID
 * 
 * @apiBody {String} deviceId The ID/UDID of the device to connect to
 * 
 * @apiSuccess {Boolean} success Whether the connection was successful
 * @apiSuccess {String} message Status message
 * @apiSuccess {Object} [device] Connected device information
 */
app.post('/api/android/connect', express.json(), async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Content-Type', 'application/json');
  
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { deviceId } = req.body;
  
  if (!deviceId) {
    return res.status(400).json({
      success: false,
      message: 'Device ID is required',
      status: 'error',
      timestamp: new Date().toISOString()
    });
  }

  try {
    console.log(`Attempting to connect to device: ${deviceId}`);
    await androidControl.connect(deviceId);
    const status = await androidControl.checkAdbStatus();
    
    // Find the connected device in the status
    const device = Array.isArray(status.devices) 
      ? status.devices.find(d => d.id === deviceId) 
      : null;
    
    console.log(`Successfully connected to device: ${deviceId}`, device);
    
    res.json({
      success: true,
      message: `Connected to device ${deviceId}`,
      device: device || { id: deviceId, name: `Android Device (${deviceId})` },
      status: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error connecting to Android device:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to connect to device',
      device: null,
      status: 'error',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @api {post} /api/android/disconnect Disconnect from Android device
 * @apiName DisconnectAndroidDevice
 * @apiGroup Android
 * @apiDescription Disconnect from the currently connected Android device
 * 
 * @apiSuccess {Boolean} success Whether the disconnection was successful
 * @apiSuccess {String} message Status message
 */
app.post('/api/android/disconnect', async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Content-Type', 'application/json');
  
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    console.log('Disconnecting from Android device...');
    await androidControl.disconnect();
    
    res.json({
      success: true,
      message: 'Disconnected from Android device',
      status: 'disconnected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error disconnecting from Android device:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to disconnect from device'
    });
  }
});

// ======================================
// 10.a START THE SERVER
// ======================================

// Start the application
  startApp().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });


// ======================================
// 10.b DATABASE MANAGEMENT
// ======================================

/**
 * Clear the database once on startup if needed
 * This is useful for development and testing
 */
async function clearDatabaseOnce() {
  try {
    // Check if we should clear the database
    if (process.env.CLEAR_DB_ON_START === 'true') {
      console.log('Clearing database...');
      await Promise.all([
        User.deleteMany({}),
        Message.deleteMany({}),
        Task.deleteMany({}),
        ChatHistory.deleteMany({}),
        Billing.deleteMany({})
      ]);
      console.log('✅ Database cleared');
    }
  } catch (error) {
    console.error('Error clearing database:', error);
    // Don't fail startup if clearing fails
  }
}

// ======================================
// 11.a. BROWSER SESSION MANAGEMENT
// ======================================
// Initialize browser cluster
import { initBrowserCluster, closeBrowserCluster, executeWithBrowser } from './src/utils/browserCluster.js';

// Initialize cluster on startup
initBrowserCluster().then(() => {
  console.log('Browser cluster initialized');
});

// Clean up cluster on process termination
process.on('SIGTERM', async () => {
  console.log('SIGTERM received - cleaning up browser cluster');
  await closeBrowserCluster();
});

process.on('SIGINT', async () => {
  console.log('SIGINT received - cleaning up browser cluster');
  await closeBrowserCluster();
  process.exit(0);
});

/**
 * Execute a task with browser cluster
 * @param {string} taskId - Task ID
 * @param {string} userId - User ID
 * @param {Function} taskFn - Task function to execute
 * @returns {Promise<any>} Result of the task
 */
async function executeWithBrowserCluster(taskId, userId, taskFn) {
  return await executeWithBrowser(taskId, userId, taskFn);
}

const HEARTBEAT_INTERVAL = 3 * 60 * 1000; // 3m
const MAX_INACTIVE = 30 * 60 * 1000;      // 30m
const MAX_HEAP = 500 * 1024 * 1024;       // 500 MB

export const browserSessionHeartbeat = setInterval(() => {
  logger.debug(`Heartbeat: pruning ${TaskPlan.livePlans.size} live plans`);
  const now = Date.now();
  const STALE = 30 * 60 * 1000;

  for (const plan of TaskPlan.livePlans) {
    if (plan.completed || (now - (plan.lastActivity||now)) > STALE) {
      TaskPlan.livePlans.delete(plan);
      logger.debug(
        `Heartbeat: pruned plan ${plan.taskId}` +
        (plan.completed ? " (completed)" : " (stale)")
      );
    }
  }
}, 3 * 60 * 1000);

// ======================================
// 12. CLEANUP AND SHUTDOWN HANDLERS
// ======================================
async function cleanupResources() {
  try {
    logger.info('Starting cleanup of resources...');
    await closeBrowserCluster();

    // — WebSocket server
    if (global.wss || wss) {
      const wsServer = global.wss || wss;
      logger.info('Closing WebSocket server...');
      try {
        wsServer.clients.forEach((client) => {
          if (client.readyState === WebSocket.OPEN) {
            client.terminate();
          }
        });
        await new Promise((resolve) => {
          wsServer.close(() => {
            logger.info('WebSocket server closed');
            resolve();
          });
        });
      } catch (error) {
        logger.error('Error during WebSocket server cleanup:', error);
      }
    }

    // — MongoDB
    if (mongoose.connection?.readyState === 1) {
      logger.info('Closing MongoDB connection...');
      await mongoose.connection.close();
      logger.info('MongoDB connection closed');
    }

    // — Heartbeat
    if (browserSessionHeartbeat) {
      logger.info('Clearing browser session heartbeat...');
      clearInterval(browserSessionHeartbeat);
    }

    logger.info('Cleanup completed successfully');
  } catch (error) {
    logger.error('Error during cleanup:', error);
    // swallow to allow shutdown
  }
}

// Handle graceful shutdown
async function handleShutdown(signal) {
  logger.info(`\n${signal} received - shutting down gracefully...`);
  
  try {
    // Start cleanup with a timeout
    const cleanupPromise = cleanupResources();
    const timeoutPromise = new Promise(resolve => setTimeout(resolve, 10000)); // 10s timeout
    
    await Promise.race([cleanupPromise, timeoutPromise]);
    logger.info('Graceful shutdown completed');
  } catch (error) {
    logger.error('Error during shutdown:', error);
  } finally {
    process.exit(0);
  }
}

// Register signal handlers
process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

// Global error handlers
process.on('unhandledRejection', (reason, promise) => {
  if (reason && reason.message && reason.message.includes('Request is already handled')) {
    logger.debug('[Puppeteer] Ignoring known issue: Request is already handled');
  } else {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  }
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  // Attempt cleanup before exiting
  cleanupResources()
    .then(() => process.exit(1))
    .catch(() => process.exit(1));
});

// 12. HELPER FUNCTIONS
// ======================================

/**
 * Sleep for a specified number of milliseconds
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Validates and normalizes a URL, with fallback to Google if invalid
 * @param {string} url - The URL to validate
 * @returns {string} - The validated URL or fallback to Google
 */
function validateAndNormalizeUrl(url) {
  if (!url) return 'https://www.google.com';
  
  // Trim whitespace and remove quotes if present
  url = url.trim().replace(/^["']|["']$/g, '');
  
  // If it's just a domain or search term, prepend https://
  if (!/^https?:\/\//i.test(url)) {
    // If it looks like a domain (contains a dot but no spaces)
    if (url.includes('.') && !url.includes(' ')) {
      url = `https://${url}`;
    } else {
      // Treat as a search query
      const encodedQuery = encodeURIComponent(url);
      return `https://www.google.com/search?q=${encodedQuery}`;
    }
  }
  
  // Basic URL validation
  try {
    const urlObj = new URL(url);
    // Ensure protocol is http or https
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return 'https://www.google.com';
    }
    return urlObj.toString();
  } catch (e) {
    // If URL parsing fails, fall back to Google search
    const encodedQuery = encodeURIComponent(url);
    return `https://www.google.com/search?q=${encodedQuery}`;
  }
}

/**
 * Shared function for saving task completion messages consistently
 * This ensures that all task completions use the same format and logic
 * regardless of how they were triggered (natural completion or forced)
 */
async function saveTaskCompletionMessages(userId, taskId, prompt, contentText, aiSummary, meta = {}) {
  try {
    console.log(`[Task ${taskId}] Saving task completion messages with consistent formatting`);
    
    // CRITICAL CHANGE: Prioritize aiSummary for the message content when available
    // This ensures we're always using the richest possible summary
    let completeMessage = aiSummary || contentText;
    
    // Add report URLs if available
    let reportInfo = [];
    if (meta.nexusReportUrl) reportInfo.push(`Analysis Report: ${meta.nexusReportUrl}`);
    if (meta.landingReportUrl) reportInfo.push(`Landing Page Report: ${meta.landingReportUrl}`);
    
    // Only append report URLs if they're not already included in the summary
    if (reportInfo.length > 0 && !completeMessage.includes('Task Reports Available')) {
      completeMessage += '\n\nTask Reports Available:\n- ' + reportInfo.join('\n- ');
    }
    
    // Add task prompt if not already included in the summary
    if (!completeMessage.toLowerCase().includes(prompt.toLowerCase().substring(0, 20))) {
      completeMessage = `Task: "${prompt}"\n\n${completeMessage}`;
    }
    
    console.log(`[Task ${taskId}] Using rich AI summary for task completion: ${completeMessage.substring(0, 100)}...`);
    
    // Save to ChatHistory
    let taskChatHistory = await ChatHistory.findOne({ userId });
    if (!taskChatHistory) taskChatHistory = new ChatHistory({ userId, messages: [] });
    
    taskChatHistory.messages.push({
      role: 'assistant',
      content: completeMessage,
      timestamp: new Date(),
      meta: {
        taskId,
        type: 'command'
      }
    });
    
    await taskChatHistory.save();
    console.log(`[Task ${taskId}] Updated ChatHistory with rich AI summary`);
    
    // Save to Message collection with full metadata
    await Message.create({
      userId,
      role: 'assistant',
      type: 'command',
      content: completeMessage,
      taskId,
      timestamp: new Date(),
      meta: {
        // Always include the AI summary for future reference
        summary: aiSummary || completeMessage,
        // Include all the metadata passed in
        ...meta
      }
    });
    
    console.log(`[Task ${taskId}] Saved consistent task completion message with rich AI summary and reports`);
    return true;
  } catch (error) {
    console.error(`[Task ${taskId}] Error saving task completion messages:`, error);
    return false;
  }
}

// --- WebSocket helper functions ---
async function sendWebSocketUpdate(userId, data) {
  // Always allow error messages and task updates through
  const isError = data.type === 'error' || data.status === 'error' || data.status === 'failed';
  const isTaskUpdate = data.type === 'task' || data.taskId;
  
  // Skip non-event data unless it's an error or task update
  if (!data.event && !isError && !isTaskUpdate) {
    console.debug('[WebSocket] Skipped non-event data over WS:', data);
    return;
  }
  
  // Ensure error messages have a consistent format
  if (isError) {
    data = {
      ...data,
      type: 'error',
      timestamp: data.timestamp || new Date().toISOString()
    };
  }

  const connections = userConnections.get(userId);
  const connectionCount = connections ? connections.size : 0;
  /*
  console.log(`[WebSocket] Sending update to userId=${userId}`, {
    event: data.event,
    connectionCount,
    hasConnections: connectionCount > 0,
    timestamp: new Date().toISOString()
  });
  */

  if (connections && connections.size > 0) {
    let successfulSends = 0;
    let failedSends = 0;
    let closedConnections = 0;

    connections.forEach((ws, index) => {
      const connectionInfo = {
        connectionIndex: index,
        readyState: ws.readyState,
        isOpen: ws.readyState === WebSocket.OPEN, // Use WebSocket.OPEN constant
        connectionDuration: ws.connectedAt ? `${(new Date() - ws.connectedAt) / 1000}s` : 'unknown'
      };

      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify(data));
          successfulSends++;
          /*
          console.debug(`[WebSocket] Successfully sent to userId=${userId}`, {
            ...connectionInfo,
            eventType: data.event,
            dataSize: JSON.stringify(data).length
          });
          */
        } catch (error) {
          failedSends++;
          console.error(`[WebSocket] Failed to send to userId=${userId}`, {
            ...connectionInfo,
            error: error.toString(),
            stack: error.stack
          });
        }
      } else {
        closedConnections++;
        console.warn(`[WebSocket] Skipping closed connection for userId=${userId}`, connectionInfo);
      }
    });
    /*
    console.log(`[WebSocket] Send summary for userId=${userId}`, {
      totalConnections: connections.size,
      successfulSends,
      failedSends,
      closedConnections,
      timestamp: new Date().toISOString()
    });
    */
  } else {
    console.log(`[WebSocket] No active connections for userId=${userId}. Queuing message.`);
    if (!unsentMessages.has(userId)) {
      unsentMessages.set(userId, []);
      console.log(`[WebSocket] Created new message queue for userId=${userId}`);
    }
    
    const queue = unsentMessages.get(userId);
    
    // Don't queue duplicate error messages for the same task
    if (isError && data.taskId) {
      const existingErrorIndex = queue.findIndex(
        msg => msg.type === 'error' && msg.taskId === data.taskId
      );
      
      if (existingErrorIndex !== -1) {
        // Replace existing error for this task
        queue[existingErrorIndex] = data;
      } else {
        queue.push(data);
      }
    } else {
      queue.push(data);
    }
    
    console.log(`[WebSocket] Queued message for userId=${userId}`, {
      queueSize: queue.length,
      type: data.type || 'unknown',
      event: data.event,
      taskId: data.taskId || 'none',
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Streamlined content processor that only keeps essential information for database storage.
 * Removes images, large content, and unnecessary data to optimize database usage.
 * @param {Object} obj - Object to inspect
 * @returns {Object} - Object with only essential information preserved
 */
function handleLargeContent(obj) {
  // If not an object or null, return as is
  if (!obj || typeof obj !== 'object') return obj;
  
  // For arrays, process each item but limit size
  if (Array.isArray(obj)) {
    // Hard limit of 50 items per array to save space
    if (obj.length > 50) {
      // Don't log this for silent operation
      return obj.slice(0, 50).map(item => handleLargeContent(item));
    }
    return obj.map(item => handleLargeContent(item));
  }
  
  // For objects, process each property with strict filtering
  const result = {};
  
  // CRITICAL: Always preserve report URLs if they exist
  const reportUrlKeys = ['nexusReportUrl', 'landingReportUrl', 'reportUrl', 'runReport', 'screenshotPath'];
  for (const urlKey of reportUrlKeys) {
    if (obj[urlKey] !== undefined) {
      // Directly copy URL values without processing
      result[urlKey] = obj[urlKey];
    }
  }
  
  for (const [key, value] of Object.entries(obj)) {
    // Skip storing these entirely - never needed in DB
    // Only skip screenshot and other large fields, but ALLOW screenshotPath (URL to saved screenshot)
    if (['pageContext', 'rawPageHtml', 'html', 'rawHtml', 
         'dom', 'tree', 'base64', 'image', 'images'].includes(key)) {
      continue; // Skip this field completely
    }
    
    // Special handling for screenshot - we want to keep the URL if it's a string path
    // but remove if it's base64 data
    if (key === 'screenshot') {
      // If it's a string URL/path, keep it. If base64 or null, skip it entirely
      if (typeof value === 'string' && !value.startsWith('data:')) {
        result[key] = value; // Keep screenshot URLs/paths
      } else {
        continue; // Skip base64 screenshots or null values
      }
    }
    
    // Very aggressive limiting for large content fields - always null out full page content
    // This saves significant DB space by not storing any extracted page content at all
    if (['extractedInfo', 'rawPageText', 'pageContent', 'pageText'].includes(key)) {
      // Don't store any page content in the database at all
      result[key] = null;
      // If we need to keep metadata about the extraction, store that instead
      if (typeof value === 'object' && value !== null) {
        // If it has properties like timestamp or metadata, just keep those
        const { timestamp, url, success, metadata } = value;
        if (timestamp) result.timestamp = timestamp;
        if (url) result.url = url;
        if (success !== undefined) result.success = success;
        if (metadata) result.metadata = handleLargeContent(metadata);
      }
    }
    // Remove all base64 images completely
    else if (typeof value === 'string' && value.startsWith('data:image')) {
      // Skip entirely - don't even store a placeholder
      continue;
    }
    // Hard limit on all string fields
    else if (typeof value === 'string' && value.length > 10000) {
      result[key] = value.substring(0, 10000);
    }
    // Process nested objects
    else if (typeof value === 'object' && value !== null) {
      // Process the object
      const processed = handleLargeContent(value);
      
      // For result objects, double-check that we preserved report URLs
      if (key === 'result') {
        // Ensure report URLs in the result object are preserved
        for (const urlKey of ['nexusReportUrl', 'landingReportUrl', 'reportUrl', 'runReport', 'screenshotPath']) {
          if (value[urlKey] !== undefined && processed[urlKey] === undefined) {
            // URL was lost during processing, restore it
            processed[urlKey] = value[urlKey];
            console.log(`[URL Preservation] Restored ${urlKey} in nested result object: ${value[urlKey]}`); 
          }
        }
      }
      
      result[key] = processed;
    }
    // Keep essential values as is
    else {
      result[key] = value;
    }
  }
  return result;
}

// Track tasks that have already been completed to prevent double-completion
const completedTasks = new Set();

// Track free tier usage (users without API keys)
const freeTierUsage = new Map(); // userId -> { count: number, lastReset: Date }
const MAX_FREE_PROMPTS = 3; // Maximum number of free prompts per user
const FREE_TIER_RESET_HOURS = 24; // Reset counter after 24 hours

/**
 * Update task in database and notify clients with optimized storage.
 * Saves images to filesystem instead of database and retains only essential data.
 * @param {string} taskId - Task ID
 * @param {Object} updates - Updates to apply
 */
async function updateTaskInDatabase(taskId, updates) {
  if (typeof updates !== 'object' || updates === null) {
    console.error(`[Database] Invalid updates parameter: expected an object, received ${typeof updates}`);
    return;
  }
  
  // Guard against overwriting report URLs in completed tasks
  if (updates.status === 'completed') {
    // If this task was already marked as completed, check if we should proceed
    if (completedTasks.has(taskId)) {
      // Only allow updates that include report URLs
      if (!updates.result || 
          (!updates.result.nexusReportUrl && !updates.result.landingReportUrl && !updates.result.reportUrl)) {
        console.log(`[TaskCompletion] Preventing second completion of task ${taskId} without report URLs`);
        return; // Skip this update to protect existing URLs
      }
    } else {
      // Mark this task as completed to prevent future overwrites
      completedTasks.add(taskId);
      
      // Get the full task to include original command in the completion event
      try {
        const task = await Task.findById(taskId).lean();
        if (task && task.prompt) {
          updates.result = updates.result || {};
          updates.result.originalCommand = task.prompt;
          console.log(`[TaskCompletion] Added original command to completion event for task ${taskId}`);
        }
      } catch (err) {
        console.error(`[TaskCompletion] Error fetching task for completion:`, err);
      }
    }
  }
  
  // Create a copy to avoid modifying the original
  const sizeLimitedUpdates = {...updates};
  
  // Process and optimize task data for storage
  console.log(`[TaskCompletion] Applying database size limits to task result...`);
  
  // Helper function to save any image to filesystem
  const saveImageToFile = async (imageData, prefix = 'img') => {
    if (!imageData || typeof imageData !== 'string' || !imageData.startsWith('data:image')) {
      return null;
    }
    
    try {
      // Extract the base64 data
      const base64Data = imageData.replace(/^data:image\/(png|jpeg|jpg);base64,/, '');
      // Create a unique filename
      const filename = `${prefix}-${Date.now()}-${Math.floor(Math.random() * 10000)}.jpg`;
      const filePath = path.join(process.cwd(), 'nexus_run', taskId, filename);
      // Ensure directory exists
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      // Write the file
      fs.writeFileSync(filePath, Buffer.from(base64Data, 'base64'));
      // Return the URL path
      return `/nexus_run/${taskId}/${filename}`;
    } catch (error) {
      console.error(`[Database] Failed to save image: ${error.message}`);
      return null;
    }
  };

  // Process result object - store only URLs, not images
  if (sizeLimitedUpdates.result) {
    // Main screenshot processing
    if (sizeLimitedUpdates.result.screenshot && typeof sizeLimitedUpdates.result.screenshot === 'string') {
      if (sizeLimitedUpdates.result.screenshot.startsWith('data:image')) {
        // Save image to file and store URL
        const imageUrl = await saveImageToFile(sizeLimitedUpdates.result.screenshot, 'screenshot');
        if (imageUrl) {
          sizeLimitedUpdates.result.screenshotPath = imageUrl;
        }
        // Always remove the base64 data
        delete sizeLimitedUpdates.result.screenshot;
      }
    }
    
    // Preserve only these key URLs that we need
    const keysToKeep = [
      'nexusReportUrl', 'landingReportUrl', 'reportUrl', 'screenshotPath',
      'extractedInfo', 'elementText', 'status', 'error'
    ];
    
    // Create a new result object with only essential data
    const essentialResult = {};
    for (const key of keysToKeep) {
      if (sizeLimitedUpdates.result[key] !== undefined) {
        essentialResult[key] = sizeLimitedUpdates.result[key];
        
        // Further limit text fields
        if (typeof essentialResult[key] === 'string' && essentialResult[key].length > 5000 &&
            key !== 'nexusReportUrl' && key !== 'landingReportUrl' && key !== 'reportUrl' && key !== 'screenshotPath') {
          essentialResult[key] = essentialResult[key].substring(0, 5000);
        }
      }
    }
    
    // Replace the full result with our optimized version
    sizeLimitedUpdates.result = essentialResult;
  }
  
  // Optimize intermediateResults - keep only URLs and essential data
  if (sizeLimitedUpdates.intermediateResults && Array.isArray(sizeLimitedUpdates.intermediateResults)) {
    // Limit to max 50 items
    if (sizeLimitedUpdates.intermediateResults.length > 50) {
      sizeLimitedUpdates.intermediateResults = sizeLimitedUpdates.intermediateResults.slice(0, 50);
    }
    
    // Process each result
    sizeLimitedUpdates.intermediateResults = await Promise.all(
      sizeLimitedUpdates.intermediateResults.map(async (result) => {
        if (!result || typeof result !== 'object') return result;
        
        // Create a simplified version with only essential fields
        const simplified = {};
        
        // Process screenshot/image if present
        if (result.screenshot && typeof result.screenshot === 'string' && 
            result.screenshot.startsWith('data:image')) {
          const imageUrl = await saveImageToFile(result.screenshot, 'step');
          if (imageUrl) {
            simplified.screenshotPath = imageUrl;
          }
        } else if (result.screenshotPath) {
          simplified.screenshotPath = result.screenshotPath;
        }
        
        // Keep only essential text data, limited to reasonable size
        if (result.extractedInfo) {
          simplified.extractedInfo = typeof result.extractedInfo === 'string' 
            ? result.extractedInfo.substring(0, 5000) 
            : result.extractedInfo;
        }
        
        // Copy other essential fields
        ['status', 'error', 'elementText', 'step', 'action'].forEach(key => {
          if (result[key] !== undefined) {
            simplified[key] = result[key];
          }
        });
        
        return simplified;
      })
    );
  }
  
  // Always apply our aggressive content limiter as final step
  sizeLimitedUpdates.result = handleLargeContent(sizeLimitedUpdates.result);
  sizeLimitedUpdates.intermediateResults = handleLargeContent(sizeLimitedUpdates.intermediateResults);
  
  // Ensure all other fields are also optimized
  if (sizeLimitedUpdates.extractedInfo) {
    sizeLimitedUpdates.extractedInfo = handleLargeContent(sizeLimitedUpdates.extractedInfo);
  }
  
  // Remove these entirely - never needed in DB
  ['pageContent', 'rawPageText', 'rawHtml', 'html'].forEach(key => {
    if (sizeLimitedUpdates[key]) {
      delete sizeLimitedUpdates[key];
    }
  });
  
  // Other potentially large fields - simplify aggressively
  if (sizeLimitedUpdates.stepMap) {
    // Just keep the structure but remove large content
    sizeLimitedUpdates.stepMap = handleLargeContent(sizeLimitedUpdates.stepMap);
  }
  
  console.log(`[Database] Updating task ${taskId}:`, Object.keys(sizeLimitedUpdates));
  try {
    // First, check if this is a completion event with report URLs
    const isCompletionWithReports = 
      updates.status === 'completed' && 
      updates.result && 
      (updates.result.nexusReportUrl || updates.result.landingReportUrl || updates.result.reportUrl);
    
    // If this is a completion with reports, log it for debugging
    if (isCompletionWithReports) {
      console.log(`[TaskCompletion] Updating task ${taskId} with report URLs:`, {
        nexusReportUrl: updates.result.nexusReportUrl,
        landingReportUrl: updates.result.landingReportUrl,
        reportUrl: updates.result.reportUrl
      });
    }

    // Update the database FIRST - before sending any events
    const task = await Task.findByIdAndUpdate(taskId, { $set: sizeLimitedUpdates }, { new: true });
    if (!task) {
      console.warn(`[Database] Task ${taskId} not found for update`);
      return;
    }
    
    // After database update, verify the URLs were properly saved
    if (isCompletionWithReports) {
      console.log(`[TaskCompletion] Verified URLs in DB for task ${taskId}:`, {
        nexusReportUrl: task.result?.nexusReportUrl,
        landingReportUrl: task.result?.landingReportUrl,
        reportUrl: task.result?.reportUrl
      });
    }
    
    // For completed tasks with report URLs, ensure we're using the database values in the update
    if (updates.status === 'completed' && task.result) {
      // Create a new updates object that uses database values for report URLs
      const enhancedUpdates = {...updates};
      
      // If the task has report URLs in the database, use those instead
      if (!enhancedUpdates.result) enhancedUpdates.result = {};
      
      // Only replace if the database has values and updates doesn't
      if (task.result.nexusReportUrl && !enhancedUpdates.result.nexusReportUrl) {
        enhancedUpdates.result.nexusReportUrl = task.result.nexusReportUrl;
      }
      if (task.result.landingReportUrl && !enhancedUpdates.result.landingReportUrl) {
        enhancedUpdates.result.landingReportUrl = task.result.landingReportUrl;
      }
      if (task.result.reportUrl && !enhancedUpdates.result.reportUrl) {
        enhancedUpdates.result.reportUrl = task.result.reportUrl;
      }
      
      // Replace the updates with our enhanced version
      updates = enhancedUpdates;
    }

    // Determine the appropriate event based on the update properties
    let eventName;
    if (updates.status === 'pending') eventName = 'taskStart';
    else if (updates.status === 'completed') {
      eventName = 'taskComplete';
      // Ensure we're not losing report URLs in the payload
      if (updates.result) {
        // Log the values to ensure they're being properly passed
        console.log(`[TaskCompletion] Sending task completion event for task ${taskId} with URLs:`, {
          landingReportUrl: updates.result.landingReportUrl,
          nexusReportUrl: updates.result.nexusReportUrl,
          reportUrl: updates.result.reportUrl,
          screenshot: updates.result.screenshot
        });
      }
    }
    else if (updates.status === 'error') eventName = 'taskError';
    else if ('progress' in updates) eventName = 'stepProgress';
    else if ('intermediateResults' in updates) eventName = 'intermediateResult';
    else eventName = 'taskUpdate';
    sendWebSocketUpdate(task.userId.toString(), { event: eventName, payload: { taskId, ...updates } });
  } catch (error) {
    console.error(`[Database] Error updating task:`, error);
  }
}

/**
 * Process task completion and generate reports.
 * @param {string} userId - User ID
 * @param {string} taskId - Task ID
 * @param {Array} intermediateResults - Intermediate results
 * @param {string} originalPrompt - Original user prompt
 * @param {string} runDir - Run directory
 * @param {string} runId - Run ID
 * @param {Object} [taskPlan] - Optional TaskPlan instance for additional context
 * @returns {Object} - Final result
 */

export async function processTaskCompletion(
  userId,
  taskId,
  intermediateResults,
  originalPrompt,
  runDir,
  runId,
  taskPlan
) {
  console.log(`[TaskCompletion] Processing completion for task ${taskId}`);
  try {
    let finalScreenshot = null;
    let agent = null;

    // 1) Retrieve session (first from taskPlan, then fallback to map)
    const session =
      taskPlan?.browserSession;

    if (session) {
      // 2) Take final screenshot if possible
      if (session.page && !session.page.isClosed()) {
        try {
          finalScreenshot = await session.page.screenshot({ encoding: 'base64' });
        } catch (error) {
          console.warn(`[TaskCompletion] Failed to take final screenshot: ${error.message}`);
        }
      }
      // 3) Grab midscene agent
      agent = session.agent;
      console.log(`[TaskCompletion] Agent found, reportFile: ${agent?.reportFile}`);
    } else {
      console.warn(`[TaskCompletion] No browser session found for task ${taskId}`);
    }

    // 4) Build finalScreenshotUrl
    let finalScreenshotUrl = null;
    if (finalScreenshot) {
      const p = path.join(runDir, `final-screenshot-${Date.now()}.png`);
      fs.writeFileSync(p, Buffer.from(finalScreenshot, 'base64'));
      console.log(`[TaskCompletion] Saved final screenshot to ${p}`);
      finalScreenshotUrl = `/nexus_run/${runId}/${path.basename(p)}`;
    } else if (intermediateResults.length > 0) {
      const last = intermediateResults[intermediateResults.length - 1];
      if (last.screenshot) {
        if (!last.screenshot.startsWith('data:image')) {
          finalScreenshotUrl = last.screenshot;
        } else {
          const p = path.join(runDir, `final-screenshot-${Date.now()}.png`);
          fs.writeFileSync(p, Buffer.from(last.screenshot.split(',')[1], 'base64'));
          console.log(`[TaskCompletion] Saved last result screenshot to ${p}`);
          finalScreenshotUrl = `/nexus_run/${runId}/${path.basename(p)}`;
        }
      }
    }

    // 5) Process midscene report
    let midsceneReportPath = null, nexusReportUrl = null, reportRawUrl = null;
    if (agent) {
      await agent.writeOutActionDumps();
      midsceneReportPath = agent.reportFile;
      if (midsceneReportPath && fs.existsSync(midsceneReportPath)) {
        try {
          midsceneReportPath = await editMidsceneReport(midsceneReportPath);
          console.log(`[NexusReport] Updated report at ${midsceneReportPath}`);
          nexusReportUrl = `/external-report/${path.basename(midsceneReportPath)}`;
        } catch (error) {
          console.warn(`[NexusReport] Error editing report: ${error.message}`);
        }
      } else {
        console.warn(`[TaskCompletion] Midscene report path invalid: ${midsceneReportPath}`);
      }
    } else {
      console.warn(`[TaskCompletion] No agent found for task ${taskId}, skipping Midscene report`);
    }

    console.log(`[TaskCompletion] Generating landing report with URLs:`, nexusReportUrl, reportRawUrl);

    // 6) Sanitize taskPlan for report
    const planLogs = taskPlan?.planLog || [];
    let sanitizedPlan = null;
    if (taskPlan) {
      sanitizedPlan = { ...taskPlan };
      delete sanitizedPlan.extractedInfo;
      delete sanitizedPlan.userOpenaiKey;
      delete sanitizedPlan.browserSession;
    }

    // 7) Generate landing report
    const reportResult = await generateReport(
      originalPrompt,
      intermediateResults,
      finalScreenshotUrl,
      runId,
      REPORT_DIR,
      nexusReportUrl,
      reportRawUrl,
      planLogs,
      sanitizedPlan
    );

    const landingReportPath = reportResult.reportPath;
    const rawPageText = intermediateResults.map(s => s.result?.extractedInfo || '').join('\n');
    const currentUrl = intermediateResults.slice(-1)[0]?.result?.currentUrl || 'N/A';

    // 8) Determine summary
    let summary = '';
    const lastSteps = [...intermediateResults].reverse().slice(0, 3);
    for (const step of lastSteps) {
      if (step.action === 'task_complete' && step.result?.summary) {
        summary = step.result.summary;
        console.log(`[TaskCompletion] Using summary from task_complete: ${summary}`);
        break;
      }
      if (step.action?.includes('complete') && step.summary) {
        summary = step.summary;
        console.log(`[TaskCompletion] Using summary from step.summary: ${summary}`);
        break;
      }
    }
    if (!summary) {
      for (const step of lastSteps) {
        if (step.type === 'completion' && step.message) {
          summary = step.message;
          console.log(`[TaskCompletion] Using summary from completion message: ${summary}`);
          break;
        }
      }
    }
    if (!summary) {
      for (const step of intermediateResults) {
        if (step.markCompleted || step.completed) {
          summary = step.summary || step.message || step.result?.message || summary;
          if (summary) {
            console.log(`[TaskCompletion] Using summary from marked-complete step: ${summary}`);
            break;
          }
        }
      }
    }
    if (!summary) {
      const last = intermediateResults.slice(-1)[0];
      if (last) {
        summary = last.result?.extractedInfo
          || last.result?.actionOutput
          || last.message
          || (typeof last === 'string' ? last : summary);
      }
    }
    if (!summary) {
      summary = `Task execution completed for: ${originalPrompt}`;
      console.log(`[TaskCompletion] Fallback summary: ${summary}`);
    }

    // 9) Build report URLs
    const landingReportUrl = landingReportPath
      ? `/external-report/${path.basename(landingReportPath)}`
      : reportResult.landingReportUrl || null;
    const rawReportUrl2 = reportResult.rawReportUrl || null;
    console.log(`[TaskCompletion] Enhanced report links:`, {
      landingReportPath, midsceneReportPath, landingReportUrl, nexusReportUrl, rawReportUrl2
    });

    // 10) Pick primaryReportUrl
    let primaryReportUrl = null;
    const tryUrl = url => {
      if (!url) return null;
      const name = path.basename(url);
      const candidate = path.join(process.cwd(), 'nexus_run', 'report', name);
      return fs.existsSync(candidate) ? url : null;
    };
    primaryReportUrl =
      tryUrl(nexusReportUrl) ||
      tryUrl(landingReportUrl) ||
      finalScreenshotUrl ||
      null;

    // 11) Construct finalResult
    let finalResult = {
      success: true,
      taskId,
      raw: { pageText: rawPageText, url: currentUrl },
      aiPrepared: {
        summary,
        nexusReportUrl,
        landingReportUrl,
        rawReportUrl: rawReportUrl2,
        rawResult: intermediateResults.slice(-1)[0]?.result?.result || null,
        cleanResult: (() => {
          const obj = intermediateResults.slice(-1)[0]?.result?.result;
          if (!obj) return 'No result data available';
          if (obj['0']?.description) return obj['0'].description;
          const fv = Object.values(obj)[0];
          if (fv?.description) return fv.description;
          return typeof obj === 'object' ? JSON.stringify(obj) : String(obj);
        })(),
        enhancedSummary: `${summary}\n\nActual Result: ${(() => {
          const obj = intermediateResults.slice(-1)[0]?.result?.result;
          if (!obj) return 'No result data available';
          if (obj['0']?.description) return obj['0'].description;
          const fv = Object.values(obj)[0];
          if (fv?.description) return fv.description;
          return typeof obj === 'object' ? JSON.stringify(obj) : String(obj);
        })()}\n\nTask Reports Available:\n${
          nexusReportUrl ? `- Analysis Report: ${nexusReportUrl}` : ''
        }${landingReportUrl ? `\n- Landing Page Report: ${landingReportUrl}` : ''}${
          rawReportUrl2 ? `\n- Raw Report: ${rawReportUrl2}` : ''
        }`
      },
      screenshot: finalScreenshotUrl,
      steps: intermediateResults.map(step =>
        step.getSummary
          ? step.getSummary()
          : {
              ...step,
              result: step.result
                ? {
                    success: step.result.success,
                    currentUrl: step.result.currentUrl,
                    extractedInfo: null,
                    navigableElements: null
                  }
                : null
            }
      ),
      landingReportUrl,
      nexusReportUrl,
      runReport: landingReportUrl,
      intermediateResults: [],
      error: null,
      reportUrl: primaryReportUrl
    };

    console.log('[TaskCompletion] Applying database size limits…');
    finalResult = handleLargeContent(finalResult);
    console.log('[TaskCompletion] Size limiting complete');

    // 12) Persist to database
    try {
      // Log screenshot URL to verify it's available
      console.log(`[TaskCompletion] Saving screenshot URL to database: ${finalScreenshotUrl}`);
      
      await Task.updateOne(
        { _id: taskId },
        {
          $set: {
            'result.nexusReportUrl': nexusReportUrl,
            'result.landingReportUrl': landingReportUrl,
            'result.reportUrl': primaryReportUrl,
            'result.runReport': landingReportUrl,
            'result.screenshot': finalScreenshotUrl,
            'result.screenshotUrl': finalScreenshotUrl,
            status: 'completed'
          }
        }
      );
      console.log(`[TaskCompletion] Successfully updated Task ${taskId}`);
    } catch (dbError) {
      console.error(`[TaskCompletion] Error updating Task document:`, dbError);
    }
    
    // Send WebSocket notification about task completion with ALL report URLs
    sendWebSocketUpdate(userId, {
      event: 'taskComplete',
      taskId: taskId.toString(),
      status: 'completed',
      summary: finalResult.aiPrepared.summary,
      // Include all available report URLs
      reportUrl: finalResult.reportUrl,
      landingReportUrl: finalResult.landingReportUrl,
      nexusReportUrl: finalResult.nexusReportUrl,
      runReport: finalResult.runReport,
      // Include screenshot URLs if available
      screenshot: finalResult.screenshot,
      // Fix: The finalScreenshotUrl is stored in screenshot field not screenshotUrl
      screenshotUrl: finalResult.screenshot,
      timestamp: new Date().toISOString()
    });
    
    console.log(`[TaskCompletion] Sending WebSocket with screenshot data:`, {
      hasScreenshot: !!finalResult.screenshot,
      screenshotUrl: finalResult.screenshot
    });

    return finalResult;
  } catch (error) {
    console.error(`[TaskCompletion] Error in task completion for task ${taskId}:`, error);

    // Send WebSocket updates
    sendWebSocketUpdate(userId, {
      event: 'taskError',
      taskId: taskId.toString(),
      error: `Error generating reports: ${error.message}`,
      timestamp: new Date().toISOString()
    });

    sendWebSocketUpdate(userId, {
      event: 'taskComplete',
      taskId: taskId.toString(),
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });

    // Generate error report HTML
    const errorReportFile = `error-report-${Date.now()}.html`;
    const errorReportPath = path.join(REPORT_DIR, errorReportFile);
    const errorReportUrl = `/external-report/${path.basename(errorReportPath)}`;

    const errorHtml = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nexus Error Report</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #eee;
            background-color: #1a1a2e;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
          }
          .error-box {
            background-color: #272741;
            border-left: 5px solid #fd3259;
            padding: 1rem 2rem;
            margin: 2rem 0;
            border-radius: 0 5px 5px 0;
          }
          pre {
            background-color: #0f0f1b;
            padding: 1rem;
            border-radius: 5px;
            overflow-x: auto;
          }
          h1, h2 {
            color: #4cc9f0;
          }
          .nexus-logo {
            text-align: center;
            margin-bottom: 2rem;
          }
          .timestamp {
            color: #aaa;
            font-size: 0.9rem;
          }
        </style>
      </head>
      <body>
        <div class="nexus-logo">
          <h1>Nexus</h1>
        </div>
        <h2>Task Error Report</h2>
        <p class="timestamp">Generated on: ${new Date().toLocaleString()}</p>
        <div class="error-box">
          <h3>Error Details</h3>
          <pre>${error.message || 'Unknown error'}</pre>
          ${error.stack ? `<h3>Stack Trace</h3><pre>${error.stack}</pre>` : ''}
        </div>
      </body>
    </html>
    `;

    fs.writeFileSync(errorReportPath, errorHtml);

    // Gather error data
    let errorScreenshot = null;
    let errorLandingReportUrl = null;
    let errorNexusReportUrl = null;
    let errorRunReport = null;
    if (Array.isArray(intermediateResults) && intermediateResults.length > 0) {
      const lastResult = intermediateResults[intermediateResults.length - 1];
      if (lastResult && typeof lastResult === 'object') {
        if (lastResult.screenshot) errorScreenshot = lastResult.screenshot;
        if (lastResult.landingReportUrl) errorLandingReportUrl = lastResult.landingReportUrl;
        if (lastResult.nexusReportUrl) errorNexusReportUrl = lastResult.nexusReportUrl;
        if (lastResult.runReport) errorRunReport = lastResult.runReport;
      }
    }

    const errorResult = {
      success: false,
      taskId,
      raw: { pageText: null, url: null },
      aiPrepared: { summary: null },
      screenshot: errorScreenshot,
      screenshotPath: errorScreenshot,
      screenshotUrl: errorScreenshot,
      steps: [],
      landingReportUrl: errorLandingReportUrl,
      nexusReportUrl: errorNexusReportUrl,
      runReport: errorRunReport,
      intermediateResults: [],
      error: error.message,
      reportUrl: errorReportUrl,
      aiSummary: `Error: ${error.message}`
    };

    console.log(
      `[TaskCompletion] Returning error result structure:`,
      JSON.stringify({
        success: errorResult.success,
        hasError: !!errorResult.error,
        errorMsg: errorResult.error,
        reportUrls: {
          nexusReportUrl: errorResult.nexusReportUrl,
          landingReportUrl: errorResult.landingReportUrl,
          reportUrl: errorResult.reportUrl
        }
      })
    );

    return errorResult;
  } finally {
    // always remove from livePlans no matter what
    TaskPlan.livePlans.delete(taskPlan);
    
    // Clean up browser session resources
    if (taskPlan?.browserSession) {
      try {
        // Close page if it exists and is not already closed
        if (taskPlan.browserSession.page && !taskPlan.browserSession.page.isClosed()) {
          await taskPlan.browserSession.page.close();
          console.log(`[TaskCompletion] Closed browser page for task ${taskId}`);
        }
        
        // Release any semaphore if needed
        if (taskPlan.browserSession.release && typeof taskPlan.browserSession.release === 'function') {
          taskPlan.browserSession.release();
          console.log(`[TaskCompletion] Released semaphore for task ${taskId}`);
        }
        
        // Mark as closed for clarity
        taskPlan.browserSession.closed = true;
        console.log(`[TaskCompletion] Cleaned up browser session for task ${taskId}`);
      } catch (cleanupError) {
        console.error(`[TaskCompletion] Error cleaning up browser session: ${cleanupError.message}`);
      }
    }
  }
}

/**
 * TaskPlan - Class to manage the execution plan for a browser task
 */
class TaskPlan {
  
  /** static registry of all in‑flight plans */
  static livePlans = new Set();

  constructor(userId, taskId, prompt, initialUrl, runDir, runId, maxSteps = 20) {
    this.userId = userId;
    this.taskId = taskId;
    this.prompt = prompt;
    this.initialUrl = initialUrl ? validateAndNormalizeUrl(initialUrl) : 'Not specified';
    this.runDir = runDir;
    this.runId = runId;
    this.steps = [];
    this.currentStepIndex = -1;
    this.maxSteps = maxSteps;
    this.currentState = [];          // Array to store all state objects (assertions, page states, etc.)
    this.extractedInfo = [];         // Array to keep a history of extracted info
    this.navigatableElements = [];   // Array to hold navigable elements (can be cumulative)
    this.planLog = [];
    this.completed = false;
    this.summary = null;    
    this.currentUrl = this.initialUrl;
    // Store the user's OpenAI API key for use in PuppeteerAgent initialization.
    this.userOpenaiKey = null;
    // Store the browser session and agent for reuse across steps
    this.browserSession = {
      page: null,
      agent: null,
      reportFile: null
    };
    TaskPlan.livePlans.add(this);
  }

  log(message, metadata = {}) {
    const entry = { timestamp: new Date().toISOString(), message, ...metadata };
    this.planLog.push(entry);
    console.log(`[Task ${this.taskId}] ${message}`, metadata);
    sendWebSocketUpdate(this.userId, { event: 'planLog', taskId: this.taskId, message, metadata });
  }

  /**
   * Create a new step in the plan.
   * After execution, a short step summary is generated and stored in step.stepSummary.
   * @param {string} type - 'action' or 'query'
   * @param {string} instruction - Instruction for the step
   * @param {Object} args - Associated arguments
   * @returns {PlanStep} - The created step.
   */
  createStep(type, instruction, args) {
    const step = {
      index: this.steps.length,
      type,
      instruction,
      args,
      status: 'pending',
      result: null,
      error: null,
      execute: async (plan) => {
        try {
          step.status = 'running';
          plan.log(`Executing step ${step.index + 1}: ${step.type} - ${step.instruction}`);
          let result;
          if (step.type === 'action') {
            result = await plan.executeBrowserAction(step.args, step.index);
          } else {
            result = await plan.executeBrowserQuery(step.args, step.index);
          }
          step.result = result;
          step.status = result.success ? 'completed' : 'failed';
          if (result.currentUrl && typeof result.currentUrl === 'string') {
            plan.currentUrl = result.currentUrl;
          }
          if (result.state) {
            plan.updateGlobalState(result);
          }
          plan.log(`Step ${step.index + 1} ${step.status}`);
          return result;
        } catch (error) {
          step.status = 'failed';
          step.error = error.message;
          plan.log(`Step ${step.index + 1} failed: ${error.message}`, { stack: error.stack });
          return { success: false, error: error.message, currentUrl: plan.currentUrl };
        }
      },
      getSummary: () => ({
        index: step.index,
        type: step.type,
        instruction: step.instruction,
        status: step.status,
        success: step.result?.success || false,
        stepSummary: step.stepSummary || 'No summary'
      })
    };
    this.steps.push(step);
    this.currentStepIndex = this.steps.length - 1;
    return step;
  }

  getCurrentStep() {
    if (this.currentStepIndex >= 0 && this.currentStepIndex < this.steps.length) {
      return this.steps[this.currentStepIndex];
    }
    return null;
  }

  markCompleted(summary) {
    this.completed = true;
    this.summary = summary;
    this.log(`Task marked as completed: ${summary}`);
  }

  /**
   * Helper method to update globals when a result is received.
   */
  updateGlobalState(result) {
    if (result.state && result.state.assertion) {
      this.currentState.push({ assertion: result.state.assertion });
    } else if (this.currentState.length === 0) {
      this.currentState.push({ assertion: 'No assertion available' });
    }
    
    let extracted = 'No extracted info available';
    if (result.extractedInfo) {
      if (typeof result.extractedInfo === 'object' && result.extractedInfo.pageContent) {
        extracted = result.extractedInfo.pageContent;
      } else if (typeof result.extractedInfo === 'string') {
        extracted = result.extractedInfo;
      }
    }
    this.extractedInfo.push(extracted);
    
    if (result.navigableElements && Array.isArray(result.navigableElements)) {
      this.navigatableElements = this.navigatableElements.concat(result.navigableElements);
    } else if (this.navigatableElements.length === 0) {
      this.navigatableElements = [];
    }
  }

  /**
   * Generate a system prompt that includes progress and state details.
   * @returns {string} - The generated system prompt.
   */
  generateSystemPrompt() {
    const latestState = (Array.isArray(this.currentState) && this.currentState.length)
      ? this.currentState[this.currentState.length - 1]
      : { assertion: 'No assertion available' };
    const assertionSummary = latestState.assertion || 'No assertion available';

    const latestExtracted = (Array.isArray(this.extractedInfo) && this.extractedInfo.length)
      ? this.extractedInfo[this.extractedInfo.length - 1]
      : 'No extracted info available';
    const extractedSummary = latestExtracted
      ? latestExtracted.substring(0, 700) + '...'
      : 'No extracted info available';

    const progressSummary = this.steps.length > 0
      ? this.steps.map(step => 
          `- Step ${step.index + 1}: ${step.type.toUpperCase()} - ${step.instruction} (${step.status})`
        ).join('\n')
      : 'No steps executed yet';

    const lastStepSummary = (this.steps.length > 0 && this.steps[this.steps.length - 1].stepSummary)
      ? this.steps[this.steps.length - 1].stepSummary
      : 'No summary available';

    const recentFailures = this.steps.slice(-3)
      .filter(step => step.status === 'failed')
      .map(step => 
        `- Step ${step.index + 1}: ${step.instruction} failed (${step.error || 'Unknown error'})`
      ).join('\n') || 'No recent failures';

    return `
You are an AI assistant automating browser tasks with resilience and adaptability. 
You never fail to accomplish the task and reason all steps until you accomplish it. 
You always instruct towards achieving the "Main Task".

GUIDELINES:
1. PERSISTENCE: Never give up on a task. If one approach fails, try alternative methods.
2. AUTONOMY: You must determine steps needed without user input after initial request.
3. PLANNING: You can take in a plan and execute it, or create a step-by-step plan based on previous results.
4. ADAPTABILITY: Adjust your plan based on new information. Analyze all changes in new information carefully to see differences then decide.
5. COMMUNICATION: Clearly explain your actions and reasoning.
6. PROGRESS TRACKING: Indicate task progress and status.
7. EXTRACTING DATA: Always provide instructions to extract all necessary page data. 
7. B. Scroll when the command specifies extracting full information for User. Dont stay in one place and extract stupid information, keep track.
8. NAVIGATION EFFICIENCY: Check the current page before navigating. Keep mind of the url you call a tool with dont pass wrong urls & change pages unless you really want to.
9. NEXT STEP PRECISION: Plan incremental steps based on the latest state and data.
10. ERROR HANDLING: Always handle errors, review if elements are available before interacting with them and adjust approach on retry.
11. KEEP TRACKING: Always keep track of the current state and data gathered towards main Task accomplishment. Retrace to last step if needed or elements required are not visible.
12. FINAL RESULT: Use all tracked data to compile a final result of the task, in great detail to offer what the user needs exactly from the results.

TIPS:
- browser_action and browser_query can handle complex instructions like "look for BTC and click it", "click search bar, type 'cats', press enter or click search button"
- passing semi-complex instructions is key to achieving success. e.g one combined instruction like: "Type Cats in search bar and press enter", instead of breaking it into 2 steps.
- breaking down action tasks to too simple instructions can lead to failure. 
- query tasks should be simple and direct.
- call task_complete when you have completed the main task.
- DONT CHANGE THE CURRENT URL IF YOU ALREADY OPENED THE CORRECT PAGE UNLESS YOU WANT TO CHANGE THE PAGE!

CURRENT TASK: "${this.prompt}"
Starting URL: ${this.initialUrl || 'Not specified'}
Current Step: ${this.currentStepIndex + 1} of ${this.maxSteps}
Current URL: ${this.currentUrl || 'Not yet navigated'}

PROGRESS SUMMARY (based on previous step): ${lastStepSummary}
FULL STEP SUMMARY:
${progressSummary}
Recent Failures:
${recentFailures}
Extracted Information:
- ${extractedSummary}
Assertion (Page State):
- ${assertionSummary}

[END OF SUMMARY]

Proceed with logical well thought out and tracked actions toward the Main Task: "${this.prompt}".
    `.trim();
  }

  getSummary() {
    return {
      taskId: this.taskId,
      prompt: this.prompt,
      initialUrl: this.initialUrl,
      currentUrl: this.currentUrl,
      steps: this.steps.map(step => step.getSummary()),
      completed: this.completed,
      summary: this.summary,
      planLog: this.planLog,
      currentStepIndex: this.currentStepIndex,
      maxSteps: this.maxSteps
    };
  }

  async executeBrowserAction(args, stepIndex) {
    if (!args.url && this.currentUrl && this.currentUrl !== 'Not specified' && 
        args.instruction && typeof args.instruction === 'string' && 
        args.instruction.toLowerCase().startsWith('navigate to ')) {
      args.url = this.currentUrl;
    }
    const result = await handleBrowserAction(
      args,
      this.userId,
      this.taskId,
      this.runId,
      this.runDir,
      stepIndex,
      this.browserSession
    );
    if (result.browserSession) {
        this.browserSession.page = result.browserSession.page;
        this.browserSession.agent = result.browserSession.agent;
        this.browserSession.reportFile = result.browserSession.reportFile;
        this.log('Browser session maintained for future steps');
      }
    return result;
  }

  async executeBrowserQuery(args, stepIndex) {
    if (!args.url && this.currentUrl && this.currentUrl !== 'Not specified' && 
        args.instruction && typeof args.instruction === 'string' && 
        args.instruction.toLowerCase().startsWith('navigate to ')) {
      args.url = this.currentUrl;
    }
    const result = await handleBrowserQuery(
      args,
      this.userId,
      this.taskId,
      this.runId,
      this.runDir,
      stepIndex,
      this.browserSession
    );
    if (result.browserSession) {
        this.browserSession.page = result.browserSession.page;
        this.browserSession.agent = result.browserSession.agent;
        this.browserSession.reportFile = result.browserSession.reportFile;
        this.log('Browser session maintained for future steps');
      }
    return result;
  }

  updateBrowserSession(session) {
    this.browserSession = session;
    if (session && session.currentUrl) {
      const validatedUrl = validateAndNormalizeUrl(session.currentUrl);
      if (validatedUrl) {
        this.currentUrl = validatedUrl;
      } else {
        console.warn(`[TaskPlan] Invalid currentUrl in browser session: ${session.currentUrl}`);
      }
    }
    this.log(`Updated browser session, current URL: ${this.currentUrl}`);
  }
}

/**
 * PlanStep - Class to manage an individual step in the execution plan
 */
class PlanStep {
  constructor(index, type, instruction, args, userId, taskId, runDir) {
    this.index = index;
    this.type = type;
    this.instruction = instruction;
    this.args = args;
    this.userId = userId;
    this.taskId = taskId;
    this.runDir = runDir;
    this.status = 'pending';
    this.result = null;
    this.startTime = new Date();
    this.endTime = null;
    this.logs = [];
    this.error = null;
    this.stepSummary = null;
  }

  log(message, data = null) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      step: this.index,
      message,
      data: data ? (typeof data === 'object' ? JSON.stringify(data) : data) : null
    };
    this.logs.push(logEntry);
    console.log(`[PlanStep:${this.index}] ${message}`);
  }

  async generateStepSummary() {
    if (this.stepSummary) return this.stepSummary;
    try {
      const summaryResponse = await openai.chat.completions.create({
        model: 'gpt-3.5-turbo',
        messages: [
          { role: 'system', content: 'Summarize this task\'s step result data like a task supervisor following on key progress:' },
          { role: 'user', content: JSON.stringify(this.getSummary()) }
        ],
        temperature: 0,
        max_tokens: 5
      });
      this.stepSummary = summaryResponse.choices[0].message.content.trim();
      return this.stepSummary;
    } catch (error) {
      console.error(`Error generating step summary: ${error.message}`);
      this.stepSummary = 'No summary';
      return this.stepSummary;
    }
  }

  async execute(plan) {
    this.log(`Starting execution: ${this.type} - ${this.instruction}`);
    this.status = 'running';

    const STEP_TIMEOUT = 300000; // 5 minutes per step

    try {
      const trimmedStepLogs = this.logs.map(entry => {
        const shortMsg = entry.message.length > 150 ? entry.message.substring(0, 150) + '...' : entry.message;
        return { ...entry, message: shortMsg };
      });
      sendWebSocketUpdate(this.userId, {
        event: 'stepProgress',
        taskId: this.taskId,
        stepIndex: this.index,
        progress: 10,
        message: `Starting: ${this.instruction}`,
        log: trimmedStepLogs
      });

      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Step ${this.index} timed out after ${STEP_TIMEOUT}ms`)), STEP_TIMEOUT)
      );

      let result;
      if (this.type === 'action') {
        this.log(`Executing browser action with session: ${plan.browserSession ? 'existing' : 'none'}`);
        result = await Promise.race([
          plan.executeBrowserAction(this.args, this.index),
          timeoutPromise
        ]);
      } else {
        this.log(`Executing browser query with session: ${plan.browserSession ? 'existing' : 'none'}`);
        result = await Promise.race([
          plan.executeBrowserQuery(this.args, this.index),
          timeoutPromise
        ]);
      }
      this.result = result;
      this.status = result.success ? 'completed' : 'failed';
      this.endTime = new Date();

      this.log(`Updating global state with result`, { success: result.success, currentUrl: result.currentUrl });
      plan.updateGlobalState(result);
      plan.updateBrowserSession({ currentUrl: result.currentUrl, ...result.browserSession });

      const trimmedActionLogs = (result.actionLog || []).map(entry => {
        const shortMsg = entry.message.length > 150 ? entry.message.substring(0, 150) + '...' : entry.message;
        return { ...entry, message: shortMsg };
      });

      const finalTrimmedStepLogs = this.logs.map(entry => {
        const shortMsg = entry.message.length > 150 ? entry.message.substring(0, 150) + '...' : entry.message;
        return { ...entry, message: shortMsg };
      });

      sendWebSocketUpdate(this.userId, {
        event: 'stepProgress',
        taskId: this.taskId,
        stepIndex: this.index,
        progress: 100,
        message: this.status === 'completed' ? 'Step completed' : 'Step failed',
        log: [...finalTrimmedStepLogs, ...trimmedActionLogs]
      });

      console.log(`[Task ${this.taskId}] Step ${this.index} completed`, {
        status: this.status,
        type: this.type,
        url: result.currentUrl
      });

      await this.generateStepSummary();
      return result;
    } catch (error) {
      this.log(`Error executing step: ${error.message}`);
      this.status = 'failed';
      this.endTime = new Date();
      this.error = error.message;

      const trimmedLogs = this.logs.map(entry => {
        const shortMsg = entry.message.length > 150 ? entry.message.substring(0, 150) + '...' : entry.message;
        return { ...entry, message: shortMsg };
      });

      sendWebSocketUpdate(this.userId, {
        event: 'stepProgress',
        taskId: this.taskId,
        stepIndex: this.index,
        progress: 100,
        message: `Error: ${error.message}`,
        log: trimmedLogs
      });

      console.log(`[Task ${this.taskId}] Step ${this.index} failed`, { error: error.message });

      // Only clean up browser session if unrecoverable (e.g., browser disconnected)
      if (plan.browserSession && plan.browserSession.browser && !plan.browserSession.browser.isConnected()) {
        try {
          this.log('[PlanStep] Cleaning up browser session due to unrecoverable error');
          if (typeof plan.browserSession.release === 'function') {
            plan.browserSession.release();
            this.log('[PlanStep] Released semaphore due to disconnected browser');
          }
          await plan.browserSession.browser.close();
          plan.browserSession = null;
          this.log('[PlanStep] Cleaned up browser session due to unrecoverable error');
        } catch (cleanupError) {
          this.log(`[PlanStep] Error during browser session cleanup: ${cleanupError.message}`);
        }
      } else {
        this.log('[PlanStep] Preserving browser session for next step');
      }

      return {
        success: false,
        error: error.message,
        actionLog: trimmedLogs,
        currentUrl: plan.currentUrl,
        task_id: this.taskId,
        stepIndex: this.index
      };
    }
  }

  getSummary() {
    return {
      index: this.index,
      type: this.type,
      instruction: this.instruction,
      args: this.args,
      status: this.status,
      startTime: this.startTime,
      endTime: this.endTime,
      duration: this.endTime ? (this.endTime - this.startTime) : null,
      resultSummary: this.result ? {
        success: this.result.success,
        currentUrl: this.result.currentUrl,
        error: this.result.error,
        extractedInfo: this.result.extractedInfo,
        navigableElements: this.result.navigableElements
      } : null,
      logs: this.logs,
      error: this.error,
      stepSummary: this.stepSummary
    };
  }
}

/**
 * Get an OpenAI client for this user, specifically configured for CHAT PURPOSES ONLY.
 * This simplified function handles chat models (GPT-4o, Claude, Gemini, etc.)
 * 
 * TODO: This function needs proper SDK implementation for non-OpenAI providers:
 * - Currently only OpenAI models (GPT-4o, GPT-4o-mini, GPT-3.5-turbo) are fully supported
 * - Claude models require the Anthropic SDK with different parameters
 * - Gemini models need Google's generative AI SDK
 * - Grok models have OpenAI-compatible API but may need specific streaming setup
 * 
 * The current implementation returns an OpenAI client which will only work properly with
 * OpenAI models. For other providers, we need to modify streamNliThoughts() to handle
 * the different client SDKs and request formats.
 * 
 * Note: This is NOT used for browser automation, which is handled by setupNexusEnvironment().
 */
/**
 * Get an OpenAI client for this user with configurable timeout
 * @param {string} userId - The user ID
 * @param {Object} [options] - Configuration options
 * @param {number} [options.timeout=30000] - Request timeout in milliseconds (default: 30000)
 * @returns {Promise<OpenAI>} Configured OpenAI client
 */
async function getUserOpenAiClient(userId, options = {}) {
  // Define standard default keys for different providers
  const DEFAULT_KEYS = {
    'openai': process.env.DEFAULT_GPT4O_KEY || '',
    'qwen': process.env.DEFAULT_OPENROUTER_KEY || '',
    'google': process.env.DEFAULT_GEMINI_KEY || '',
    'xai': process.env.DEFAULT_GROK_KEY || ''
  };
  
  // Define provider-specific base URLs
  const PROVIDER_BASE_URLS = {
    'openai': process.env.CUSTOM_OPENAI_ENDPOINT || undefined,
    'google': 'https://generativelanguage.googleapis.com/v1beta/openai/',
    'qwen': 'https://openrouter.ai/api/v1',
    'xai': 'https://api.groq.com/openai/v1'
  };
  
  // Map from model to provider
  const MODEL_PROVIDER_MAPPING = {
    // OpenAI models
    'gpt-4o': 'openai',
    'gpt-4o-mini': 'openai',
    'gpt-3.5-turbo': 'openai',
    // Gemini models
    'gemini-2.5-pro': 'google',
    'gemini-2.5-flash': 'google',
    // Grok models
    'grok-1': 'xai'
  };
  
  // Track whether we're using a default key
  let usingDefaultKey = false;
  let keySource = 'user';
  
  // Fetch user's preferences and API keys
  const user = await User
    .findById(userId)
    .select('openaiApiKey apiKeys preferredEngine modelPreferences')
    .lean();

  if (!user) {
    console.error(`[OpenAIClient] User ${userId} not found, using default GPT-4o key`);
    usingDefaultKey = true;
    keySource = 'system-default';
    return new OpenAI({ 
      apiKey: DEFAULT_KEYS['openai'],
      defaultQuery: { usingDefaultKey, keySource, engine: 'gpt-4o', provider: 'openai' }
    });
  }

  // Get the user's preferred chat model, defaulting to gpt-4o if not set
  let preferredModel = user?.modelPreferences?.chat || 'gpt-4o';
  console.log(`[Chat] Using chat model preference: ${preferredModel}`);
  
  // Determine the provider for this model
  const provider = MODEL_PROVIDER_MAPPING[preferredModel] || 'openai';
  
  // If model isn't supported, fall back to gpt-4o
  if (!MODEL_PROVIDER_MAPPING[preferredModel]) {
    console.warn(`[OpenAIClient] Unsupported model ${preferredModel}, falling back to gpt-4o`);
    preferredModel = 'gpt-4o';
  }
  
  // Get the base URL for this provider
  const baseURL = PROVIDER_BASE_URLS[provider];
  
  // Map from provider to schema key in User model
  const PROVIDER_SCHEMA_MAPPING = {
    'openai': 'gpt4o',
    'google': 'gemini',
    'xai': 'grok',
    'qwen': 'qwen'
  };
  
  // Handle Gemini models with Google's API format but through OpenAI compatible endpoint
  if (provider === 'google') {
    console.log(`[OpenAIClient] Using Gemini model: ${preferredModel} with Google API compatibility layer`);
  }

  // Get the schema key for the user's API keys
  const schemaKey = PROVIDER_SCHEMA_MAPPING[provider];
  
  // Check for the appropriate API key
  let apiKey;
  
  // First try user's stored key for this provider
  if (user?.apiKeys?.[schemaKey] && user.apiKeys[schemaKey].trim().length > 0) {
    apiKey = user.apiKeys[schemaKey].trim();
    keySource = 'user';
    usingDefaultKey = false;
  } 
  // For OpenAI, check legacy key as well
  else if (provider === 'openai' && user?.openaiApiKey && user.openaiApiKey.trim().length > 0) {
    apiKey = user.openaiApiKey.trim();
    keySource = 'legacy';
    usingDefaultKey = false;
  } 
  // If no user key, try default key
  else if (DEFAULT_KEYS[provider] && DEFAULT_KEYS[provider].trim().length > 0) {
    apiKey = DEFAULT_KEYS[provider];
    keySource = 'system-default';
    usingDefaultKey = true;
  } 
  // If no key available for preferred model, fall back to GPT-4o
  else {
    // Notify the user that we're falling back
    notifyApiKeyStatus(userId, {
      hasKey: false,
      engine: preferredModel,
      provider,
      message: `No API key available for ${preferredModel}, falling back to gpt-4o`
    });
    
    // Reset to GPT-4o
    preferredModel = 'gpt-4o';
    
    // Try user's GPT-4o key
    if (user?.apiKeys?.gpt4o && user.apiKeys.gpt4o.trim().length > 0) {
      apiKey = user.apiKeys.gpt4o.trim();
      keySource = 'fallback-user';
      usingDefaultKey = false;
    } 
    // Try legacy key
    else if (user?.openaiApiKey && user.openaiApiKey.trim().length > 0) {
      apiKey = user.openaiApiKey.trim();
      keySource = 'fallback-legacy';
      usingDefaultKey = false;
    }
    // Try default key
    else if (DEFAULT_KEYS['openai'] && DEFAULT_KEYS['openai'].trim().length > 0) {
      apiKey = DEFAULT_KEYS['openai'];
      keySource = 'fallback-system';
      usingDefaultKey = true;
    }
    // No keys available at all
    else {
      console.error(`[OpenAIClient] No API keys available for user ${userId}`);
      throw new Error('No API keys available');
    }
  }

  // Log what we're using but mask most of the key
  const maskedKey = apiKey.length > 8 
    ? `${apiKey.substring(0, 4)}...${apiKey.substring(apiKey.length - 4)}` 
    : '[none]';
  console.log(
    `[ChatClient] Using ${preferredModel} with key ${maskedKey} for user ${userId} ` +
    `(source: ${keySource}, default: ${usingDefaultKey})`
  );
  
  // Create client with appropriate configuration and metadata
  const clientConfig = {
    apiKey, 
    baseURL,
    timeout: options.timeout || 60000, // Default 60s timeout
    defaultQuery: { 
      usingDefaultKey, 
      keySource, 
      engine: preferredModel, 
      provider 
    }
  };
  
  // For Google models (Gemini), adjust the default headers for compatibility
  if (provider === 'google') {
    clientConfig.defaultHeaders = {
      'x-goog-api-key': apiKey,
      'Content-Type': 'application/json'
    };
    // Don't pass the API key in the standard auth header for Google APIs
    clientConfig.apiKey = null;
  }

  return new OpenAI(clientConfig);
}


/**
 * Check if a user has a valid API key for the specified engine
 * @param {string} userId - User ID
 * @param {string} engineName - Engine name (gpt-4o, qwen-2.5-vl-72b, etc.)
 * @returns {Object} - Object containing whether key exists and source
 */
export async function checkEngineApiKey(userId, engineName) {
  // Validate the engine name is one we support
  if (!Object.keys(ENGINE_KEY_MAPPING).includes(engineName)) {
    console.warn(`Unsupported engine requested: ${engineName}, falling back to gpt-4o`);
    engineName = 'gpt-4o'; // Default fallback
  }
  
  // Map from engine name to API key type
  const apiKeyType = ENGINE_KEY_MAPPING[engineName];
  
  // Map from engine name to database schema key
  const engineToSchemaKey = {
    'gpt-4o': 'gpt4o',
    'qwen-2.5-vl-72b': 'qwen',
    'gemini-2.5-pro': 'gemini',
    'ui-tars': 'uitars'
  };
  
  // Get the schema key for this engine
  const schemaKey = engineToSchemaKey[engineName];
  console.log(`[API Key Check] Checking API key for engine ${engineName} using schema key ${schemaKey}`);
  
  // Default fallback keys - mapped to our standardized key types
  const DEFAULT_KEYS = {
    'openai': process.env.DEFAULT_GPT4O_KEY || '',
    'qwen': process.env.DEFAULT_OPENROUTER_KEY || '',
    'google': process.env.DEFAULT_GEMINI_KEY || '',
    'uitars': process.env.DEFAULT_UITARS_KEY || ''
  };
  
  // Fetch user's API keys
  const user = await User
    .findById(userId)
    .select('apiKeys openaiApiKey')
    .lean();

  if (!user) {
    return { 
      hasKey: DEFAULT_KEYS['openai'].length > 0, 
      keySource: 'system-default',
      usingDefault: true,
      engine: 'gpt-4o', // Always fall back to GPT-4o for missing users
      keyType: 'openai'
    };
  }

  // This is where we removed a duplicate nested function
  // The main function already does this check correctly


  // Check if user has the required key based on schema mapping
  if (user?.apiKeys?.[schemaKey] && user.apiKeys[schemaKey].trim().length > 0) {
    console.log(`[API Key Check] Found user API key for ${engineName} in schema key ${schemaKey}`);
    return { 
      hasKey: true, 
      keySource: 'user', 
      usingDefault: false, 
      engine: engineName,
      keyType: apiKeyType 
    };
  }
  
  // Special case for legacy OpenAI key
  if (apiKeyType === 'openai' && user?.openaiApiKey && user.openaiApiKey.trim().length > 0) {
    return { 
      hasKey: true, 
      keySource: 'legacy', 
      usingDefault: false, 
      engine: engineName,
      keyType: apiKeyType 
    };
  }
  
  // Check for default key
  if (DEFAULT_KEYS[apiKeyType] && DEFAULT_KEYS[apiKeyType].length > 0) {
    return { 
      hasKey: true, 
      keySource: 'system-default', 
      usingDefault: true, 
      engine: engineName,
      keyType: apiKeyType 
    };
  }
  
  // If we get here, no key was found - either user or default
  // For ui-tars, we always consider it available
  if (engineName === 'ui-tars') {
    return { 
      hasKey: true, 
      keySource: 'internal', 
      usingDefault: false, 
      engine: engineName,
      keyType: apiKeyType 
    };
  }
  
  // For any other engine, we need to fall back to GPT-4o
  return { 
    hasKey: false, 
    keySource: 'none', 
    usingDefault: false, 
    engine: engineName,
    keyType: apiKeyType,
    fallbackEngine: 'gpt-4o',
    fallbackKeyType: 'openai'
  };
}

/**
 * Notify a user about API key status
 * @param {string} userId - User ID
 * @param {Object} keyInfo - Information about the key status
 */
export function notifyApiKeyStatus(userId, keyInfo) {
  // Log the API key status regardless of notification type
  if (!keyInfo.hasKey) {
    console.log(`[API Key] No API key found for ${keyInfo.engine}, notifying user`);
  } else if (keyInfo.usingDefault) {
    console.log(`[API Key] Using system default API key for ${keyInfo.engine} from source: ${keyInfo.keySource}`);
  } else if (keyInfo.keySource === 'user') {
    console.log(`[API Key] Using user's own API key for ${keyInfo.engine}`);
  }
}

/**
 * Set up environment variables for midscene based on user preferences following
 * the guidelines at https://midscenejs.com/choose-a-model.html
 * This must be called before creating any midscene agent.
 */
async function setupNexusEnvironment(userId) {
  // Default API key fallbacks from environment (for development/testing)
  const DEFAULT_GPT4O_KEY = process.env.DEFAULT_GPT4O_KEY || '';
  const DEFAULT_OPENROUTER_KEY = process.env.DEFAULT_OPENROUTER_KEY || '';
  const DEFAULT_GEMINI_KEY = process.env.DEFAULT_GEMINI_KEY || '';
  const DEFAULT_UITARS_KEY = process.env.DEFAULT_UITARS_KEY || '';

  // Fetch user and their API keys + preferences
  const user = await User
    .findById(userId)
    .select('apiKeys preferredEngine modelPreferences')
    .lean();

  if (!user) {
    console.error(`[MidsceneEnv] User ${userId} not found`);
    return false;
  }

  // Get preferred engine or default to GPT-4o
  const preferredEngine = user?.preferredEngine || 'gpt-4o';
  console.log(`[MidsceneEnv] Setting up engine: ${preferredEngine} for user ${userId}`);

  // Log the state of environment variables before resetting
  console.log(`[MidsceneEnv] BEFORE RESET - Environment variables state:`);
  console.log(`[MidsceneEnv] OPENAI_BASE_URL = ${process.env.OPENAI_BASE_URL || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_USE_QWEN_VL = ${process.env.MIDSCENE_USE_QWEN_VL || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_USE_GEMINI = ${process.env.MIDSCENE_USE_GEMINI || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_USE_VLM_UI_TARS = ${process.env.MIDSCENE_USE_VLM_UI_TARS || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_MODEL_NAME = ${process.env.MIDSCENE_MODEL_NAME || 'not set'}`);

  // Reset all environment variables to avoid conflicts
  delete process.env.OPENAI_BASE_URL;
  delete process.env.MIDSCENE_USE_QWEN_VL;
  delete process.env.MIDSCENE_USE_GEMINI;
  delete process.env.MIDSCENE_USE_VLM_UI_TARS;
  
  // Standard configuration across all models
  process.env.MIDSCNE
  process.env.MIDSCENE_MAX_STEPS = '20';
  process.env.MIDSCENE_TIMEOUT = '1800000'; // 30 min

  // Configure environment based on selected engine
  switch (preferredEngine) {
    case 'gpt-4o':
      // OpenAI GPT-4o configuration
      const gpt4oKey = (user?.apiKeys?.gpt4o && user.apiKeys.gpt4o.trim().length > 0)
        ? user.apiKeys.gpt4o.trim()
        : DEFAULT_GPT4O_KEY;
      
      process.env.OPENAI_API_KEY = gpt4oKey;
      process.env.MIDSCENE_MODEL_NAME = 'gpt-4o';
      // Optional custom endpoint configuration
      if (process.env.CUSTOM_OPENAI_ENDPOINT) {
        process.env.OPENAI_BASE_URL = process.env.CUSTOM_OPENAI_ENDPOINT;
      }
      
      console.log(`[MidsceneEnv] Configured GPT-4o, hasKey=${gpt4oKey.length > 0}`);
      break;

    case 'qwen-2.5-vl-72b':
      // Qwen-2.5-VL 72B Instruct configuration via OpenRouter per documentation
      // https://midscenejs.com/choose-a-model.html
      const qwenKey = (user?.apiKeys?.qwen && user.apiKeys.qwen.trim().length > 0)
        ? user.apiKeys.qwen.trim()
        : DEFAULT_OPENROUTER_KEY;
      
      // Configure Qwen via OpenRouter approach per documentation
      process.env.OPENAI_BASE_URL = 'https://openrouter.ai/api/v1';
      process.env.OPENAI_API_KEY = qwenKey;
      process.env.MIDSCENE_MODEL_NAME = 'qwen/qwen2.5-vl-72b-instruct';
      process.env.MIDSCENE_USE_QWEN_VL = '1';
      
      console.log(`[MidsceneEnv] Configured Qwen-2.5-VL via OpenRouter, hasKey=${qwenKey.length > 0}`);
      break;

    case 'gemini-2.5-pro':
      // Gemini-2.5-Pro configuration per documentation (https://midscenejs.com/choose-a-model.html)
      const geminiKey = (user?.apiKeys?.gemini && user.apiKeys.gemini.trim().length > 0)
        ? user.apiKeys.gemini.trim()
        : DEFAULT_GEMINI_KEY;
      
      // Debug check for valid Gemini API key format
      if (geminiKey.startsWith('sk-') || !geminiKey.includes('_')) {
        console.warn(`[MidsceneEnv] WARNING: Gemini API key may be in incorrect format! Google API keys typically start with 'AIza' and don't use 'sk-' prefix`);
      }
      
      // Make sure we're using the correct Google API key format
      // According to Google documentation, API keys should be passed without Bearer prefix
      const formattedGeminiKey = geminiKey;
      
      // Configure Gemini per documentation
      process.env.OPENAI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/openai/';
      process.env.OPENAI_API_KEY = formattedGeminiKey;
      process.env.MIDSCENE_MODEL_NAME = 'gemini-2.5-pro';
      process.env.MIDSCENE_USE_GEMINI = '1';
      
      // Additional debugging info for Gemini setup
      console.log(`[MidsceneEnv] Configured Gemini-2.5-Pro, hasKey=${geminiKey.length > 0}`);
      console.log(`[MidsceneEnv] API key format check: starts with 'AIza'=${geminiKey.startsWith('AIza')}`);
      break;

    case 'ui-tars':
      // UI-TARS configuration with DOUBAO engine according to documentation
      // https://midscenejs.com/choose-a-model.html
      const uitarsKey = (user?.apiKeys?.uitars && user.apiKeys.uitars.trim().length > 0)
        ? user.apiKeys.uitars.trim()
        : DEFAULT_UITARS_KEY;
      
      // Check if the key looks like an inference access point ID
      const isInferencePoint = uitarsKey.startsWith('ep-');
      
      // UI-TARS/DOUBAO configuration
      process.env.OPENAI_BASE_URL = "https://ark.cn-beijing.volces.com/api/v3";
      process.env.OPENAI_API_KEY = uitarsKey; // API key
      process.env.MIDSCENE_MODEL_NAME = isInferencePoint ? uitarsKey : 'ui-tars-72b-sft'; // Use access point ID or default model
      process.env.MIDSCENE_USE_VLM_UI_TARS = 'DOUBAO';
      
      console.log(`[NexusEnv] Configured UI-TARS (DOUBAO), hasKey=${uitarsKey.length > 3}, using ${isInferencePoint ? 'inference point' : 'default model name'}`);
      break;

    default:
      console.error(`[NexusEnv] Unknown engine: ${preferredEngine}, falling back to GPT-4o`);
      // Fall back to GPT-4o
      const fallbackKey = (user?.apiKeys?.gpt4o && user.apiKeys.gpt4o.trim().length > 0)
        ? user.apiKeys.gpt4o.trim()
        : DEFAULT_GPT4O_KEY;
      
      process.env.OPENAI_API_KEY = fallbackKey;
      process.env.MIDSCENE_MODEL_NAME = 'gpt-4o';
      
      console.log(`[NexusEnv] Fallback to GPT-4o, hasKey=${fallbackKey.length > 0}`);
  }
  
  // Log the final state of environment variables after setup
  console.log(`[MidsceneEnv] AFTER SETUP - Final environment variables state:`);
  console.log(`[MidsceneEnv] OPENAI_BASE_URL = ${process.env.OPENAI_BASE_URL || 'not set'}`);
  console.log(`[MidsceneEnv] OPENAI_API_KEY = ${process.env.OPENAI_API_KEY ? '*****' + process.env.OPENAI_API_KEY.slice(-5) : 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_USE_QWEN_VL = ${process.env.MIDSCENE_USE_QWEN_VL || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_USE_GEMINI = ${process.env.MIDSCENE_USE_GEMINI || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_USE_VLM_UI_TARS = ${process.env.MIDSCENE_USE_VLM_UI_TARS || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_MODEL_NAME = ${process.env.MIDSCENE_MODEL_NAME || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_MAX_STEPS = ${process.env.MIDSCENE_MAX_STEPS || 'not set'}`);
  console.log(`[MidsceneEnv] MIDSCENE_TIMEOUT = ${process.env.MIDSCENE_TIMEOUT || 'not set'}`);
  
  return true;
}

/**
 * Enhanced browser action handler with comprehensive logging and obstacle management
 * @param {Object} args - Action arguments
 * @param {string} userId - User ID
 * @param {string} taskId - Task ID
 * @param {string} runId - Run ID 
 * @param {string} runDir - Run directory
 * @param {number} currentStep - Current step number
 * @param {Object} existingSession - Existing browser session
 * @returns {Object} - Result of the action
 */
// AI Action Context for browser automation
const AI_ACTION_CONTEXT = `
You are a visual AI assistant that can see and interact with web pages. 

When you see these common elements, handle them automatically:
- Click "Accept All" or similar buttons on cookie consent dialogs
- Close any popups, modals or overlays that block content
- For CAPTCHAs: Analyze the challenge and solve it if possible, otherwise ask for human help
- Dismiss any non-essential notifications or banners
- Handle login prompts only if credentials are provided

Scroll down on youtube popups to see cookies buttons for example.

Focus on completing the main task while managing these elements as needed.
`;

async function isSessionValid(session) {
  if (!session || !session.browser || !session.browser.isConnected()) {
    return false;
  }
  try {
    const pages = await session.browser.pages();
    return pages.length > 0;
  } catch (error) {
    return false;
  }
}

/**
 * Executes a “browser action” (e.g. clicking, filling forms, navigation, etc.) within
 * the shared Puppeteer cluster.  
 * All of your existing logging, retry logic, Nexus + filesystem screenshots,
 * WebSocket progress updates, and final return shape are preserved.
 *
 * @param {Object} args
 *   - command: the AI‑driven instruction to run (e.g. “click the login button”)
 *   - url: optional starting URL, if this step isn’t a “navigate to” command
 * @param {string} userId         Unique identifier for this user
 * @param {string} taskId         Unique identifier for this task
 * @param {string} runId          Identifier for this overall run (for screenshot paths)
 * @param {string} runDir         Filesystem directory where run artifacts (screenshots) are stored
 * @param {number} [currentStep=0]  Zero‑based index of this step
 * @returns {Promise<Object>}
 *   An object containing:
 *     • success {boolean}
 *     • error   {string|null}
 *     • task_id {string}
 *     • closed  {boolean}            always false (cluster manages closure)
 *     • currentUrl {string}
 *     • stepIndex  {number}
 *     • actionOutput {string}        summary of what happened
 *     • pageTitle {string}
 *     • extractedInfo {string}       AI‑extracted page content
 *     • navigableElements {Array}    list of clickable/interactable elements
 *     • actionLog {Array}            trimmed array of your detailed logs
 *     • screenshotPath {string}
 *     • browserSession {null}        cluster‑managed (no manual session handle)
 *     • state {Object}               { assertion: concise page assertion }
 */

async function handleBrowserAction(
  args,
  userId,
  taskId,
  runId,
  runDir,
  currentStep = 0
) {
  console.log(`[BrowserAction] Received currentStep: ${currentStep}`);
  await setupNexusEnvironment(userId);

  const { command, url: providedUrl } = args;
  const actionLog = [];
  const logAction = (message, data = null) => {
    actionLog.push({
      timestamp: new Date().toISOString(),
      step: currentStep,
      message,
      data: data ? JSON.stringify(data) : null,
    });
    console.log(`[BrowserAction][Step ${currentStep}] ${message}`, data || "");
  };

  // retry navigation with exponential backoff
  async function navigateWithRetry(page, url, maxRetries = 3) {
    let attempt = 0;
    while (attempt < maxRetries) {
      try {
        logAction(`Navigation attempt ${attempt + 1} to ${url}`);
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60000 });
        logAction(`Successfully navigated to ${url}`);
        return true;
      } catch (err) {
        logAction(`Navigation attempt ${attempt + 1} failed: ${err.message}`);
        if (attempt === maxRetries - 1) {
          logAction(`All navigation attempts failed for ${url}`);
          return false;
        }
        await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
        attempt++;
      }
    }
    return false;
  }

  // now hand off to the cluster manager...
  return executeWithBrowserCluster(taskId, userId, async (page) => {
    const browser = page.browser();
    try {
      logAction(`Starting action with command: "${command}", URL: "${providedUrl || "none provided"}"`);

      // 1) figure out URL
      const isNav = command.toLowerCase().startsWith("navigate to ");
      let navigationUrl = null;
      if (isNav) {
        const m = command.match(/navigate to (\S+)/i);
        if (!m) throw new Error("No URL found in navigate command");
        navigationUrl = validateAndNormalizeUrl(m[1]);
        if (!navigationUrl) throw new Error(`Invalid URL extracted: ${m[1]}`);
        logAction(`Extracted URL from command: ${navigationUrl}`);
      }

      const initialUrl = isNav
        ? navigationUrl
        : (() => {
            const u = validateAndNormalizeUrl(providedUrl);
            if (!u) throw new Error(`Invalid provided URL: ${providedUrl}`);
            return u;
          })();

      logAction(`Navigating to URL: ${initialUrl}`);
      page.setUserAgent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      );
      if (!(await navigateWithRetry(page, initialUrl))) {
        throw new Error(`Failed to navigate to ${initialUrl} after retries`);
      }

      // 2) report 30%
      sendWebSocketUpdate(userId, {
        event: "stepProgress",
        taskId,
        stepIndex: currentStep,
        progress: 30,
        message: `Executing: ${command}`,
        log: actionLog,
      });

      // 3) set AI context + perform action
      const agent = new PuppeteerAgent(page, {
      reportFile: path.join(runDir, `midscene-report-${taskId}-${Date.now()}.json`),
      userId: userId,
      taskId: taskId,
      runId: runId
    });
    
    // Store the agent and report file in the browser session
    const browserSession = {
      page,
      agent,
      reportFile: agent.reportFile
    };
    
    // Log the report file initialization
    console.log(`[PuppeteerAgent] Initialized with report file: ${agent.reportFile}`);
      if (agent.setAIActionContext) {
        try {
          logAction("Setting AI action context");
          await agent.setAIActionContext(AI_ACTION_CONTEXT);
        } catch (e) {
          logAction(`Warning: Failed to set AI action context: ${e.message}`);
        }
      }

      if (!isNav) {
        logAction(`Executing action: "${command}"`);
        try {
          await agent.aiAction(command);
          logAction("Action executed successfully");
        } catch (e) {
          logAction(`Action execution error: ${e.message}`);
        }
      }

      // 4) popup & obstacle checks
      const popupCheck = await page.evaluate(() => ({
        url: window.location.href,
        popupOpened: window.opener !== null,
        numFrames: window.frames.length,
        alerts: document.querySelectorAll("[role=\"alert\"]").length,
      }));
      logAction("Post-action popup check", popupCheck);

      if (popupCheck.popupOpened) {
        logAction("Popup detected - checking for new pages");
        const pages = await browser.pages();
        if (pages.length > 1) {
          logAction(`Found ${pages.length} pages, switching to newest`);
          page = pages[pages.length - 1];
          agent = new PuppeteerAgent(page);
          logAction("Switched to new page and reinitialized agent");
        }
        logAction("Checking for page obstacles");
        const obs = await handlePageObstacles(page, agent);
        logAction("Obstacle check results", obs);
      }

      // 5) extract context
      const currentUrl = await page.url();
      logAction(`Current URL: ${currentUrl}`);
      logAction("Extracting rich page context");
      const { pageContent: extractedInfo, navigableElements } =
        await extractRichPageContext(
          agent,
          page,
          currentUrl,
          command,
          "Read, scan and observe the page. Then state - What information is now visible on the page? What can be clicked or interacted with?"
        );
      logAction("Rich context extraction complete", {
        contentLength:
          typeof extractedInfo === "string" ? extractedInfo.length : "object",
        navigableElements: navigableElements.length,
      });

      // 6) Nexus screenshot
      if (agent.logScreenshot) {
        try {
          logAction("Logging screenshot to Nexus report");
          await agent.logScreenshot(`Step ${currentStep}: ${currentUrl}`, {
            content: `${command}`,
          });
        } catch (e) {
          logAction(`Warning: Failed to log screenshot: ${e.message}`);
        }
      }

      // 7) filesystem screenshot
      let screenshotUrl = "";
      try {
        const shot = await page.screenshot({ encoding: "base64" });
        const fn = `screenshot-${Date.now()}.png`;
        const p = path.join(runDir, fn);
        fs.writeFileSync(p, Buffer.from(shot, "base64"));
        screenshotUrl = `/nexus_run/${runId}/${fn}`;
        logAction("Screenshot captured and saved", { path: p, url: screenshotUrl });
      } catch (e) {
        logAction(`Warning: Failed to capture screenshot: ${e.message}`);
      }

      // 8) intermediateResult
      try {
        sendWebSocketUpdate(userId, {
          event: "intermediateResult",
          taskId,
          result: {
            screenshotUrl,
            screenshotPath: screenshotUrl,
            currentUrl,
            extractedInfo,
            navigableElements,
          },
        });
        logAction("Sent intermediateResult");
      } catch (e) {
        console.error(`[Server] WS error: ${e.message}`);
        logAction(`WebSocket update error: ${e.message}`);
      }

      // 9) final 100% update
      sendWebSocketUpdate(userId, {
        event: "stepProgress",
        taskId,
        stepIndex: currentStep,
        progress: 100,
        message: "Action completed",
        log: actionLog,
      });

      // 10) return
      const trimmedLog = actionLog.map((e) => ({
        ...e,
        message:
          e.message.length > 700 ? e.message.slice(0, 700) + "…" : e.message,
      }));

      return {
        success: true,
        error: null,
        task_id: taskId,
        closed: false,
        currentUrl,
        stepIndex: currentStep,
        actionOutput: `Completed: ${command}`,
        pageTitle: await page.title(),
        extractedInfo,
        navigableElements,
        actionLog: trimmedLog,
        screenshotPath: screenshotUrl,
        browserSession: {
          page,
          agent,
          reportFile: agent.reportFile
        },
        state: {
          assertion:
            extractedInfo && extractedInfo.length
              ? extractedInfo
              : "No content extracted",
        },
      };
    } catch (error) {
      logAction(`Error in browser action: ${error.message}`, {
        stack: error.stack,
      });
      // no manual session cleanup needed—cluster will handle it
      return {
        success: false,
        error: error.message,
        actionLog: actionLog.map((e) => ({
          ...e,
          message:
            e.message.length > 150 ? e.message.slice(0, 150) + "…" : e.message,
        })),
        currentUrl: page?.url?.() ?? null,
        task_id: taskId,
        stepIndex: currentStep,
        browserSession: {
          page: page || null,
          agent: agent || null,
          reportFile: agent?.reportFile || null
        },
        browserSession: {
          page: page || null,
          agent: agent || null,
          reportFile: agent?.reportFile || null
        },
      };
    }
  });
}

/**
 * Executes a “browser query” (i.e. `agent.aiQuery`) within the shared Puppeteer cluster.
 * Includes full navigation logic, obstacle detection, AI query, context extraction,
 * Nexus + filesystem screenshots, and WebSocket updates.  
 *
 * @param {Object} args
 *   - query: the AI‑driven question to ask the page (e.g. “what’s the price?”)
 *   - url: optional starting URL (if you’re not re‑using the current page)
 * @param {string} userId         Unique identifier for this user
 * @param {string} taskId         Unique identifier for this task
 * @param {string} runId          Identifier for this overall run (for screenshot paths)
 * @param {string} runDir         Filesystem directory where run artifacts (screenshots) are stored
 * @param {number} [currentStep=0]  Zero‑based index of this step
 * @returns {Promise<Object>}
 *   An object containing:
 *     • success {boolean}
 *     • error   {string|null}
 *     • task_id {string}
 *     • closed  {boolean}            always false (cluster manages closure)
 *     • currentUrl {string}
 *     • stepIndex  {number}
 *     • actionOutput {string}        summary of what happened
 *     • pageTitle {string}
 *     • extractedInfo {string}       raw AI‑query result
 *     • navigableElements {Array}    list of clickable/interactable elements
 *     • actionLog {Array}            trimmed array of your detailed logs
 *     • screenshotPath {string}
 *     • browserSession {null}        cluster‑managed (no manual session handle)
 *     • state {Object}               { assertion: concise page assertion }
 */
export async function handleBrowserQuery(
  args,
  userId,
  taskId,
  runId,
  runDir,
  currentStep = 0
) {
  console.log(`[BrowserQuery] Received currentStep: ${currentStep}`);
  await setupNexusEnvironment(userId);

  const { query, url: providedUrl } = args;
  const actionLog = [];
  const logQuery = (message, data = null) => {
    actionLog.push({
      timestamp: new Date().toISOString(),
      step: currentStep,
      message,
      data: data ? JSON.stringify(data) : null,
    });
    console.log(`[BrowserQuery][Step ${currentStep}] ${message}`, data || '');
  };

  // mark task as processing
  await updateTaskInDatabase(taskId, {
    status: 'processing',
    progress: 50,
    lastAction: query,
  });

  // **Everything below runs inside the cluster-managed browser/page**
  return executeWithBrowserCluster(taskId, userId, async (page) => {
    const browser = page.browser();
    logQuery(`Starting query: "${query}"`);

    // 1) Determine and navigate to URL
    const effectiveUrl = providedUrl
      ? validateAndNormalizeUrl(providedUrl)
      : null;
    logQuery(`Using URL: ${effectiveUrl || 'current page'}`);
    if (!effectiveUrl) {
      throw new Error('No URL provided for new browser session');
    }

    logQuery(`Navigating to: ${effectiveUrl}`);
    page.setDefaultTimeout(TIMEOUTS.ELEMENT_WAIT);
    try {
      await page.goto(effectiveUrl, { waitUntil: 'domcontentloaded' });
      logQuery('Navigation completed successfully');
    } catch (err) {
      logQuery(`Navigation error: ${err.message}`);
      throw new Error(`Failed to navigate to ${effectiveUrl}: ${err.message}`);
    }

    // 2) Progress update
    sendWebSocketUpdate(userId, {
      event: 'stepProgress',
      taskId,
      stepIndex: currentStep,
      progress: 30,
      message: `Querying: ${query}`,
      log: actionLog,
    });

    // 3) Run the AI query
    const agent = new PuppeteerAgent(page, {
      reportFile: path.join(runDir, `midscene-report-${taskId}-${Date.now()}.json`),
      userId: userId,
      taskId: taskId,
      runId: runId
    });
    
    // Store the agent and report file in the browser session
    const browserSession = {
      page,
      agent,
      reportFile: agent.reportFile
    };
    
    // Log the report file initialization
    console.log(`[PuppeteerAgent] Initialized with report file: ${agent.reportFile}`);
    logQuery(`Executing AI query: "${query}"`);
    let queryResult;
    try {
      queryResult = await agent.aiQuery(
        { domIncluded: true },
        'NOTE: Read all information carefully line by line before scrolling past it!! Proceed to carefully and closely: "' +
          query +
          '"'
      );
      logQuery('Query executed successfully');
    } catch (err) {
      logQuery(`AI query error: ${err.message}`);
      throw err;
    }

    // 4) Popup & obstacle handling
    const stateCheck = await page.evaluate(() => ({
      url: window.location.href,
      popupOpened: window.opener !== null,
      numFrames: window.frames.length,
      alerts: document.querySelectorAll('[role="alert"]').length,
    }));
    logQuery('Post-query state check', stateCheck);

    if (stateCheck.popupOpened) {
      logQuery('Popup detected – checking for new pages');
      const pages = await browser.pages();
      if (pages.length > 1) {
        const newPage = pages[pages.length - 1];
        if (newPage !== page) {
          page = newPage;
          logQuery('Switched to new page and reinitialized agent');
        }
      }
      logQuery('Checking for page obstacles');
      const obstacleResults = await handlePageObstacles(page, new PuppeteerAgent(page));
      logQuery('Obstacle check results', obstacleResults);
    }

    // 5) Extract rich context
    const currentUrl = await page.url();
    logQuery(`Current URL: ${currentUrl}`);
    logQuery(`Extracting rich page context from: ${currentUrl}`);
    const { pageContent: extractedInfo, navigableElements } =
      await extractRichPageContext(
        agent,
        page,
        currentUrl,
        query,
        'Read, scan and observe the page. Extract all information.'
      );
    logQuery('Rich context extraction complete', {
      contentLength: (
        typeof extractedInfo === 'string' ? extractedInfo.length : 'object'
      ),
      navigableElements: navigableElements.length,
    });

    // 6) Nexus screenshot
    if (agent.logScreenshot) {
      try {
        logQuery('Logging screenshot to Nexus report');
        await agent.logScreenshot(`Step ${currentStep}: ${currentUrl}`, {
          content: `${query}`,
        });
      } catch (err) {
        logQuery(`Warning: Failed to log screenshot to Nexus report: ${err.message}`);
      }
    }

    // 7) File‑system screenshot
    let screenshotUrl = '';
    if (page) {
      try {
        const shot = await page.screenshot({ encoding: 'base64' });
        const screenshotFilename = `screenshot-${Date.now()}.png`;
        const screenshotPath = path.join(runDir, screenshotFilename);
        fs.writeFileSync(screenshotPath, Buffer.from(shot, 'base64'));
        screenshotUrl = `/nexus_run/${runId}/${screenshotFilename}`;
        logQuery('Screenshot captured and saved', {
          path: screenshotPath,
          url: screenshotUrl,
        });
      } catch (err) {
        logQuery(`Warning: Failed to capture screenshot: ${err.message}`);
      }
    }

    // 8) Send intermediateResult
    try {
      sendWebSocketUpdate(userId, {
        event: 'intermediateResult',
        taskId,
        result: {
          screenshotUrl,
          screenshotPath: screenshotUrl,
          currentUrl,
          extractedInfo: cleanForPrompt(extractedInfo),
          navigableElements: Array.isArray(navigableElements)
            ? navigableElements.map(el => cleanForPrompt(el))
            : cleanForPrompt(navigableElements),
        },
      });
      logQuery('Sent intermediate result WebSocket update');
    } catch (wsErr) {
      console.error(`[BrowserQuery] Error sending WebSocket update: ${wsErr.message}`);
      logQuery(`WebSocket update error: ${wsErr.message}`);
    }

    // 9) Final progress update
    try {
      sendWebSocketUpdate(userId, {
        event: 'stepProgress',
        taskId,
        stepIndex: currentStep,
        progress: 100,
        message: 'Query completed',
        log: actionLog,
      });
      logQuery('Sent step progress WebSocket update');
    } catch (wsErr) {
      console.error(`[BrowserQuery] Error sending step progress update: ${wsErr.message}`);
      logQuery(`Step progress WebSocket update error: ${wsErr.message}`);
    }

    // 10) Trim log and return
    const trimmedActionLog = actionLog.map(entry => ({
      ...entry,
      message:
        entry.message.length > 700
          ? entry.message.slice(0, 700) + '...'
          : entry.message,
    }));

    const assertion =
      "After execution, this is what's now visible: " + extractedInfo;
    logQuery('Assertion for query completed', { assertion });

    return {
      success: true,
      error: null,
      task_id: taskId,
      closed: false,
      currentUrl,
      stepIndex: currentStep,
      actionOutput: `Completed: ${query}`,
      pageTitle: await page.title(),
      extractedInfo: queryResult,
      navigableElements,
      actionLog: trimmedActionLog,
      screenshotPath: screenshotUrl,
      browserSession: {
        page,
        agent,
        reportFile: agent.reportFile
      },
      state: {
        assertion: extractedInfo && extractedInfo.length
          ? extractedInfo
          : 'No content extracted',
      },
    };
  });
}

// Global handler for unhandled promise rejections, particularly for Puppeteer
process.on('unhandledRejection', (reason, promise) => {
  // Only log detailed info for non-puppeteer errors to avoid console spam
  if (reason && reason.message && reason.message.includes('Request is already handled')) {
    // This is a known Puppeteer issue when request interception has race conditions
    // Just log a brief message and continue - it doesn't affect functionality
    console.log('[Puppeteer] Ignoring known issue: Request is already handled');
  } else {
    // For other types of unhandled rejections, log full details
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  }
  // Don't crash the process, allowing the application to continue
});

// ===========================
// ===========================

// Token usage tracking is implemented further down in the file

/**
 * Classifies user prompts as either 'task' or 'chat' using an LLM
 * @param {string} prompt - The user's input prompt
 * @param {string} userId - The ID of the user making the request
 * @returns {Promise<string|Object>} - Returns 'task' or 'chat' on success, or an error object
 */
async function openaiClassifyPrompt(prompt, userId) {
  /**
   * Checks if an error is a quota/rate limit error
   * @param {Error|Object} err - The error to check
   * @returns {boolean} - True if this is a quota/rate limit error
   */
  const isQuotaError = (err) => {
    if (!err) return false;
    
    const errorMessage = String(err.message || '').toLowerCase();
    const errorCode = String(err.code || '').toLowerCase();
    const errorStatus = String(err.status || '').toLowerCase();
    const errorType = String(err.type || '').toLowerCase();
    const errorBody = (err.response?.data || '').toString().toLowerCase();
    
    const errorStr = [
      errorMessage,
      errorCode,
      errorStatus,
      errorType,
      errorBody,
      JSON.stringify(err, Object.getOwnPropertyNames(err))
    ].join(' ');
    
    const quotaIndicators = [
      'quota', 'rate limit', 'rate_limit', 'too many requests',
      'insufficient_quota', 'billing', 'credit', 'limit reached',
      '429', 'usage limit', 'usage_limit', 'quota exceeded',
      'insufficient_quota', 'billing_not_active', 'quota_exceeded',
      'exceeded quota', 'quota limit', 'quota_limit', 'quota reached',
      'rate limit reached', 'account has exceeded', 'exceeded the quota',
      'quota has been exceeded', 'quota has been reached', 'quota is exceeded'
    ];
    
    return quotaIndicators.some(indicator => 
      errorStr.includes(indicator.toLowerCase())
    ) || errorStatus === '429' || errorCode === 'insufficient_quota';
  };

  let client;
  
  try {
    // Get the appropriate OpenAI client with a 10s timeout for classification
    client = await getUserOpenAiClient(userId, { timeout: 10000 });
    
    // Use a small, fast model for classification to save tokens
    const resp = await client.chat.completions.create({
      model: 'gpt-4o-mini', 
      messages: [
        { 
          role: 'system', 
          content: 'Classify user messages as "task" or "chat". ' +
                  'If it\'s a browser automation instruction, classify as "task". ' +
                  'If it\'s a neutral message, question, or comment, classify as "chat". ' +
                  'Respond ONLY with "task" or "chat".' 
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0,
      max_tokens: 5
    });
    
    // Estimate token usage (approximate calculation)
    const promptTokens = Math.ceil(prompt.length / 4); // ~4 chars per token
    const totalTokens = 20 + promptTokens + 5; // System prompt + user prompt + response
    
    // Track token usage
    await trackTokenUsage(userId, totalTokens, "gpt-4o-mini");
    
    // Parse the response
    const responseText = resp.choices?.[0]?.message?.content?.toLowerCase() || '';
    return responseText.includes('task') ? 'task' : 'chat';
    
  } catch (err) {
    console.error('Error in openaiClassifyPrompt:', err);
    
    // Handle quota/rate limit errors
    if (isQuotaError(err)) {
      const provider = client?.defaultQuery?.provider || 'OpenAI';
      const keyType = client?.defaultQuery?.keyType || 'API key';
      console.error(`Quota exceeded for ${provider} (${keyType}):`, err.message);
      return { 
        error: 'quota_exceeded',
        message: `API quota exceeded for ${provider} (${keyType}). Please check your billing or try a different model.`,
        details: err.message
      };
    }
    
    // Handle authentication errors
    if (err.status === 401 || err.message?.includes('auth') || err.code === 'invalid_api_key') {
      const keyType = client?.defaultQuery?.keyType || 'API key';
      console.error(`Authentication error with ${keyType}:`, err.message);
      return { 
        error: 'authentication_error',
        message: `Authentication failed with ${keyType}. Please check your API key in settings.`,
        details: err.message
      };
    }
    
    // Handle other API errors
    if (err.status >= 400) {
      const provider = client?.defaultQuery?.provider || 'API';
      console.error(`${provider} API error (${err.status}):`, err.message);
      return { 
        error: 'api_error',
        message: `${provider} API error (${err.status}): ${err.message || 'Unknown error'}`,
        details: err.message
      };
    }
    
    // Default error handling
    return { 
      error: 'classification_error',
      message: 'Failed to classify prompt',
      details: err.message || 'Unknown error'
    };
  }
}

/**
 * Refactored processTask function using the grand plan approach
 * @param {string} userId - User ID
 * @param {string} userEmail - User email
 * @param {string} taskId - Task ID
 * @param {string} runId - Run ID 
 * @param {string} runDir - Run directory
 * @param {string} prompt - Task prompt
 * @param {string} url - Starting URL
 * @param {string} engine - Engine to use for this task (optional)
 */
// Import YAML map processing utilities
import { processYamlMapTask, extractYamlMapIdFromPrompt } from './src/utils/yamlProcessor.js';

/**
 * Check if a user has exceeded their free tier limit
 * @param {string} userId - User ID to check
 * @returns {{exceeded: boolean, remaining: number, resetIn: number}} - Usage information
 */
function checkFreeTierLimit(userId) {
  const now = new Date();
  let usage = freeTierUsage.get(userId) || { count: 0, lastReset: now };
  
  // Reset counter if more than 24 hours have passed
  const hoursSinceReset = (now - usage.lastReset) / (1000 * 60 * 60);
  if (hoursSinceReset >= FREE_TIER_RESET_HOURS) {
    usage = { count: 0, lastReset: now };
    freeTierUsage.set(userId, usage);
  }
  
  const remaining = Math.max(0, MAX_FREE_PROMPTS - usage.count);
  const resetIn = Math.ceil(FREE_TIER_RESET_HOURS - hoursSinceReset);
  
  return {
    exceeded: usage.count >= MAX_FREE_PROMPTS,
    remaining,
    resetIn,
    total: MAX_FREE_PROMPTS
  };
}

/**
 * Increment the free tier usage counter for a user
 * @param {string} userId - User ID to increment counter for
 */
function incrementFreeTierUsage(userId) {
  const now = new Date();
  let usage = freeTierUsage.get(userId) || { count: 0, lastReset: now };
  
  // Reset counter if more than 24 hours have passed
  const hoursSinceReset = (now - usage.lastReset) / (1000 * 60 * 60);
  if (hoursSinceReset >= FREE_TIER_RESET_HOURS) {
    usage = { count: 1, lastReset: now };
  } else {
    usage.count = (usage.count || 0) + 1;
  }
  
  freeTierUsage.set(userId, usage);
}

async function processTask(userId, userEmail, taskId, runId, runDir, prompt, url, engine) {
  // --- Check if user has any API key configured ---
  const userData = await User.findById(userId).select('apiKeys openaiApiKey');
  
  // Check if any API key is configured (either in the new apiKeys object or legacy openaiApiKey)
  const hasApiKey = userData && (
    // Check legacy openaiApiKey
    (userData.openaiApiKey && userData.openaiApiKey.trim() !== '') ||
    // Check new apiKeys structure
    (userData.apiKeys && Object.values(userData.apiKeys).some(
      key => key && typeof key === 'string' && key.trim() !== ''
    ))
  );
  
  // For users without any API key, enforce rate limiting
  if (!hasApiKey) {
    const usage = checkFreeTierLimit(userId);
    
    if (usage.exceeded) {
      throw new Error(
        `Free tier limit reached (${usage.total} prompts per ${FREE_TIER_RESET_HOURS}h). ` +
        `Please add an API key in settings to continue. ` +
        `Next reset in ~${usage.resetIn} hours.`
      );
    }
    
    // Increment usage counter
    incrementFreeTierUsage(userId);
    
    console.log(`[RateLimit] User ${userId} used ${usage.total - usage.remaining + 1}/${usage.total} free prompts`);
  }

  // --- Unified message persistence: save user command as message ---
  await new Message({
    userId,
    role: 'user',
    type: 'command',
    content: prompt,
    taskId,
    timestamp: new Date()
  }).save();
  console.log(`[ProcessTask] Starting ${taskId}: "${prompt}"`);
  
  // Check for Android control commands (e.g., 'android open twitter', 'android like tweets')
  const androidCommandMatch = prompt.match(/^android\s+(.+)$/i);
  
  // Check for PC control commands (e.g., 'pc search files', 'pc open camera', 'pc media play')
  const pcCommandMatch = !androidCommandMatch && prompt.match(/^pc\s+(search|open|media|system)\s+(.+)$/i);
  
  // Check if the prompt contains a YAML map reference or if it was attached via the UI
  let yamlMapId = extractYamlMapIdFromPrompt(prompt);
  
  // Also check if the prompt contains a direct YAML map reference that might be formatted differently
  if (!yamlMapId) {
    // Alternative pattern check: Look for "yaml map: ID" pattern
    const yamlMapPattern = /yaml\s+map:?\s+([a-zA-Z0-9]+)/i;
    const match = prompt.match(yamlMapPattern);
    if (match && match[1]) {
      yamlMapId = match[1];
      console.log(`[ProcessTask] Detected YAML map ID from alternative pattern: ${yamlMapId}`);
    }
  }
  
  // Handle PC control commands
  if (pcCommandMatch) {
    const [_, action, params] = pcCommandMatch;
    console.log(`[ProcessTask] Detected PC control command: ${action} ${params}`);
    
    // Input validation
    if (!action || !params) {
      throw new Error('Invalid PC control command format. Expected format: pc <action> <params>');
    }
    
    // Check if the action is allowed
    const allowedActions = ['search', 'open', 'media', 'system'];
    const normalizedAction = action.toLowerCase();
    if (!allowedActions.includes(normalizedAction)) {
      throw new Error(`Invalid PC control action. Allowed actions: ${allowedActions.join(', ')}`);
    }
    
    // Apply rate limiting
    const commandType = normalizedAction === 'system' ? 'system' : 'default';
    if (!pcControlRateLimit.canExecute(userId, commandType)) {
      const timeLeft = pcControlRateLimit.getTimeUntilNext(userId, commandType);
      throw new Error(`Rate limit exceeded. Please wait ${timeLeft.toFixed(1)} seconds before executing another ${commandType} command.`);
    }
    
    // Log the command execution attempt
    console.log(`[PC Control] User ${userId} executing command: ${normalizedAction} ${params}`);
    
    try {
      let result;
      const normalizedAction = action.toLowerCase();
      
      // Log the start of command processing
      console.log(`[PC Control] [${taskId}] Starting ${normalizedAction} command with params: ${params}`);
      
      // Handle different PC control actions
      switch (normalizedAction) {
        case 'search':
          result = await pcControl.searchFiles(params);
          break;
          
        case 'open':
          if (params.toLowerCase().includes('camera')) {
            result = await pcControl.openCamera();
          } else {
            result = { success: false, error: `Unsupported open command: ${params}` };
          }
          break;
          
        case 'media':
          const mediaAction = params.toLowerCase().trim();
          if (['play', 'pause', 'next', 'previous', 'volumeup', 'volumedown', 'mute', 'unmute'].includes(mediaAction)) {
            result = await pcControl.mediaControl(mediaAction);
          } else {
            result = { success: false, error: `Unsupported media action: ${mediaAction}` };
          }
          break;
          
        case 'system':
          const systemAction = params.toLowerCase().trim();
          if (['lock', 'sleep', 'restart', 'shutdown', 'logoff'].includes(systemAction)) {
            result = await pcControl.systemCommand(systemAction);
          } else {
            result = { success: false, error: `Unsupported system command: ${systemAction}` };
          }
          break;
          
        default:
          result = { success: false, error: `Unknown PC control action: ${action}` };
      }
      
      // Format the result for the task completion
      const success = result.success !== false; // Handle both undefined and true as success
      const message = result.message || (success ? 'PC control command executed successfully' : result.error || 'Unknown error');
      
      // Log the result
      console.log(`[PC Control] [${taskId}] Command ${normalizedAction} completed with ${success ? 'success' : 'error'}:`, 
        success ? message : result.error || 'Unknown error'
      );
      
      try {
        // Save the task completion
        await saveTaskCompletionMessages(
          userId,
          taskId,
          prompt,
          JSON.stringify({
            ...result,
            timestamp: new Date().toISOString(),
            command: normalizedAction,
            params
          }, null, 2),
          message,
          { 
            pcControl: true, 
            action: normalizedAction, 
            params, 
            success,
            timestamp: new Date().toISOString()
          }
        );
        
        // Clean up any resources
        await pcControl.cleanup();
        
        // Log successful cleanup
        console.log(`[PC Control] [${taskId}] Resources cleaned up successfully`);
        
        return {
          success,
          message,
          result: {
            ...result,
            command: normalizedAction,
            params,
            timestamp: new Date().toISOString()
          },
          taskId
        };
        
      } catch (saveError) {
        console.error(`[PC Control] [${taskId}] Error saving task completion:`, saveError);
        // Re-throw with additional context
        throw new Error(`Failed to save task completion: ${saveError.message}`);
      }
      
    } catch (error) {
      console.error(`[ProcessTask] Error executing PC control command:`, error);
      
      // Save error to task
      await saveTaskCompletionMessages(
        userId,
        taskId,
        prompt,
        error.stack || error.message || 'Unknown error',
        `Failed to execute PC control command: ${error.message}`,
        { 
          pcControl: true, 
          error: true, 
          action: pcCommandMatch[1], 
          params: pcCommandMatch[2] 
        }
      );
      
      // Clean up any resources
      await pcControl.cleanup().catch(cleanupError => {
        console.error('[ProcessTask] Error during PC control cleanup:', cleanupError);
      });
      
      throw error;
    }
  }
  
  // Handle Android control commands
  if (androidCommandMatch) {
    const [_, command] = androidCommandMatch;
    console.log(`[ProcessTask] Detected Android command: ${command}`);
    
    // Input validation
    if (!command) {
      throw new Error('Invalid Android command format. Expected format: android <command>');
    }
    
    // Initialize result object with metadata
    const startTime = new Date();
    const executionId = `android-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`;
    
    try {
      // Update task status
      await updateTaskInDatabase(taskId, {
        status: 'executing',
        startedAt: new Date(),
        executionType: 'android',
        executionId
      });

      // Ensure environment is properly set up for Android automation
      await setupNexusEnvironment(userId);
      
      // Check if the current model is VL-capable (specifically for Android automation)
      const validVLModels = [
        // Qwen VL models
        'qwen/qwen2.5-vl-72b-instruct',  // OpenRouter
        'qwen-vl-max-latest',            // Aliyun DashScope
        
        // Gemini 2.5 Pro
        'gemini-2.5-pro-preview-05-06',
        
        // UI-TARS and Doubao Vision models
        'ep-',  // Any inference endpoint ID from Volcano Engine
        'doubao-1.5-ui-tars',
        'doubao-1.5-thinking-vision-pro'
      ];
      
      const currentModel = (process.env.MIDSCENE_MODEL_NAME || '').toLowerCase();
      const isVLModel = validVLModels.some(model => 
        currentModel.includes(model.toLowerCase())
      ) || 
      // Check for VL flags in environment variables
      process.env.MIDSCENE_USE_QWEN_VL === '1' ||
      process.env.MIDSCENE_USE_GEMINI === '1' ||
      process.env.MIDSCENE_USE_VLM_UI_TARS === 'DOUBAO' ||
      process.env.MIDSCENE_USE_DOUBAO_VISION === '1';
      
      if (!isVLModel) {
        const errorMessage = 'Android automation requires a vision-language model with visual grounding capabilities.\n' +
          'Please switch to a supported model like:\n' +
          '- Qwen-2.5-VL on OpenRouter or Aliyun\n' +
          '- Gemini-2.5-Pro on Google Gemini\n' +
          '- Doubao-1.5-thinking-vision-pro on Volcano Engine\n' +
          '- UI-TARS on volcengine.com\n\n' +
          'Note: GPT-4o cannot be used for Android automation.';
          
        // Create a simple error object that will serialize cleanly
        const error = new Error(errorMessage);
        error.isModelError = true;
        error.code = 'UNSUPPORTED_MODEL';
        throw error;
      }
      
      // Connect to Android device if not already connected
      if (!androidControl.device) {
        console.log(`[AndroidControl] [${taskId}] Connecting to Android device...`);
        await sendWebSocketUpdate(userId, {
          type: 'status',
          taskId,
          status: 'connecting',
          message: 'Connecting to Android device...',
          timestamp: new Date().toISOString()
        });
        
        await androidControl.connect(androidConfig.defaultDeviceUdid);
      }
      
      // Execute the command with progress updates
      await sendWebSocketUpdate(userId, {
        type: 'status',
        taskId,
        status: 'executing',
        message: `Executing Android command: ${command}`,
        timestamp: new Date().toISOString()
      });
      
      const result = await androidControl.executeAction(command, {
        timeout: androidConfig.defaultCommandTimeout,
        sessionId: taskId,
        userId,
        taskId,
        onProgress: (progress) => {
          sendWebSocketUpdate(userId, {
            type: 'progress',
            taskId,
            progress,
            timestamp: new Date().toISOString()
          });
        }
      });
      
      // Calculate execution time
      const endTime = new Date();
      const executionTime = endTime - startTime;
      
      // Format the response with enhanced details
      const response = {
        success: true,
        executionId,
        command,
        startTime: startTime.toISOString(),
        endTime: endTime.toISOString(),
        executionTime: `${executionTime}ms`,
        result: result,
        taskId,
        metadata: {
          device: androidControl.device?.id || 'unknown',
          sdkVersion: androidControl.sdkVersion || 'unknown',
          commandType: typeof command === 'string' ? 'direct' : 'script'
        }
      };
      
      // Generate a user-friendly success message
      const successMessage = typeof command === 'string' 
        ? `Successfully executed Android command: ${command}`
        : 'Android automation script executed successfully';
      
      // Format the result for display
      let formattedResult = '';
      try {
        if (typeof result === 'object' && result !== null) {
          formattedResult = JSON.stringify(result, null, 2);
        } else {
          formattedResult = String(result);
        }
      } catch (e) {
        console.error(`[AndroidControl] [${taskId}] Error formatting result:`, e);
        formattedResult = 'Result available (unable to format)';
      }
      
      // Save the task completion with enhanced metadata
      const completionMeta = {
        androidControl: true,
        command: typeof command === 'string' ? command : 'script',
        success: true,
        executionTime,
        deviceId: androidControl.device?.id,
        sdkVersion: androidControl.sdkVersion,
        screenshots: result?.screenshots?.length || 0,
        logs: result?.logs?.length || 0,
        timestamp: new Date().toISOString()
      };
      
      await saveTaskCompletionMessages(
        userId,
        taskId,
        prompt,
        formattedResult,
        successMessage,
        completionMeta
      );
      
      // Send final update
      await sendWebSocketUpdate(userId, {
        type: 'complete',
        taskId,
        status: 'completed',
        message: successMessage,
        result: response,
        timestamp: new Date().toISOString()
      });
      
      // Update task status in database
      await updateTaskInDatabase(taskId, {
        status: 'completed',
        completedAt: new Date(),
        executionTime,
        result: response
      });
      
      return response;
      
    } catch (error) {
      console.error(`[AndroidControl] [${taskId}] Error executing command:`, error);
      const errorTime = new Date();
      const executionTime = errorTime - startTime;
      
      // Create a sanitized error message that's safe for database storage
      const getErrorMessage = (err) => {
        if (!err) return 'Unknown error';
        
        // If it's already a string, return as is
        if (typeof err === 'string') return err;
        
        // Handle Error objects
        if (err instanceof Error) {
          return err.message || 'Unknown error';
        }
        
        // Handle object errors
        if (typeof err === 'object') {
          return err.message || err.error || err.reason || 'Unknown error';
        }
        
        // Fallback to string conversion
        return String(err);
      };

      // Get a simple error message for database storage
      const errorMessage = getErrorMessage(error);
      
      // Create a more detailed error object for the response
      const errorDetails = {
        message: errorMessage,
        command: typeof command === 'string' ? command : 'script',
        executionTime: `${executionTime}ms`,
        timestamp: errorTime.toISOString(),
        code: error.code || 'UNKNOWN_ERROR'
      };
      
      // Send error update with sanitized error details
      await sendWebSocketUpdate(userId, {
        type: 'error',
        taskId,
        status: 'failed',
        message: `Android command failed: ${errorMessage}`,
        error: errorDetails,
        timestamp: errorTime.toISOString()
      });
      
      // Create a safe error message for the database
      const safeErrorMessage = typeof errorMessage === 'string' 
        ? errorMessage 
        : 'An unknown error occurred during Android automation';
      
      // Only include the first line of the error message in the database to prevent issues
      const firstLineError = safeErrorMessage.split('\n')[0];
      
      // Save error to task with enhanced metadata
      const errorMeta = {
        androidControl: true,
        error: true,
        command: typeof command === 'string' ? command : 'script',
        executionTime,
        deviceId: androidControl.device?.id || 'disconnected',
        sdkVersion: androidControl.sdkVersion || 'unknown',
        errorDetails: {
          message: error.message || 'Unknown error',
          code: error.code || 'UNKNOWN_ERROR',
          stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        },
        timestamp: errorTime.toISOString()
      };
      
      // Update task status in database with just the first line of the error message
      await updateTaskInDatabase(taskId, {
        status: 'failed',
        completedAt: errorTime,
        executionTime,
        error: firstLineError  // Only store a simple string
      });
      
      // Save detailed error to task history
      await saveTaskCompletionMessages(
        userId,
        taskId,
        prompt,
        safeErrorMessage,
        `Failed to execute Android command: ${firstLineError}`,
        errorMeta
      );
      
      // Clean up resources
      try {
        await androidControl.cleanup();
      } catch (cleanupError) {
        console.error(`[AndroidControl] [${taskId}] Error during cleanup:`, cleanupError);
      }
      
      throw error;
    }
  }
  
  // Handle YAML map tasks
  if (yamlMapId) {
    console.log(`[ProcessTask] Detected YAML map reference: ${yamlMapId}`);
    await Task.updateOne({ _id: taskId }, { $set: { yamlMapId, status: 'executing' } });
  
    // Fetch user document to determine browserEngine
    const user = await User.findById(userId).select('preferredEngine modelPreferences').lean();
    const browserPreference = user?.modelPreferences?.browser;
    const browserEngine = browserPreference || user?.preferredEngine || 'gpt-4o'; // Default to gpt-4o
    console.log(`[ProcessTask] Using browser engine for YAML execution: ${browserEngine}`);
  
    // Verify dependencies
    if (typeof sendWebSocketUpdate !== 'function') {
      console.error(`[ProcessTask] sendWebSocketUpdate is not defined for task ${taskId}`);
      throw new Error('WebSocket update function is not available');
    }
    if (typeof setupNexusEnvironment !== 'function') {
      console.error(`[ProcessTask] setupNexusEnvironment is not defined for task ${taskId}`);
      throw new Error('Nexus environment setup function is not available');
    }

    // Define tasksStore (optional, pass null as default)
    const tasksStore = null; // No store provided; processYamlMapTask handles null

    try {
      const yamlResult = await processYamlMapTask({
        userId,
        userEmail,
        taskId,
        runId,
        runDir,
        yamlMapId,
        url,
        engine: browserEngine,
        tasksStore,
        sendWebSocketUpdate,
        setupNexusEnvironment,
        updateTaskInDatabase: async (taskId, updateData) => {
          return await Task.updateOne({ _id: taskId }, { $set: updateData });
        }
      });
      
      // Close the browser if it's still open after YAML processing
      try {
        if (yamlResult.browserSession && yamlResult.browserSession.browser) {
          console.log(`[ProcessTask] Closing browser for task ${taskId} after YAML processing`);
          await yamlResult.browserSession.browser.close().catch(err => {
            console.error(`[ProcessTask] Error closing browser:`, err);
          });
        }
      } catch (closeBrowserError) {
        console.error(`[ProcessTask] Error during browser cleanup:`, closeBrowserError);
        // Non-critical error, continue with task completion
      }
  
      // Get YAML map name from the result for better display
      const yamlMapName = yamlResult.formattedResult?.raw?.yamlMapName || 'Unknown YAML Map';
      
      // Get the execution result for display in the Task Completion card
      const executionResult = yamlResult.formattedResult?.formattedExecutionResult?.result || 
                           yamlResult.formattedResult?.raw?.executionResult || null;
      
      // Extract clean result messages from the execution results
      let cleanResultMessage = '';
      
      // Try to extract a human-readable result message from the execution result
      if (executionResult) {
        try {
          // If it's already a string, use it directly
          if (typeof executionResult === 'string') {
            cleanResultMessage = executionResult;
          } 
          // If it's an object that needs parsing
          else if (typeof executionResult === 'object') {
            // Check if it's already in the expected format with a description field
            if (executionResult['0'] && executionResult['0'].description) {
              cleanResultMessage = executionResult['0'].description;
            }
            // Look for description in any of the object's properties
            else {
              // First check if it's a simple object with a "0" key containing text
              if (executionResult['0'] && typeof executionResult['0'] === 'string') {
                cleanResultMessage = executionResult['0'];
              }
              // Then search for any description field
              else {
                for (const key in executionResult) {
                  if (executionResult[key] && typeof executionResult[key] === 'object' && executionResult[key].description) {
                    cleanResultMessage = executionResult[key].description;
                    break;
                  }
                }
                
                // If we still don't have a clean message, try to format it nicely
                if (!cleanResultMessage) {
                  // Format the execution result as a readable string
                  if (executionResult['0']) {
                    // Handle numbered results format
                    cleanResultMessage = `Execution result: ${JSON.stringify(executionResult, null, 2)}`;
                  } else {
                    // Try to create a human-readable summary
                    const resultKeys = Object.keys(executionResult);
                    if (resultKeys.length === 1 && typeof executionResult[resultKeys[0]] === 'string') {
                      // Simple single value
                      cleanResultMessage = executionResult[resultKeys[0]];
                    } else {
                      // Format as readable object
                      cleanResultMessage = `Execution result: ${JSON.stringify(executionResult, null, 2)}`;
                    }
                  }
                }
              }
            }
          }
        } catch (e) {
          console.log(`[ProcessTask] Error extracting clean message from execution result:`, e);
          // If parsing fails, use the raw result as string
          cleanResultMessage = String(executionResult);
        }
      }
      
      // Create the full task completion message
      const taskCompletionMessage = `YAML map ${yamlMapName} executed successfully`;
      
      // Add the clean result message if available (without duplicating "executed successfully")
      const fullTaskCompletionMessage = cleanResultMessage ? 
        `${taskCompletionMessage}\n\n${cleanResultMessage}` : 
        taskCompletionMessage;
        
      // Use this message as our success message for all database and WebSocket updates
      const successMessage = fullTaskCompletionMessage;
      
      // Normalize result to match processTaskCompletion structure with enhanced data
      const finalResult = {
        success: yamlResult.success,
        taskId,
        raw: {
          pageText: yamlResult.formattedResult?.raw?.pageText || null,
          url: yamlResult.formattedResult?.url || yamlResult.currentUrl || null,
          yamlMapName: yamlMapName,
          executionResult: executionResult
        },
        aiPrepared: {
          summary: cleanResultMessage, // Use our clean result message here
          nexusReportUrl: yamlResult.formattedResult?.aiPrepared?.nexusReportUrl || null,
          landingReportUrl: yamlResult.formattedResult?.aiPrepared?.landingReportUrl || null,
          runReport: yamlResult.formattedResult?.aiPrepared?.runReport || null,
          executionResult: executionResult // Add execution result to aiPrepared for easy access
        },
        screenshot: yamlResult.formattedResult?.screenshotUrl || yamlResult.formattedResult?.screenshotPath || null,
        screenshotPath: yamlResult.formattedResult?.screenshotPath || null,
        screenshotUrl: yamlResult.formattedResult?.screenshotUrl || yamlResult.formattedResult?.screenshotPath || null,
        steps: yamlResult.formattedResult?.steps || [],
        landingReportUrl: yamlResult.formattedResult?.aiPrepared?.landingReportUrl || null,
        nexusReportUrl: yamlResult.formattedResult?.aiPrepared?.nexusReportUrl || null,
        runReport: yamlResult.formattedResult?.aiPrepared?.runReport || null,
        intermediateResults: yamlResult.formattedResult?.intermediateResults || [],
        error: yamlResult.error || null,
        reportUrl: yamlResult.formattedResult?.reportUrl || yamlResult.formattedResult?.aiPrepared?.nexusReportUrl || yamlResult.formattedResult?.aiPrepared?.landingReportUrl || null,
        aiSummary: successMessage,
        yamlMapName: yamlMapName, // Save the actual YAML map name
        executionResult: executionResult // Save the execution result for display
      };
  
      // Log YAML result for debugging
      console.log('[YAML Screenshot Debug] Processing YAML result:', {
        taskId,
        hasScreenshotInFormattedResult: !!yamlResult.formattedResult?.screenshotUrl,
        formattedResultScreenshot: yamlResult.formattedResult?.screenshotUrl || null,
        formattedResultScreenshotPath: yamlResult.formattedResult?.screenshotPath || null,
        hasActionLog: Array.isArray(yamlResult.actionLog),
        actionLogLength: Array.isArray(yamlResult.actionLog) ? yamlResult.actionLog.length : 0,
        hasScreenshotInActionLog: !!yamlResult.actionLog?.find(log => 
          log.data?.screenshotUrl && 
          log.message?.includes('Screenshot captured successfully')
        )
      });
      // Find the actual screenshot URL from various possible sources for YAML tasks
      let finalScreenshotUrl = null;
      
      // MOST IMPORTANT SOURCE: Check in actionLog for the "Screenshot captured successfully" message
      // This is the most reliable source for YAML tasks as shown in the logs
      if (Array.isArray(yamlResult.actionLog)) {
        console.log('[YAML Screenshot Tracking] Searching actionLog for screenshot messages...');
        // Log all messages to see what's available
        yamlResult.actionLog.forEach((log, index) => {
          if (log.message?.includes('Screenshot')) {
            console.log(`[YAML Screenshot Tracking] Found screenshot-related log entry #${index}:`, { 
              message: log.message,
              hasData: !!log.data,
              hasScreenshotUrl: !!log.data?.screenshotUrl,
              screenshotUrl: log.data?.screenshotUrl
            });
          }
        });
        
        const screenshotLog = yamlResult.actionLog.find(log => 
          log.message?.includes('Screenshot captured successfully') && 
          log.data?.screenshotUrl
        );
        
        if (screenshotLog?.data?.screenshotUrl) {
          // The URL is already in the correct web-friendly format from yamlProcessor
          finalScreenshotUrl = screenshotLog.data.screenshotUrl;
          console.log('[YAML Screenshot Tracking] ✓ Found correctly formatted screenshot URL in actionLog:', finalScreenshotUrl);
        } else {
          console.log('[YAML Screenshot Tracking] × No matching screenshot log entry found with correct criteria');
        }
      } else {
        console.log('[YAML Screenshot Tracking] × No actionLog array available in yamlResult');
      }
      
      // Fallback options if not found in actionLog
      if (!finalScreenshotUrl) {
        // Try direct properties in yamlResult
        finalScreenshotUrl = yamlResult.screenshotUrl || yamlResult.screenshotPath;
        
        // Try in formattedResult
        if (!finalScreenshotUrl && yamlResult.formattedResult) {
          finalScreenshotUrl = yamlResult.formattedResult.screenshotUrl || 
                              yamlResult.formattedResult.screenshotPath || 
                              yamlResult.formattedResult.screenshot;
        }
        
        // Try in steps
        if (!finalScreenshotUrl && yamlResult.formattedResult?.steps?.length > 0) {
          for (const step of yamlResult.formattedResult.steps) {
            const stepScreenshot = step.screenshot || step.screenshotPath || step.screenshotUrl;
            if (stepScreenshot) {
              finalScreenshotUrl = stepScreenshot;
              console.log('[YAML Screenshot Debug] Found screenshot in steps:', finalScreenshotUrl);
              break;
            }
          }
        }
        
        // Try in intermediate results
        if (!finalScreenshotUrl && yamlResult.formattedResult?.intermediateResults?.length > 0) {
          for (const result of yamlResult.formattedResult.intermediateResults) {
            const resultScreenshot = result.screenshot || result.screenshotPath || result.screenshotUrl;
            if (resultScreenshot) {
              finalScreenshotUrl = resultScreenshot;
              console.log('[YAML Screenshot Debug] Found screenshot in intermediateResults:', finalScreenshotUrl);
              break;
            }
          }
        }
      }
      
      // Simple path correction if needed (only for fallback paths)
      if (finalScreenshotUrl && !finalScreenshotUrl.startsWith('/') && 
          !finalScreenshotUrl.startsWith('http') && !finalScreenshotUrl.startsWith('data:')) {
        finalScreenshotUrl = '/' + finalScreenshotUrl;
      }
      
      // If we found a screenshot URL, make sure finalResult has it too for future reference
      if (finalScreenshotUrl) {
        console.log('[YAML Screenshot Tracking] Setting screenshot URL in finalResult:', finalScreenshotUrl);
        
        // Update the finalResult object with the found screenshot URL
        finalResult.screenshotUrl = finalScreenshotUrl;
        finalResult.screenshotPath = finalScreenshotUrl;
        finalResult.screenshot = finalScreenshotUrl;
        
        console.log('[YAML Screenshot Tracking] Updated finalResult:', {
          screenshot: finalResult.screenshot,
          screenshotUrl: finalResult.screenshotUrl,
          screenshotPath: finalResult.screenshotPath
        });
      } else {
        console.warn('[YAML Screenshot Tracking] ⚠️ No screenshot found for YAML task', taskId);
      }

      // Create the update data object with all fields to be set
      const taskUpdateData = {
        status: yamlResult.success ? 'completed' : 'error',
        progress: yamlResult.success ? 100 : 0,
        result: finalResult,
        endTime: new Date(),
        summary: finalResult.aiSummary,
        // Prioritize the newly extracted screenshot URL specifically for YAML tasks
        screenshotUrl: finalScreenshotUrl,
        screenshotPath: finalScreenshotUrl, // Also update the path for consistency
        screenshot: finalScreenshotUrl,     // Add an additional field for maximum compatibility
        nexusReportUrl: finalResult.nexusReportUrl,
        landingReportUrl: finalResult.landingReportUrl
      };
      
      // Log the exact update operation being performed for debugging
      console.log('[YAML Screenshot Tracking] Updating MongoDB Task document with screenshot data:', {
        taskId,
        screenshotFields: {
          screenshot: taskUpdateData.screenshot,
          screenshotUrl: taskUpdateData.screenshotUrl,
          screenshotPath: taskUpdateData.screenshotPath
        }
      });
      
      // Update Task document with final result
      await Task.updateOne(
        { _id: taskId },
        { $set: taskUpdateData }
      );
      
      // Verify the update worked by reading back the document
      try {
        const updatedTask = await Task.findById(taskId).lean();
        console.log('[YAML Screenshot Tracking] Verification - Task after update:', {
          _id: updatedTask._id,
          hasResult: !!updatedTask.result,
          topLevelScreenshot: updatedTask.screenshot,
          topLevelScreenshotUrl: updatedTask.screenshotUrl,
          topLevelScreenshotPath: updatedTask.screenshotPath,
          resultScreenshot: updatedTask.result?.screenshot,
          resultScreenshotUrl: updatedTask.result?.screenshotUrl,
          resultScreenshotPath: updatedTask.result?.screenshotPath,
        });
      } catch (error) {
        console.error('[YAML Screenshot Tracking] Error verifying task update:', error.message);
      }
  
      // Save assistant message using saveTaskCompletionMessages
      await saveTaskCompletionMessages(
        userId,
        taskId,
        prompt,
        fullTaskCompletionMessage, // Use the detailed message with actual results
        fullTaskCompletionMessage, // Use the same detailed message here too
        {
          nexusReportUrl: finalResult.nexusReportUrl,
          landingReportUrl: finalResult.landingReportUrl,
          screenshot: finalResult.screenshot,
          screenshotPath: finalResult.screenshotPath,
          screenshotUrl: finalResult.screenshotUrl,
          completedAt: new Date().toISOString()
        }
      );
  
      // Send thoughtComplete event for UI thought bubble
      sendWebSocketUpdate(userId, {
        event: 'thoughtComplete',
        taskId,
        text: finalResult.aiSummary,
        thought: finalResult.aiSummary
      });
  
      // Send taskComplete event
      sendWebSocketUpdate(userId, {
        event: 'taskComplete',
        taskId,
        progress: 100,
        status: 'completed',
        result: finalResult,
        summary: finalResult.aiSummary,
        log: yamlResult.actionLog ? yamlResult.actionLog.slice(-10) : [], // Safely handle yamlLog
        executionTime: yamlResult.formattedResult?.executionTime || 0,
        timestamp: new Date().toISOString(),
        item: {
          type: 'summary',
          title: `YAML Map: ${yamlResult.formattedResult?.raw?.yamlMapName || 'Unknown Map'}`,
          content: finalResult.aiSummary,
          executionTime: yamlResult.formattedResult?.executionTime || 0,
          timestamp: new Date().toISOString()
        }
      });
  
      return finalResult;
    } catch (error) {
      console.error(`[ProcessTask] Error executing YAML map ${yamlMapId}:`, {
        error: error.message,
        stack: error.stack,
        taskId,
        userId
      });
      const errorResult = {
        success: false,
        taskId,
        raw: { pageText: null, url: null },
        aiPrepared: { summary: null },
        screenshot: null,
        screenshotPath: null,
        screenshotUrl: null,
        steps: [],
        landingReportUrl: null,
        nexusReportUrl: null,
        runReport: null,
        intermediateResults: [],
        error: error.message,
        reportUrl: null,
        aiSummary: `Error executing YAML map: ${error.message}`
      };
  
      // Update Task document with error
      await Task.updateOne(
        { _id: taskId },
        {
          $set: {
            status: 'error',
            progress: 0,
            result: errorResult,
            error: error.message,
            endTime: new Date(),
            summary: errorResult.aiSummary
          }
        }
      );
  
      // Save error message to ChatHistory and Message
      await saveTaskCompletionMessages(
        userId,
        taskId,
        prompt,
        `Error: ${error.message}`,
        errorResult.aiSummary,
        {
          error: error.message,
          completedAt: new Date().toISOString()
        }
      );
  
      // Send taskError event
      sendWebSocketUpdate(userId, {
        event: 'taskError',
        taskId,
        error: error.message,
        log: [], // Use empty array as fallback
        timestamp: new Date().toISOString(),
        item: {
          type: 'error',
          title: 'YAML Map Execution Failed',
          content: error.message,
          timestamp: new Date().toISOString()
        }
      });
  
      throw error;
    } finally {
      console.log(`[ProcessTask] Cleaning up browser session for YAML task ${taskId}`);
    }
  }

  // Fetch the user's preferences including execution mode, browser model, and max steps
  const user = await User.findById(userId).select('executionMode preferredEngine modelPreferences maxSteps').lean();
  const executionMode = user?.executionMode || 'step-planning';
  const maxSteps = user?.maxSteps || 20; // Default to 10 if not set
  
  // First check for explicitly requested engine in the function call
  // Then check user's browser model preference
  // Then fall back to user's general preferred engine
  // Finally default to gpt-4o
  const browserPreference = user?.modelPreferences?.browser;
  const engineToUse = engine || browserPreference || user?.preferredEngine || 'gpt-4o';
  
  console.log(`[ProcessTask] Engine selection for browser automation: ${engineToUse} (from: ${engine ? 'explicit' : browserPreference ? 'browser preference' : user?.preferredEngine ? 'preferred engine' : 'default'})`);
  
  // Check if the engine is valid and the user has access to it
  const keyInfo = await checkEngineApiKey(userId, engineToUse);
  if (!keyInfo.hasKey) {
    console.error(`[ProcessTask] No API key available for ${engineToUse}, falling back to GPT-4o`);
    // Fall back to GPT-4o if no key is available for the specified engine
    // This is a safety fallback that should never happen if the API endpoints are working correctly
    const gpt4oKeyInfo = await checkEngineApiKey(userId, 'gpt-4o');
    if (!gpt4oKeyInfo.hasKey) {
      throw new Error(`No API key available for any engine`);
    }
    // Use GPT-4o as the fallback engine
    // Note: We don't have access to req.session here, but that's fine since we're directly using GPT-4o now
    // Notify the user about the fallback
    notifyApiKeyStatus(userId, {
      hasKey: true,
      engine: 'gpt-4o',
      usingDefault: true,
      keySource: 'fallback-system',
      message: `No API key available for ${engineToUse}, falling back to GPT-4o`
    });
  } else if (keyInfo.usingDefault) {
    // Notify the user that we're using a default key
    notifyApiKeyStatus(userId, keyInfo);
  }
  
  console.log(`[ProcessTask] Using engine: ${engineToUse} with execution mode: ${executionMode} for task ${taskId}`);

  const plan = new TaskPlan(userId, taskId, prompt, url, runDir, runId, maxSteps);
  plan.log(`Plan created with engine: ${engineToUse} and execution mode: ${executionMode}`);

  // Clear any queued old messages for this user to avoid stale deliveries
  unsentMessages.delete(userId);

  try {
    await Task.updateOne({ _id: taskId }, { status:'processing', progress:5 });
    sendWebSocketUpdate(userId, { event:'taskStart', taskId, prompt, url });
    plan.log("taskStart → frontend");

    let taskCompleted = false, consecutiveFailures = 0;

    while (!taskCompleted && plan.currentStepIndex < plan.maxSteps - 1) {
      const systemPrompt = plan.generateSystemPrompt();
      plan.log("SYSTEM PROMPT generated");
      
      let messages = [
        { role: "system", content: systemPrompt },
        { role: "user", content: prompt }
      ];
      
      if (plan.steps.length > 0) {
        plan.steps.slice(-3).forEach(step => {
          if (step.result) {
            const toolCallId = `call_${step.index}`;
            messages.push({
              role: "assistant",
              content: null,
              tool_calls: [
                {
                  id: toolCallId,
                  type: "function",
                  function: {
                    name: step.type === 'action' ? 'browser_action' : 'browser_query',
                    arguments: JSON.stringify({
                      [step.type === 'action' ? 'command' : 'query']: step.instruction,
                      task_id: taskId,
                      url: plan.currentUrl
                    })
                  }
                }
              ]
            });
            messages.push({
              role: "tool",
              tool_call_id: toolCallId,
              name: step.type === 'action' ? 'browser_action' : 'browser_query',
              content: JSON.stringify({
                success: step.result.success,
                currentUrl: step.result.currentUrl,
                error: step.result.error,
                extractedInfo: typeof step.result.extractedInfo === 'string'
                  ? step.result.extractedInfo.substring(0, 1500) + '...'
                  : "No extraction",
                navigableElements: Array.isArray(step.result.navigableElements) 
                  ? step.result.navigableElements.slice(0, 30) 
                  : []
              })
            });
          }
        });
      }
      
      if (plan.currentState && plan.currentState.pageDescription) {
        let descriptionText = (typeof plan.currentState.pageDescription === 'string')
          ? plan.currentState.pageDescription.substring(0, 300) + '...'
          : JSON.stringify(plan.currentState.pageDescription).substring(0, 300) + '...';
        messages.push({
          role: "system",
          content: `Current page state: ${descriptionText}`
        });
      }
      
      // Extracted data logged thorough
      if (plan.steps.length > 0) {
        const lastStep = plan.steps[plan.steps.length - 1];
        plan.log("Using extraction from last step", {
          extractedInfo: cleanForPrompt(lastStep.result?.extractedInfo),
          navigableElements: lastStep.result?.navigableElements
        });
      } else {
        plan.log("No intermediate extraction data available.");
      }
      
      // Log which execution mode is being used
      plan.log(`Using execution mode: ${executionMode} for AI request`);
      
      plan.log("Sending function call request to AI", { messages });
      
      // Configure the AI request based on execution mode
      const streamConfig = {
        model: "gpt-4o-mini",
        messages,
        stream: true,
        temperature: 0.3,
        max_tokens: 700,
        tools: [
          {
            type: "function",
            function: {
              name: "browser_action",
              description: "Executes a browser action by specifying a complete natural language instruction, e.g., 'navigate to https://example.com', 'type Sony Wireless headphones into the search bar', or 'click the search button'. The 'command' parameter must include both the verb and the target details.",
              parameters: {
                type: "object",
                properties: {
                  command: { type: "string", description: "Natural language instruction for the browser action, including verb and target" },
                  url: { type: "string", description: "The page URL on which to perform the action" },
                  task_id: { type: "string", description: "Identifier for the current task" }
                },
                required: ["command"]
              }
            }
          },
          {
            type: "function",
            function: {
              name: "browser_query",
              description: "Extracts information from the webpage by performing the specified query, e.g., 'list all clickable elements on the page'. The 'query' parameter must clearly state what to extract.",
              parameters: {
                type: "object",
                properties: {
                  query: { type: "string", description: "Natural language query describing what information to extract from the page" },
                  url: { type: "string", description: "The page URL from which to extract information" },
                  task_id: { type: "string", description: "Identifier for the current task" }
                },
                required: ["query"]
              }
            }
          },
          {
            type: "function",
            function: {
              name: "task_complete",
              description: "Signals that the task is complete with a final summary.",
              parameters: {
                type: "object",
                properties: { summary: { type: "string" } },
                required: []
              }
            }
          }
        ],
        tool_choice: "auto"
      };

      // Special handling for UI-TARS and action-planning mode
      const isUiTars = engineToUse === 'ui-tars';
      const isActionPlanning = executionMode === 'action-planning';
      
      if (isUiTars || isActionPlanning) {
        // For UI-TARS or action-planning mode, modify the system prompt to emphasize end-to-end execution
        messages[0].content += "\n\nIMPORTANT: This task will be executed as a DIRECT AUTOMATION INSTRUCTION. " + 
                              "Do not decompose the task into individual steps or attempt to plan a sequence of actions. " + 
                              "Instead, interpret the command as a single, unified task description for the automation system to execute. " + 
                              "Your response should include a clear, comprehensive description of the end goal for the automation tool.";
        
        // Add specialized behavior based on which condition triggered this mode
        if (isUiTars) {
          messages[0].content += "\n\nThis is running on UI-TARS, which has enhanced web automation capabilities. " + 
                                "Focus on the high-level goal rather than specific steps.";
        }
        
        if (isActionPlanning) {
          messages[0].content += "\n\nAction planning mode is enabled. Provide a complete sequence of actions as a single plan. " + 
                                "Think about the full workflow and optimize for efficiency with minimal back-and-forth.";
          
          // Increase temperature for more exploration in action planning mode
          streamConfig.temperature = 0.5;
        }
        
        // Add a user message specifically asking for a direct execution approach
        messages.push({
          role: "user",
          content: "Please treat my request as a direct automation instruction rather than breaking it down into steps. Provide a clear description of what should be accomplished."
        });
      }
      
      // Use the appropriate client based on the selected engine
      let stream;
      
      // Note: We don't need to call setupNexusEnvironment here since it's already called
      // in the lower-level functions (handleBrowserAction and handleBrowserQuery)
      // This avoids redundancy and potential issues with multiple environment setups
      
      // Get a chat client for the orchestration/planning part
      // This client is only used for the planning conversations, not the actual browser automation
      const client = await getUserOpenAiClient(userId);
      
      if (!client) {
        throw new Error(`No chat client available for user ${userId}`);
      }
      
      // Log the model being used for task planning
      const chatModel = client.defaultQuery?.engine || 'gpt-4o';
      const provider = client.defaultQuery?.provider || 'openai';
      plan.log(`Using chat model ${chatModel} for task planning/orchestration`);
      
      // Adjust stream configuration for Gemini
      if (provider === 'google') {
        // Gemini has different parameter requirements
        streamConfig.temperature = streamConfig.temperature || 0.7;
        streamConfig.max_output_tokens = streamConfig.max_tokens;
        delete streamConfig.max_tokens;
        
        // Gemini requires a different format for tools/function calling.
        if (streamConfig.tools && Array.isArray(streamConfig.tools)) {
          const functionDeclarations = streamConfig.tools
            .map(tool => tool.function)
            .filter(Boolean); // Filter out any non-function tools

          if (functionDeclarations.length > 0) {
            streamConfig.tools = [{ function_declarations: functionDeclarations }];
          } else {
            delete streamConfig.tools; // Remove if no valid functions are found
          }
        }
      }
      
      // Create different streams based on provider
      try {
        stream = await client.chat.completions.create(streamConfig);
      } catch (err) {
        // Log detailed information about the error
        plan.log(`Error creating stream with ${chatModel}: ${err.message}`);
        if (err.response) {
          plan.log(`Response status: ${err.response.status}`);
          plan.log(`Response headers: ${JSON.stringify(err.response.headers)}`);
          plan.log(`Response data: ${JSON.stringify(err.response.data)}`);
        }
        throw err;
      }
      
      let currentFunctionCall = null;
      let accumulatedArgs = '';
      let functionCallReceived = false;
      let thoughtBuffer = '';
      
      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta;
        
        if (delta?.content) {
          thoughtBuffer += delta.content;
          // Ensure consistent attribute naming in the WebSocket update
          sendWebSocketUpdate(userId, { 
            event: 'thoughtUpdate', 
            taskId, // This is the key attribute - must be consistently named
            thought: delta.content 
          });
        }
        
        if (delta?.tool_calls) {
          for (const toolCallDelta of delta.tool_calls) {
            if (toolCallDelta.index === 0) {
              if (toolCallDelta.function.name && !currentFunctionCall) {
                currentFunctionCall = { name: toolCallDelta.function.name };
                accumulatedArgs = '';
                if (thoughtBuffer) {
                  sendWebSocketUpdate(userId, { event: 'thoughtComplete', taskId, thought: thoughtBuffer });
                  thoughtBuffer = '';
                }
                plan.log(`New tool call started: ${currentFunctionCall.name}`);
                
                // Check if we've reached the maximum steps limit (10 steps)
                // If so, we need to make sure a task_complete is forced if this function call isn't it
                const MAX_STEPS = user?.maxSteps;
                if (plan.steps.length >= MAX_STEPS - 1 && currentFunctionCall.name !== 'task_complete') {
                  plan.log(`WARNING: Reached maximum steps (${MAX_STEPS}). Will force task_complete after this step.`);
                  // Set flag to force task_complete after this function call completes
                  plan.forceTaskComplete = true;
                }
              }
              if (toolCallDelta.function.arguments) {
                accumulatedArgs += toolCallDelta.function.arguments;
                sendWebSocketUpdate(userId, {
                  event: 'functionCallPartial',
                  taskId,
                  functionName: currentFunctionCall?.name,
                  partialArgs: accumulatedArgs
                });
                try {
                  const parsedArgs = JSON.parse(accumulatedArgs);
                  functionCallReceived = true;
                  plan.log(`Function call received: ${currentFunctionCall.name}`, parsedArgs);
                  
                  // Check if we need to force task_complete after this function call
                  const needsForceComplete = plan.forceTaskComplete === true && currentFunctionCall.name !== 'task_complete';
                  
                  // Handle different function types
                  if (currentFunctionCall.name === "browser_action") {
                    const step = plan.createStep('action', parsedArgs.command, parsedArgs);
                    const result = await step.execute(plan);
                    await addIntermediateResult(userId, taskId, result);
                    consecutiveFailures = result.success ? 0 : consecutiveFailures + 1;
                    // Force task_complete if we've reached max steps
                    if (needsForceComplete) {
                      plan.log("Forcing task_complete after this step");
                      // Mark as completed with max steps reached summary
                      const summary = `Task reached maximum steps (20) without explicit completion. Current URL: ${plan.currentUrl || 'N/A'}`;
                      plan.markCompleted(summary, true); // true indicates this was forced
                      
                      // Process task completion
                      const finalResult = await processTaskCompletion(
                        userId,
                        taskId,
                        plan.steps.map(step => step.result || { success: false }),
                        prompt,
                        runDir,
                        runId,
                        plan
                      );
                      
                      // Set the maxStepsReached flag for client awareness
                      finalResult.maxStepsReached = true;
                      
                      // IMPORTANT: Use the original summary from task_complete as the sole source of truth
                      // This fixes inconsistency between different summary sources
                      const aiSummary = summary; // Use the summary from task_complete
                      
                      // Ensure screenshot URL and report URLs are properly included in the task result
                      const enhancedResult = {
                        ...finalResult,
                        // Make sure all screenshot and report URLs are consistently available
                        screenshot: finalResult.screenshot || finalResult.screenshotPath || null,
                        screenshotPath: finalResult.screenshotPath || finalResult.screenshot || null,
                        screenshotUrl: finalResult.screenshotUrl || finalResult.screenshotPath || finalResult.screenshot || null,
                        nexusReportUrl: finalResult.nexusReportUrl || null,
                        landingReportUrl: finalResult.landingReportUrl || null
                      };
                      
                      await Task.updateOne(
                        { _id: taskId },
                        { 
                          $set: { 
                            status: 'completed', 
                            progress: 100, 
                            maxStepsReached: true,
                            result: enhancedResult,
                            endTime: new Date(),
                            summary: aiSummary, // Store the AI-prepared summary in the task record
                            // Also store screenshot and report URLs at the top level for easier access
                            screenshotUrl: enhancedResult.screenshotUrl,
                            screenshotPath: enhancedResult.screenshotPath,
                            nexusReportUrl: enhancedResult.nexusReportUrl,
                            landingReportUrl: enhancedResult.landingReportUrl
                          } 
                        }
                      );
                      
                      // Use the shared function to save task completion messages consistently
                      // This will use the AI-prepared summary instead of a generic message
                      await saveTaskCompletionMessages(
                        userId,
                        taskId,
                        prompt,
                        aiSummary, // Use the rich AI summary
                        aiSummary, // Prioritize AI summary
                        {
                          // Pass all relevant data to the shared function
                          nexusReportUrl: finalResult.nexusReportUrl,
                          landingReportUrl: finalResult.landingReportUrl,
                          errorReportUrl: finalResult.errorReportUrl || null,
                          screenshot: finalResult.screenshot || finalResult.screenshotPath || null,
                          screenshotPath: finalResult.screenshotPath || finalResult.screenshot || null,
                          maxStepsReached: true,
                          completedAt: new Date().toISOString()
                        }
                      );
                      
                      taskCompleted = true;
                      break; // Exit the loop since we've forced completion
                    }
                    
                    if (consecutiveFailures >= 3) {
                      plan.log("Triggering recovery due to consecutive failures");
                      const recoveryStep = plan.createStep('query', 'Suggest a new approach to achieve this command: ', {
                        query: parsedArgs.command,
                        task_id: taskId,
                        url: plan.currentUrl
                      });
                      await recoveryStep.execute(plan);
                      consecutiveFailures = 0;
                    }
                    functionCallReceived = true;
                    break;
                  } else if (currentFunctionCall.name === "browser_query") {
                    const step = plan.createStep('query', parsedArgs.query, parsedArgs);
                    const result = await step.execute(plan);
                    await addIntermediateResult(userId, taskId, result);
                    consecutiveFailures = 0;
                    functionCallReceived = true;
                    
                    // In action-planning mode, we might want to automatically follow up with actions
                    // based on the query results without requiring additional back-and-forth
                    if (executionMode === 'action-planning' && result.success) {
                      plan.log("Action-planning mode: analyzing query results for potential follow-up actions");
                    }
                    
                    break;
                  } else if (currentFunctionCall.name === "task_complete") {
                    const summary = parsedArgs.summary || `Task completed: ${prompt}`;
                    plan.markCompleted(summary);
                    const finalResult = await processTaskCompletion(
                      userId,
                      taskId,
                      plan.steps.map(step => step.result || { success: false }),
                      prompt,
                      runDir,
                      runId,
                      plan
                    );
                    const finalExtracted = (finalResult.raw && finalResult.raw.pageText && 
                                            cleanForPrompt(finalResult.raw.pageText).length > 0)
                      ? cleanForPrompt(finalResult.raw.pageText)
                      : (finalResult.aiPrepared && finalResult.aiPrepared.summary && 
                         cleanForPrompt(finalResult.aiPrepared.summary).length > 0)
                        ? cleanForPrompt(finalResult.aiPrepared.summary)
                        : `Task completed: ${prompt}`;
                    // Log screenshot information from finalResult for debugging
                    console.log(`[Task ${taskId}] Final result screenshot data:`, {
                      screenshot: finalResult.screenshot,
                      screenshotPath: finalResult.screenshotPath,
                      hasScreenshot: !!finalResult.screenshot
                    });
                    
                    const cleanedFinal = {
                      success: finalResult.success,
                      // Prioritize nexus report URL over current URL for user consumption
                      currentUrl: finalResult.raw?.url || finalResult.currentUrl,
                      // Store both report URLs explicitly for easy access
                      nexusReportUrl: finalResult.nexusReportUrl,
                      landingReportUrl: finalResult.landingReportUrl,
                      // Original URL is still important for context
                      originalUrl: finalResult.raw?.url || finalResult.currentUrl,
                      extractedInfo: finalExtracted,
                      // Store screenshot in standard property names
                      screenshot: finalResult.screenshot,
                      screenshotUrl: finalResult.screenshot,
                      screenshotPath: finalResult.screenshot,
                      timestamp: new Date()
                    };

                    // IMPORTANT: Use the original summary from task_complete as the sole source of truth
                    // This ensures consistency between different parts of the application
                    // Only fall back to other sources if summary is empty
                    const aiSummary = summary && summary.trim().length > 0
                        ? summary  // Use the original summary from task_complete as primary source
                        : (finalResult.aiPrepared?.summary && finalResult.aiPrepared?.summary.trim().length > 0
                            ? finalResult.aiPrepared.summary
                            : finalExtracted);
                    
                    // Store the rich AI summary directly in the task result object
                    // so it can be accessed later without additional database lookups
                    cleanedFinal.aiSummary = aiSummary;
                    
                    // CRITICAL FIX: Ensure screenshot URLs are properly logged for debugging
                    console.log(`[Task ${taskId}] Final cleanedFinal screenshot data after processing:`, {
                      screenshot: cleanedFinal.screenshot,
                      screenshotUrl: cleanedFinal.screenshotUrl,
                      screenshotPath: cleanedFinal.screenshotPath,
                      hasScreenshot: !!cleanedFinal.screenshot
                    });
                    
                    // Update the task with the complete result including the AI summary
                    await Task.updateOne(
                      { _id: taskId },
                      { 
                        $set: { 
                          status: 'completed', 
                          progress: 100, 
                          result: cleanedFinal, 
                          endTime: new Date(),
                          // Also store these fields at the top level for easier access by ChatHistory
                          screenshotUrl: cleanedFinal.screenshotUrl,
                          screenshotPath: cleanedFinal.screenshotPath,
                          nexusReportUrl: cleanedFinal.nexusReportUrl,
                          landingReportUrl: cleanedFinal.landingReportUrl,
                          aiSummary: aiSummary
                        } 
                      }
                    );

                    // Use the shared function to save task completion messages consistently
                    await saveTaskCompletionMessages(
                      userId,
                      taskId,
                      prompt,
                      finalExtracted, // Original fallback content
                      aiSummary, // CRITICAL: Use the same summary that was stored in the task document
                      {
                        // Pass all relevant data to the shared function - use cleanedFinal which has normalized URLs
                        nexusReportUrl: cleanedFinal.nexusReportUrl,
                        landingReportUrl: cleanedFinal.landingReportUrl,
                        originalUrl: cleanedFinal.originalUrl || finalResult.raw?.url || finalResult.currentUrl,
                        // Use consistent screenshot path/URL values from the cleaned result
                        screenshot: cleanedFinal.screenshot,
                        screenshotPath: cleanedFinal.screenshotPath,
                        screenshotUrl: cleanedFinal.screenshotUrl,
                        maxStepsReached: finalResult.maxStepsReached || plan.forceTaskComplete || false,
                        completedAt: new Date().toISOString()
                      }
                    );
                    
                    // Log the consistent values used for debugging
                    console.log(`[Task ${taskId}] Using consistent values for task completion:`, {
                      summary: aiSummary.substring(0, 100) + '...',
                      nexusReportUrl: cleanedFinal.nexusReportUrl,
                      landingReportUrl: cleanedFinal.landingReportUrl,
                      screenshotUrl: cleanedFinal.screenshotUrl
                    });
                    
                    // CRITICAL: Send thought completion event with content
                    // This is what makes the thought bubble show the content in the UI
                    try {
                      sendWebSocketUpdate(userId, {
                        event: 'thoughtComplete',
                        taskId: taskId.toString(),
                        text: aiSummary, // This is the content that should show in the thought bubble
                        thought: aiSummary // Fallback for older clients
                      });
                      console.log(`[Task ${taskId}] Sent thought completion with content: ${aiSummary.substring(0, 100)}...`);
                    } catch (wsError) {
                      console.error(`[Task ${taskId}] Error sending thought completion:`, wsError);
                    }
                    
                    console.log(`[Task ${taskId}] Stored AI summary in task result: ${aiSummary.substring(0, 100)}...`);
                    
                    console.log(`[Task ${taskId}] Saved assistant message with summary: ${summary} and reports:`, {
                      nexusReport: finalResult.nexusReportUrl || cleanedFinal.nexusReportUrl,
                      landingReport: finalResult.landingReportUrl || cleanedFinal.landingReportUrl
                    });
                    taskCompleted = true;
                    break;
                  }
                } catch (e) {
                  // Continue accumulating if JSON is incomplete
                }
              }
            }
          }
        }}
      
        if (thoughtBuffer) {
          sendWebSocketUpdate(userId, { event: 'thoughtComplete', taskId, thought: thoughtBuffer });
          thoughtBuffer = "";
        }
      
        if (taskCompleted) {
          plan.log(`Task completed after ${plan.currentStepIndex + 1} steps.`);
          break;
        }
      
        if (!functionCallReceived) {
          plan.log(`No tool call received for step ${plan.currentStepIndex + 1}`);
          const recoveryStep = plan.createStep('query', 'Describe the current page state and available actions', {
            query: 'Describe the current page state and available actions',
            task_id: taskId,
            url: plan.currentUrl
          });
          await recoveryStep.execute(plan);
          consecutiveFailures = 0;
        }
      
        const progress = Math.min(95, Math.floor((plan.currentStepIndex + 1) / plan.maxSteps * 100));
        await Task.updateOne(
          { _id: taskId },
          { $set: { status: 'running', progress, currentStepIndex: plan.currentStepIndex, currentUrl: plan.currentUrl } }
        );
        plan.log(`Task progress updated in DB: ${progress}%`);
    }
    
    if (!taskCompleted) {
      const summary = `Task reached maximum steps (${plan.maxSteps}) without explicit completion. Current URL: ${plan.currentUrl}`;
      plan.markCompleted(summary);
      const finalResult = await processTaskCompletion(
        userId,
        taskId,
        plan.steps.map(step => step.result || { success: false }),
        prompt,
        runDir,
        runId,
        plan  // Pass the full task plan for detailed reporting
      );
      
      await Task.updateOne(
        { _id: taskId },
        { $set: { status: 'completed', progress: 100, result: finalResult, endTime: new Date(), summary } }
      );
      
      // Use the shared function to save task completion messages consistently
      await saveTaskCompletionMessages(
        userId,
        taskId,
        prompt,
        summary, // Pass the summary as contentText in case there's no AI summary
        finalResult.aiPrepared?.summary || summary, // Prioritize AI-prepared summary
        {
          // Pass all relevant data to the shared function
          nexusReportUrl: finalResult.nexusReportUrl,
          landingReportUrl: finalResult.landingReportUrl,
          errorReportUrl: finalResult.errorReportUrl || null,
          screenshot: finalResult.screenshot || finalResult.screenshotPath || null,
          screenshotPath: finalResult.screenshotPath || finalResult.screenshot || null,
          maxStepsReached: true,
          completedAt: new Date().toISOString()
        }
      );
    }
  } catch (error) {
    console.error(`[ProcessTask] Error in task ${taskId}:`, error);
    plan.log(`Error encountered: ${error.message}`, { stack: error.stack });
    
    // Send both error and completion events
    sendWebSocketUpdate(userId, {
      event: 'taskError',
      taskId,
      error: error.message,
      log: plan.planLog.slice(-10)
    });
    
    // Send taskComplete event with error status
    sendWebSocketUpdate(userId, {
      event: 'taskComplete',
      taskId: taskId.toString(),
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
    
    await Task.updateOne(
      { _id: taskId },
      { $set: { status: 'error', error: error.message, endTime: new Date() } }
    );
    
    // --- Save error message as assistant message to both ChatHistory and Message ---
    let taskChatHistory = await ChatHistory.findOne({ userId });
    if (!taskChatHistory) taskChatHistory = new ChatHistory({ userId, messages: [] });
    taskChatHistory.messages.push({
      role: 'assistant',
      content: `Error: ${error.message}`,
      timestamp: new Date()
    });
    await taskChatHistory.save();
    await Message.create({
      userId,
      role: 'assistant',
      type: 'command',
      content: `Error: ${error.message}`,
      taskId,
      timestamp: new Date(),
      meta: { error: error.message }
    });
    // -------------------------------------------------------------
  } finally {
    console.log(`[ProcessTask] Task ${taskId} finished with ${plan.steps.length} steps executed.`);
    
    try {
      await Task.updateOne(
        { _id: taskId },
        { $set: { planSummary: plan.getSummary(), stepsExecuted: plan.steps.length } }
      );
      plan.log("Plan summary saved to database.");
    } catch (dbError) {
      console.error(`[ProcessTask] Error saving plan summary:`, dbError);
    }
  }
}

function cleanForPrompt(data) {
  if (data == null) return "";
  let str = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  // Remove known placeholder text
  if (str.trim() === "Structured data") return "";
  return str.trim();
}

/**
 * Track token usage for a user
 * @param {string} userId - User ID
 * @param {number} tokensUsed - Number of tokens used
 * @param {string} model - LLM model used
 */
async function trackTokenUsage(userId, tokensUsed, model = 'gpt-4o') {
  try {
    if (!userId || tokensUsed <= 0) return;
    
    // Find or create billing record
    let billing = await Billing.findOne({ userId });
    
    if (!billing) {
      billing = new Billing({
        userId,
        tokens: { used: 0, available: 1000 }, // Start with 1000 free tokens
        requests: { count: 0, limit: 100 },
        plan: 'free'
      });
    }
    
    // Update token usage
    billing.tokens.used += tokensUsed;
    
    // Add transaction for usage
    billing.transactions.push({
      type: 'usage',
      amount: tokensUsed / 1000, // Amount in USD equivalent
      tokens: tokensUsed,
      timestamp: new Date(),
      details: `Used ${tokensUsed} tokens with model ${model}`
    });
    
    // Increment request count
    billing.requests.count += 1;
    
    await billing.save();
    console.log(`Updated token usage for user ${userId}: +${tokensUsed} tokens used`);
    
    // Check if user is out of tokens
    if (billing.tokens.available <= billing.tokens.used && billing.plan !== 'free') {
      console.warn(`User ${userId} has used all available tokens`);
      // Here you could implement logic to notify the user or restrict access
    }
  } catch (err) {
    console.error('Error tracking token usage:', err);
  }
}

/**
 * Helper function to add intermediate results to a task
 * @param {string} userId - User ID
 * @param {string} taskId - Task ID
 * @param {Object} result - Result to add
 */
async function addIntermediateResult(userId, taskId, result) {
  try {
    // Only keep fields you care about, truncating any large text.
    const cleanedResult = {
      success: result.success,
      currentUrl: result.currentUrl,
      extractedInfo: typeof result.extractedInfo === 'string'
        ? result.extractedInfo
        : 'Complex data omitted',
      navigableElements: Array.isArray(result.navigableElements) 
        ? result.navigableElements.slice(0, 30) 
        : [],
      screenshotPath: result.screenshotPath,  // Only store path/URL, not raw base64
      timestamp: new Date()
    };

    await Task.updateOne(
      { _id: taskId },
      { 
        $push: { intermediateResults: cleanedResult },
        $set: {
          currentUrl: result.currentUrl,
          lastUpdate: new Date()
        }
      }
    );
  } catch (error) {
    console.error(`[addIntermediateResult] Error:`, error);
  }
}

async function extractRichPageContext(agent, page, currentUrl, command, query) {
  const domainType = detectDomainType(currentUrl);
  const domainSpecificPrompt = generateDomainSpecificPrompt(domainType);
  
  const combinedQuery = `
After executing "${command}", thoroughly analyze the page and return a JSON object with the following structure:
{
  "main_content": "Describe the main content visible on the page (listed information, products, tokens, prices, titles, important information).",
  "navigable_elements": [
    "List ALL clickable and navigable elements with their EXACT text as shown on screen."
  ],
  "interactive_controls": [
    "List ALL interactive controls (sliders, toggles, filters, etc.) with their EXACT labels if visible."
  ],
  "data_visualization": [
    "List ALL chart controls, time selectors, indicator buttons with their EXACT labels. Detail chart type (line or graph)"
  ],
  "product_filters": [
    "List ALL product filtering options with their EXACT labels."
  ],
  "search_fields": [
    "List any search fields or input areas with their placeholder text."
  ],
  "pagination": "Describe any pagination controls."
}

${domainSpecificPrompt}

Always outline in Great Detail the main page content on center of page.  
Always read Key information in the sidebars if present.
For news and documents focus on main content.
For products and cryptocurrency focus on Description, Symbols, Names, Prices, Lists, and any other relevant information.

IGNORE ALL IMAGES of phones, laptops, devices, billboards, or any marketing images simulating data presentation.
Describe charts or graphs including Chart heading, chart type (line/bar/candlestick), time frame, and any other relevant information.
Ensure you return valid JSON. If any field is not present, return an empty string or an empty array as appropriate.
[END OF INSTRUCTION]
${query}
  `;
 
  try {
    let extractedInfo = await agent.aiQuery(combinedQuery, { domIncluded: true },);
    if (typeof extractedInfo !== 'string') {
      if (extractedInfo && typeof extractedInfo === 'object') {
        const pageContent = extractedInfo.main_content || "No content extracted";
        const navigableElements = [
          ...(Array.isArray(extractedInfo.navigable_elements) ? extractedInfo.navigable_elements : []),
          ...(Array.isArray(extractedInfo.interactive_controls) ? extractedInfo.interactive_controls : []),
          ...(Array.isArray(extractedInfo.data_visualization) ? extractedInfo.data_visualization : []),
          ...(Array.isArray(extractedInfo.product_filters) ? extractedInfo.product_filters : [])
        ];
        return { pageContent, navigableElements };
      }
      return { pageContent: "No content extracted", navigableElements: [] };
    }
    
    let pageContent = extractedInfo;
    let navigableElements = [];
    try {
      const sections = extractedInfo.split(/(?:\r?\n){1,}/);
      const elementKeywords = [
        "clickable", "navigable", "button", "link", "menu", "filter", "toggle", 
        "checkbox", "select", "dropdown", "chart", "control", "tab", "icon",
        "slider", "candlestick", "time frame", "period", "indicator"
      ];
      
      for (const section of sections) {
        if (elementKeywords.some(keyword => section.toLowerCase().includes(keyword))) {
          const newElements = section.split(/\r?\n/)
                                    .filter(line => line.trim())
                                    .map(line => line.trim());
          navigableElements = [...navigableElements, ...newElements];
        }
      }
      navigableElements = [...new Set(navigableElements)];
    } catch (parseError) {
      console.log("[Rich Context] Error parsing navigable elements:", parseError);
    }
   
    return { 
      pageContent: pageContent || "No content extracted", 
      navigableElements 
    };
  } catch (queryError) {
    console.error(`[Rich Context] Error in AI query:`, queryError);
    return { pageContent: "Error extracting page content: " + queryError.message, navigableElements: [] };
  }
}

function detectDomainType(url) {
  const urlLower = url.toLowerCase();
  
  if (urlLower.includes('dextools') || urlLower.includes('dexscreener') ||
      urlLower.includes('coinbase') || urlLower.includes('coingecko') ||
      urlLower.includes('coinmarketcap') || urlLower.includes('binance') ||
      urlLower.includes('jupiterexchange')) {
    return 'cryptoSpecial';
  }
  if (urlLower.includes('amazon') || urlLower.includes('ebay') || 
      urlLower.includes('walmart') || urlLower.includes('etsy')) {
    return 'ecommerce';
  }
  if (urlLower.includes('twitter') || urlLower.includes('facebook') ||
      urlLower.includes('instagram') || urlLower.includes('tiktok')) {
    return 'social';
  }
  return 'general';
}

function generateDomainSpecificPrompt(domainType) {
  if (domainType === 'cryptoSpecial') {
    return `
CRYPTO SPECIAL INTERFACE DETECTED (e.g., Dextools, Dexscreener, Coinbase, Coingecko, Coinmarketcap, Jupiter Exchange):
- Note the side menus, top navigation bars, and dashboard sections.
- Identify buttons such as "Trade", "Charts", "Market", "Analysis".
- Include any filtering dropdowns, time frame selectors, and graph toggles.
- List any visible token names in a list, token labels or information links.
    `;
  } else if (domainType === 'ecommerce') {
    return `
ECOMMERCE SITE DETECTED: Focus on product filters, sort options, "Add to cart" buttons, and product variations.
    `;
  } else if (domainType === 'social') {
    return `
SOCIAL MEDIA SITE DETECTED: Focus on post creation, reply/comment buttons, and timeline navigation controls.
    `;
  } else {
    return `
GENERAL SITE DETECTED: Be comprehensive in finding all interactive elements to navigate this type of website. Emphasize clickable links, menus, and controls.
    `;
  }
}

async function waitForPageStability(page, timeout = 10000) {
  await page.waitForFunction(() => {
    return document.readyState === 'complete' && 
           !document.querySelector('[aria-busy="true"]') &&
           window.jQuery ? window.jQuery.active === 0 : true;
  }, { timeout, polling: 200 });
}

/**
 * Advanced popup and obstacle handler for web browsing
 * @param {Object} page - Puppeteer page object
 * @param {Object} agent - Browser agent
 * @returns {Object} - Result of the preparation
 */
async function handlePageObstacles(page, agent) {
  console.log(`🔍 [Obstacles] Checking for page obstacles...`);
  const results = {
    obstacles: [],
    actionsAttempted: [],
    success: false
  };

  try {
    // Wait for page to be stable
    await waitForPageStability(page);

    // Listen for any dialogs (alerts, confirms, prompts) and auto-accept them.
    page.on('dialog', async (dialog) => {
      try {
        console.log(`🔔 [Obstacles] Dialog detected: ${dialog.type()} - ${dialog.message()}`);
        results.obstacles.push(`Dialog: ${dialog.type()} - ${dialog.message()}`);
        await dialog.accept();
        results.actionsAttempted.push(`Accepted ${dialog.type()} dialog`);
      } catch (e) {
        console.warn('Failed to dismiss dialog:', e.message);
      }
    });

    // Prepare a text instruction prompt for obstacles.
    const obstacleCheckPrompt = `
      Analyze the current page for common obstacles such as:
      1. Cookie consent banners,
      2. Newsletter signup modals,
      3. Login walls,
      4. Captcha or Turnstile challenges,
      5. Overlays or popups blocking content.
      
      For each obstacle, list any dismiss button text visible (e.g., "Accept", "Close", "No thanks"). If no obstacles or popups are found, return "no obstacles" or "none detected" only.
      Return a structured answer.
    `;
    
    // Execute the obstacle detection query.
    let obstacles = await agent.aiQuery(obstacleCheckPrompt);
    // Normalize obstacles to text regardless of whether it comes as a string or object.
    let obstaclesText = '';
    if (typeof obstacles === 'string') {
      obstaclesText = obstacles;
    } else if (typeof obstacles === 'object') {
      obstaclesText = JSON.stringify(obstacles, null, 2);
    } else {
      obstaclesText = String(obstacles);
    }
    
    // If no obstacles are detected in text, mark success.
    if (typeof obstaclesText === 'string' &&
        (obstaclesText.toLowerCase().includes('no obstacles') ||
         obstaclesText.toLowerCase().includes('none detected'))) {
      console.log(`✅ [Obstacles] No obstacles detected.`);
      results.success = true;
      return results;
    }
    
    // Otherwise, log the detected obstacles.
    console.log(`⚠️ [Obstacles] Detected: ${obstaclesText.slice(0, 150)}...`);
    results.obstacles.push(obstaclesText);
    
    // Define a list of dismissal actions to attempt.
    const dismissActions = [
      "Find and click 'Accept', 'Accept All', 'I Accept', 'I Agree', or 'Agree'",
      "Find and click 'Continue', 'Close', 'Got it', 'I understand', or 'OK'",
      "Look for and click 'X', 'Close', 'Skip', 'No thanks', or 'Maybe later'",
      "If a CAPTCHA is present, attempt to solve or reload the challenge",
      "Try pressing the 'Escape' key or clicking outside a modal"
    ];
    
    let attemptCount = 0;
    const maxAttempts = 3; // Limit the number of times to retry a single dismiss action.
    
    // Iterate over each dismissal action.
    for (const action of dismissActions) {
      attemptCount = 0;
      let cleared = false;
      while (attemptCount < maxAttempts) {
        try {
          console.log(`🔧 [Obstacles] Attempting dismissal: ${action}`);
          results.actionsAttempted.push(action);
          // Run command
          await agent.aiAction(action);
          
          // Check if obstacles are still present.
          const recheck = await agent.aiQuery("Are there any popups, overlays, or banners blocking the main content?");
          if (typeof recheck === 'string' && 
              (recheck.toLowerCase().includes('no') || 
               recheck.toLowerCase().includes('cleared') ||
               recheck.toLowerCase().includes('gone'))) {
            console.log(`✅ [Obstacles] Cleared with action: ${action}`);
            results.success = true;
            cleared = true;
            break;
          }
        } catch (dismissError) {
          console.log(`❌ [Obstacles] Dismissal error on attempt ${attemptCount + 1} for action "${action}": ${dismissError.message}`);
        }
        attemptCount++;
      }
      if (cleared) break;
    }
    
    if (!results.success) {
      console.log(`⚠️ [Obstacles] Unable to clear obstacles after ${maxAttempts * dismissActions.length} attempts.`);
    }
    
    return results;
  } catch (error) {
    console.error(`❌ [Obstacles] Error during obstacle handling: ${error.message}`);
    results.obstacles.push(`Error: ${error.message}`);
    return results;
  }
}

// --- Helper: Ensure userId is present in session, generate guest if needed ---
function ensureUserId(req, res, next) {
  if (!req.session.user) {
    req.session.user = 'guest_' + Date.now() + '_' + Math.floor(Math.random()*100000);
    console.debug('[DEBUG] ensureUserId: Generated guest userId', req.session.user);
  } else {
    console.debug('[DEBUG] ensureUserId: Found userId in session', req.session.user);
  }
  next();
}

// Set-engine route has been moved to src/routes/user.js
// --- API: Who Am I (userId sync endpoint) ---
app.get('/api/whoami', (req, res) => {
  try {
    let userId = null;
    if (req.session && req.session.user) {
      userId = req.session.user;
      console.debug('[whoami] Returning userId from session:', userId);
    } else if (req.session) {
      userId = 'guest_' + Date.now() + '_' + Math.floor(Math.random()*100000);
      req.session.user = userId;
      console.debug('[whoami] Generated new guest userId:', userId);
    } else {
      // Session middleware is broken or not present
      userId = 'guest_' + Date.now() + '_' + Math.floor(Math.random()*100000);
      console.warn('[whoami] WARNING: req.session missing, returning fallback guest userId:', userId);
    }
    res.json({ userId });
  } catch (err) {
    console.error('[whoami] ERROR:', err);
    res.status(500).json({ error: 'Failed to get userId', detail: err.message });
  }
});

// --- Robust API: Who Am I (no /api prefix, for proxy rewrite) ---
app.get('/whoami', (req, res) => {
  try {
    let userId = null;
    if (req.session && req.session.user) {
      userId = req.session.user;
      console.debug('[whoami] Returning userId from session:', userId);
    } else if (req.session) {
      userId = 'guest_' + Date.now() + '_' + Math.floor(Math.random()*100000);
      req.session.user = userId;
      console.debug('[whoami] Generated new guest userId:', userId);
    } else {
      userId = 'guest_' + Date.now() + '_' + Math.floor(Math.random()*100000);
      console.warn('[whoami] WARNING: req.session missing, returning fallback guest userId:', userId);
    }
    res.json({ userId });
  } catch (err) {
    console.error('[whoami] ERROR:', err);
    res.status(500).json({ error: 'Failed to get userId', detail: err.message });
  }
});

/**
 * Unified NLI endpoint (DUPLICATE REMOVED):
 * NOTE: See the main implementation of this route at line ~5561
 */

// --- Unified Message Retrieval Endpoint (backward compatible) ---
app.get('/api/messages', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const limit = parseInt(req.query.limit, 10) || 20;
    // New schema: unified Message collection
    let messages = await Message.find({ userId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean();
    // Backward compatibility: if empty, try ChatHistory
    if (!messages.length) {
      const chatHistory = await ChatHistory.findOne({ userId });
      if (chatHistory && chatHistory.messages) {
        messages = chatHistory.messages.slice(-limit).reverse().map(m => ({
          userId,
          role: m.role,
          type: 'chat',
          content: m.content,
          timestamp: m.timestamp || null,
          legacy: true
        }));
      }
    }
    return res.json({ success: true, messages: messages.reverse() }); // oldest first
  } catch (err) {
    console.error('[GET /messages] Error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Helper: async generator for streaming thought (and tool) events
async function* streamNliThoughts(userId, prompt) {
  console.log('[streamNliThoughts] Starting stream for user:', userId);
  
  // Persist user prompt
  await new Message({ userId, role: 'user', type: 'chat', content: prompt, timestamp: new Date() }).save();

  // Enhanced context builder (existing code)
  async function getEnhancedChatHistory(userId, limit = 20) {
    console.log(`[Chat] Getting enhanced history for user ${userId} with limit ${limit}`);
    
    const messages = await Message.find({ 
      userId, 
      $or: [
        { role: { $in: ['user','assistant'] }, type: 'chat' },
        { role: 'assistant', type: 'command' }
      ]
    })
    .sort({ timestamp: -1 })
    .limit(limit)
    .lean();
    
    console.log(`[Chat] Found ${messages.length} messages for history, including task results`);
    
    return messages.map(msg => {
      if (msg.type === 'command' && msg.meta) {
        let enhancedContent = msg.content;
        
        const hasReports = msg.meta.nexusReportUrl || msg.meta.landingReportUrl;
        
        if (hasReports) {
          enhancedContent += '\n\nTask Reports Available:';
          if (msg.meta.nexusReportUrl) {
            enhancedContent += `\n- Analysis Report: ${msg.meta.nexusReportUrl}`;
          }
          if (msg.meta.landingReportUrl) {
            enhancedContent += `\n- Landing Page Report: ${msg.meta.landingReportUrl}`;
          }
          console.log(`[Chat] Enhanced task result with report URLs for message ${msg._id}`);
        }
        
        return {
          role: msg.role,
          content: enhancedContent
        };
      }
      
      return {
        role: msg.role,
        content: msg.content
      };
    });
  }
  
  const history = await getEnhancedChatHistory(userId, 20);
  console.log(`[Chat] Using ${history.length} messages for context, including task results`);
  
  let buffer = '';
  let fullReply = '';
  
  const openaiClient = await getUserOpenAiClient(userId);
  
  let chatModel = 'gpt-4o';
  if (openaiClient.defaultQuery?.engine) {
    chatModel = openaiClient.defaultQuery.engine;
  }
  
  console.log(`[Chat] Creating stream with model: ${chatModel}`);
  
  const systemMessage = `You are Nexus, an AI assistant with chat and task capabilities. For general conversation, 
  simply respond helpfully and clearly. DO NOT use tools unless the user explicitly asks for a task, web search, 
  or cryptocurrency information.

Only use tools when:
- The user asks you to perform a web task (use process_task)`;
  
  const standardTools = [
    {
      type: "function",
      function: {
        name: "process_task",
        description: "Process and execute a web browser task",
        parameters: {
          type: "object",
          properties: {
            command: {
              type: "string",
              description: "The browser task to execute, e.g. 'navigate to google.com and search for cats'"
            }
          },
          required: ["command"]
        }
      }
    }
  ];
  
  try {
    const reversedHistory = [...history].reverse();
    
    const fullHistory = [
      { role: 'system', content: systemMessage },
      ...reversedHistory,
      { role: 'user', content: prompt }
    ];
    
    console.log('[Chat] Sending messages in correct chronological order to the AI');
    
    const stream = await openaiClient.chat.completions.create({
      model: chatModel,
      messages: fullHistory,
      stream: true,
      temperature: 0.7,
      max_tokens: 700,
      tools: standardTools
    });
    
    console.log('[streamNliThoughts] Stream created, beginning iteration...');
    
    for await (const chunk of stream) {
      const delta = chunk.choices[0]?.delta;
      
      if (delta?.content) {
        buffer += delta.content;
        fullReply += delta.content;
        console.log('[streamNliThoughts] Yielding thoughtUpdate:', delta.content.substring(0, 20) + '...');
        yield { event: 'thoughtUpdate', text: delta.content };
        if (/[.?!]\s$/.test(buffer) || buffer.length > 80) buffer = '';
      }
      
      // Tool call handling (existing code - keeping as is but adding logs)
      if (delta?.tool_calls) {
        console.log('[streamNliThoughts] Processing tool calls...');
        // ... existing tool call code ...
      }
    }
    
    const responseText = fullReply.trim().length > 0 
      ? fullReply 
      : 'I apologize, but I encountered an issue generating a response. Please try again.';
    
    console.log(`[streamNliThoughts] Sending final response of length: ${responseText.length}`);
    
    // FIXED: Always yield thoughtComplete
    yield { 
      event: 'thoughtComplete', 
      text: responseText 
    };
    
    // Save response to history
    if (responseText.trim().length > 0) {
      try {
        await new Message({
          userId,
          role: 'assistant',
          type: 'chat',
          content: responseText,
          timestamp: new Date()
        }).save();
        console.log(`[Chat] Saved assistant response to message history`);
      } catch (saveError) {
        console.error(`[Chat] Error saving assistant response:`, saveError);
      }
    }
    
    // Clear tool calls
    if (global.toolCallsInProgress) {
      global.toolCallsInProgress.clear();
      console.log('[Chat] Cleared any pending tool calls');
    }
    
  } catch (error) {
    console.error('[streamNliThoughts] Error occurred:', error);
    
    // FIXED: Better quota error detection
    const isQuotaError = (err) => {
      if (!err) return false;
      
      if (err.status === 429) return true;
      
      const errorStr = (err.message || '').toLowerCase() + 
                     (err.code ? ' ' + err.code.toString().toLowerCase() : '') +
                     (err.error?.code ? ' ' + err.error.code.toString().toLowerCase() : '');
      
      const quotaIndicators = [
        'quota', 'rate limit', 'rate_limit', 'too many requests',
        'insufficient_quota', 'billing', 'credit', 'limit reached',
        '429', 'usage limit', 'usage_limit', 'quota exceeded',
        'insufficient_quota', 'billing_not_active', 'quota_exceeded'
      ];
      
      return quotaIndicators.some(indicator => errorStr.includes(indicator.toLowerCase()));
    };

    const isAuthError = (err) => [401, 403].includes(err?.status) || 
      ['auth', 'api key', 'api_key', 'invalid', 'unauthorized'].some(term => 
        String(err?.message || '').toLowerCase().includes(term)
      ) || ['invalid_api_key', 'invalid_request_error'].includes(err?.code);

    if (isQuotaError(error)) {
      const provider = openaiClient?.defaultQuery?.provider || 'OpenAI';
      const errorDetails = error.error?.message || error.message || 'API quota exceeded';
      const errorMessage = `[Quota Error] ${provider} API: ${errorDetails}`;
      console.error(errorMessage);
      
      try {
        console.log('[streamNliThoughts] Yielding quota error event');
        yield {
          event: 'quotaExceeded',
          text: `🚫 API Quota Exceeded: ${errorDetails}. ` +
                'Please check or add a valid API key in settings.'
        };
        
        yield {
          event: 'thoughtComplete',
          text: 'I apologize, system fallback API key hit a limit. Please Add your own valid API key in settings to continue using the agent.',
          isError: true,
          errorType: 'quotaExceeded'
        };
        
        await new Message({
          userId,
          role: 'assistant',
          type: 'chat',
          content: 'I apologize, system fallback API key hit a limit. Please Add your own valid API key in settings to continue using the agent.',
          timestamp: new Date()
        }).save();
        
        console.log('[streamNliThoughts] Quota error handling completed');
      } catch (logError) {
        console.error('Error handling quota error:', logError);
      }
      return;
    }
    
    if (isAuthError(error)) {
      const provider = openaiClient.defaultQuery?.provider || 'API provider';
      const details = error.response?.data?.error?.message || error.message;
      console.error(`[Auth Error] ${provider}:`, details);
      
      console.log('[streamNliThoughts] Yielding auth error event');
      yield {
        event: 'authError',
        text: `🔑 Authentication Error: ${details || 'Invalid API key'}. ` +
              'Please verify your API key in Settings > API Keys.'
      };
      
      yield {
        event: 'thoughtComplete',
        text: 'Authentication error occurred. Please check your API key settings.',
        isError: true,
        errorType: 'authError'
      };
      return;
    }
    
    // Handle all other errors
    console.log('[streamNliThoughts] Yielding general error event');
    yield {
      event: 'error',
      text: `❌ Error: ${error.message || 'An unknown error occurred'}. Please try again.`
    };
    
    yield {
      event: 'thoughtComplete',
      text: 'An error occurred while processing your request. Please try again.',
      isError: true,
      errorType: 'error'
    };
  }
}

const handleFinalResponse = async (userId, finalResponse) => {
  try {
    // Validate that the finalResponse is not empty
    if (!finalResponse || typeof finalResponse !== 'string' || finalResponse.trim().length === 0) {
      console.warn('[NLI] Empty or invalid response received, skipping persistence');
      // Still send WebSocket notification so UI shows the response is done processing
      sendWebSocketUpdate(userId, {
        event: 'nliResponsePersisted',
        content: 'Sorry, there was an issue processing your request. Please try again.'
      });
      return;
    }
    
    await Promise.all([
      // Store in Message collection for individual access
      Message.create({
        userId,
        content: finalResponse,
        role: 'assistant',
        type: 'system',  // Using validated enum value
        timestamp: new Date()
      }),
      
      // Append to ChatHistory for conversation context
      // CRITICAL: Add type:'system' to match Message collection and prevent duplicates
      ChatHistory.updateOne(
        { userId },
        { 
          $push: { 
            messages: { 
              role: 'assistant', 
              type: 'system', // Explicitly add type to match Message collection
              content: finalResponse,
              timestamp: new Date() 
            } 
          } 
        },
        { upsert: true }
      )
    ]);
    
    sendWebSocketUpdate(userId, {
      event: 'nliResponsePersisted',
      content: finalResponse
    });
  } catch (err) {
    console.error('[NLI] Error persisting final response:', err);
    // Consider adding retry logic here if needed
  }
};

// --- API: History endpoints ---
// History routes are now handled by historyRouter

// --- API: User Settings endpoints ---
app.get('/api/settings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const user = await User.findById(userId).exec();
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Extract only the settings information
    res.json({
      success: true,
      apiKeys: {
        gpt4o: user.apiKeys.gpt4o ? true : false,
        qwen: user.apiKeys.qwen ? true : false,
        gemini: user.apiKeys.gemini ? true : false,
        uitars: user.apiKeys.uitars ? true : false
      },
      preferredEngine: user.preferredEngine,
      executionMode: user.executionMode || 'step-planning',
      privacyMode: user.privacyMode || false,
      customUrls: user.customUrls || []
    });
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API endpoint for user API key management
app.post('/api/user/api-keys', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const { apiKeyType, apiKey } = req.body;
    
    if (!userId) {
      return res.status(401).json({ success: false, error: 'User not authenticated' });
    }
    
    // Validate key type against our supported engines
    const validKeyTypes = Object.values(ENGINE_KEY_MAPPING);
    if (!validKeyTypes.includes(apiKeyType)) {
      return res.status(400).json({ 
        success: false, 
        error: `Invalid API key type. Supported types are: ${validKeyTypes.join(', ')}` 
      });
    }
    
    // Validate provided key
    if (!apiKey || apiKey.trim().length < 8) {  // Most API keys are longer than 8 characters
      return res.status(400).json({ success: false, error: 'Invalid API key provided' });
    }
    
    // Find user
    const user = await User.findOne({ _id: userId });
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Make sure apiKeys object exists
    if (!user.apiKeys) {
      user.apiKeys = {};
    }
    
    // Update the appropriate key
    user.apiKeys[apiKeyType] = apiKey;
    await user.save();
    
    // Get the corresponding engine for this key type
    const engineId = KEY_ENGINE_MAPPING[apiKeyType];
    const engineName = getEngineDisplayName(engineId);
    
    // Send notification about key update
    sendWebSocketUpdate(userId, {
      event: 'notification',
      type: 'success',
      title: 'API Key Updated',
      message: `Your ${engineName} API key has been updated successfully`
    });
    
    res.json({ 
      success: true, 
      message: `${engineName} API key updated successfully`,
      engineId,
      keyType: apiKeyType  
    });
  } catch (error) {
    console.error('Error updating API key:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Delete user API key
app.delete('/api/user/api-keys', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const { apiKeyType } = req.body;
    
    if (!userId) {
      return res.status(401).json({ success: false, error: 'User not authenticated' });
    }
    
    // Validate key type against our supported engines
    const validKeyTypes = Object.values(ENGINE_KEY_MAPPING);
    if (!validKeyTypes.includes(apiKeyType)) {
      return res.status(400).json({ 
        success: false, 
        error: `Invalid API key type. Supported types are: ${validKeyTypes.join(', ')}` 
      });
    }
    
    // Find user
    const user = await User.findOne({ _id: userId });
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Check if the key exists before attempting to delete
    if (!user.apiKeys || !user.apiKeys[apiKeyType]) {
      return res.status(404).json({ success: false, error: 'API key not found' });
    }
    
    // Delete the key
    delete user.apiKeys[apiKeyType];
    await user.save();
    
    // Get the corresponding engine for this key type
    const engineId = KEY_ENGINE_MAPPING[apiKeyType];
    const engineName = getEngineDisplayName(engineId);
    
    // Send notification about key deletion
    sendWebSocketUpdate(userId, {
      event: 'notification',
      type: 'info',
      title: 'API Key Removed',
      message: `Your ${engineName} API key has been removed`
    });
    
    res.json({ 
      success: true, 
      message: `${engineName} API key deleted successfully`,
      engineId,
      keyType: apiKeyType
    });
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// API endpoint to set user's execution mode preference
app.post('/api/user/set-execution-mode', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const { mode } = req.body;
    
    if (!userId) {
      return res.status(401).json({ success: false, error: 'User not authenticated' });
    }
    
    // Validate execution mode
    const validModes = ['step-planning', 'action-planning'];
    if (!validModes.includes(mode)) {
      return res.status(400).json({ success: false, error: 'Invalid execution mode' });
    }
    
    // Find user
    const user = await User.findOne({ _id: userId });
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Update the user's execution mode
    user.executionMode = mode;
    await user.save();
    
    // Send notification about mode update
    sendWebSocketUpdate(userId, {
      event: 'notification',
      type: 'success',
      title: 'Execution Mode Updated',
      message: `Your execution mode has been set to ${mode === 'step-planning' ? 'Step Planning' : 'Action Planning (Autopilot)'}`
    });
    
    res.json({
      success: true,
      message: `Execution mode set to ${mode}`
    });
  } catch (error) {
    console.error('Error setting execution mode:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/settings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const { action } = req.body;
    const user = await User.findById(userId).exec();
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    // Handle different types of settings updates
    switch (action) {
      case 'saveApiKey':
        const { provider, key } = req.body;
        
        if (!provider || !key) {
          return res.status(400).json({ success: false, error: 'Provider and key are required' });
        }
        
        // Initialize apiKeys if it doesn't exist
        if (!user.apiKeys) {
          user.apiKeys = {};
        }
        
        // Save API key
        user.apiKeys[provider] = key;
        await user.save();
        
        return res.json({ success: true, message: `${provider} API key saved successfully` });

      case 'saveLlmPreferences':
        const { models } = req.body;
        
        if (!models) {
          return res.status(400).json({ success: false, error: 'Model preferences are required' });
        }
        
        // Initialize llmPreferences if it doesn't exist
        if (!user.llmPreferences) {
          user.llmPreferences = {};
        }
        
        // Update LLM preferences
        user.llmPreferences = {
          ...user.llmPreferences,
          ...models
        };
        
        await user.save();
        
        return res.json({ success: true, message: 'LLM preferences saved successfully' });
        
      default:
        return res.status(400).json({ success: false, error: 'Invalid action' });
    }
  } catch (error) {
    console.error('Error updating user settings:', error);
    return res.status(500).json({ success: false, error: 'Failed to update user settings' });
  }
});

app.delete('/api/settings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user;
    const { action, provider } = req.body;
    const user = await User.findById(userId).exec();
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (action === 'deleteApiKey') {
      if (!provider) {
        return res.status(400).json({ success: false, error: 'Provider is required' });
      }
      
      // Check if apiKeys and the specific provider key exist
      if (user.apiKeys && user.apiKeys[provider]) {
        // Delete the key
        delete user.apiKeys[provider];
        await user.save();
        
        return res.json({ success: true, message: `${provider} API key deleted successfully` });
      } else {
        return res.status(404).json({ success: false, error: 'API key not found' });
      }
    } else {
      return res.status(400).json({ success: false, error: 'Invalid action' });
    }
  } catch (error) {
    console.error('Error deleting API key:', error);
    return res.status(500).json({ success: false, error: 'Failed to delete API key' });
  }
});


// Serve static assets - this should be the last middleware
serveStaticAssets(app);

// ======================================
// CATCH-ALL ROUTE AND ERROR HANDLERS
// These must be the last routes in the file
// ======================================

// API 404 handler - catches any undefined API routes
app.use('/api/*', api404Handler);

// SPA catch-all route - serves index.html for client-side routing
app.get('*', spaCatchAll);

// 404 handler for all other routes
app.use(html404Handler);

// Error handling middleware (in order of execution)
app.use(errorHandler1);
app.use(errorHandler2);
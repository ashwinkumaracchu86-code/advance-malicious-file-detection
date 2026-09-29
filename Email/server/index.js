import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import express from 'express';
import { WebSocketServer } from 'ws';
import { EmailStore } from './store.js';
import { EmailMonitor } from './monitor.js';
import { createRoutes, buildStatus } from './routes.js';
import { summarize } from './parser.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

function pinMatches(provided, pin) {
  if (!pin) return true;
  const a = crypto.createHash('sha256').update(String(provided || '')).digest();
  const b = crypto.createHash('sha256').update(pin).digest();
  return crypto.timingSafeEqual(a, b);
}

export function createApp({ store, monitor, pin = process.env.DASHBOARD_PIN || '' }) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader(
      'Content-Security-Policy',
      "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    );
    next();
  });

  if (pin) {
    app.use('/api', (req, res, next) => {
      const provided = req.get('x-pin') || '';
      if (pinMatches(provided, pin)) return next();
      res.status(401).json({ error: 'Dashboard PIN required.', code: 'pin_required' });
    });
  }

  app.use('/api', createRoutes({ store, monitor }));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Server/API error: endpoint not found.', code: 'not_found' }));

  app.use(express.static(PUBLIC_DIR, { index: 'index.html' }));
  app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err && err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Server/API error: invalid JSON body.', code: 'bad_request' });
    }
    const status = (err && (err.status || err.statusCode)) || 500;
    if (status >= 500) console.error(`[api] ${err?.message || err}`);
    res.status(status).json({
      error: status >= 500 ? `Server/API error: ${err?.message || 'unexpected failure'}` : err?.message || 'Invalid request.',
      code: (err && err.code) || (status >= 500 ? 'server_error' : 'bad_request'),
    });
  });

  return app;
}

function start() {
  const port = parseInt(process.env.PORT, 10) || 4000;
  const pin = process.env.DASHBOARD_PIN || '';
  const store = new EmailStore();
  const monitor = new EmailMonitor(store);
  const app = createApp({ store, monitor, pin });
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  const broadcast = (payload) => {
    const data = JSON.stringify(payload);
    for (const client of wss.clients) {
      if (client.readyState === client.OPEN) client.send(data);
    }
  };

  wss.on('connection', (ws, req) => {
    const url = new URL(req.url || '/ws', 'http://localhost');
    if (!pinMatches(url.searchParams.get('pin') || '', pin)) {
      ws.close(4401, 'pin required');
      return;
    }
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });
    ws.send(JSON.stringify({ type: 'status', data: buildStatus(store, monitor) }));
    ws.send(JSON.stringify({ type: 'emails:initial', data: store.list(50, 0).map(summarize) }));
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.isAlive === false) {
        ws.terminate();
        continue;
      }
      ws.isAlive = false;
      ws.ping();
    }
  }, 30000);
  if (typeof heartbeat.unref === 'function') heartbeat.unref();

  monitor.on('status', () => broadcast({ type: 'status', data: buildStatus(store, monitor) }));
  monitor.on('email', (email) => broadcast({ type: 'email:new', data: summarize(email) }));

  server.listen(port, () => {
    console.log(`[email-monitor] dashboard listening on http://localhost:${port}`);
  });

  // Attempt to start monitoring on boot when an account is configured.
  monitor.start().catch((err) => console.error(`[monitor] startup failed: ${err.message}`));

  const shutdown = async () => {
    console.log('\n[email-monitor] shutting down...');
    clearInterval(heartbeat);
    try {
      await monitor.stop();
    } catch {
      /* ignore */
    }
    wss.close();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return { server, store, monitor };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start();
}

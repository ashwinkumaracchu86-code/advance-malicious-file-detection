import { Router } from 'express';
import { getPublicSettings, saveSettings } from './config.js';
import { summarize } from './parser.js';

export function buildStatus(store, monitor) {
  const s = monitor.getStatus();
  return {
    monitoring: s.state === 'active' ? 'active' : 'inactive',
    state: s.state,
    code: s.code,
    message: s.message,
    configured: s.configured,
    mailbox: s.mailbox,
    startedAt: s.startedAt,
    totalEmails: store.count(),
    storedEmails: store.storedCount(),
    lastEmailAt: store.lastEmailAt(),
    time: new Date().toISOString(),
  };
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function clampInt(value, def, min, max) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) return def;
  return Math.min(max, Math.max(min, n));
}

export function createRoutes({ store, monitor }) {
  const router = Router();

  router.get('/status', (req, res) => {
    res.json(buildStatus(store, monitor));
  });

  router.get('/emails', (req, res) => {
    const limit = clampInt(req.query.limit, 50, 1, 200);
    const offset = clampInt(req.query.offset, 0, 0, 1_000_000);
    res.json({
      total: store.storedCount(),
      totalReceived: store.count(),
      emails: store.list(limit, offset).map(summarize),
    });
  });

  router.get('/emails/:id', (req, res) => {
    const email = store.get(req.params.id);
    if (!email) return res.status(404).json({ error: 'Email not found.', code: 'not_found' });
    res.json(email);
  });

  router.get('/settings', (req, res) => {
    res.json(getPublicSettings());
  });

  router.post(
    '/settings',
    wrap(async (req, res) => {
      const saved = saveSettings(req.body || {});
      res.json({ ok: true, settings: saved, message: 'Settings saved. Monitoring restarted.' });
      monitor.restart().catch((err) => console.error(`[monitor] restart failed: ${err.message}`));
    }),
  );

  router.post(
    '/monitor/start',
    wrap(async (req, res) => {
      await monitor.start();
      res.json({ ok: true, status: buildStatus(store, monitor) });
    }),
  );

  router.post(
    '/monitor/stop',
    wrap(async (req, res) => {
      await monitor.stop();
      res.json({ ok: true, status: buildStatus(store, monitor) });
    }),
  );

  router.post(
    '/monitor/refresh',
    wrap(async (req, res) => {
      const result = await monitor.refresh();
      res.json({ ok: true, ...result, status: buildStatus(store, monitor) });
    }),
  );

  return router;
}

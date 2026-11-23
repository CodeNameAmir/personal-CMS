import dotenv from 'dotenv';
import express from 'express';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';

dotenv.config();
dotenv.config({ path: '.env.local', override: true });

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.set('trust proxy', true);

  // Exposes ONLY public Supabase client config for local preview when configured via server env/Secrets.
  // Never exposes SUPABASE_SECRET_KEY or service_role keys.
  app.get('/api/config', (_req, res) => {
    const supabaseUrl = (process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '').trim();
    const supabasePublishableKey = (
      process.env.VITE_SUPABASE_PUBLISHABLE_KEY ||
      process.env.SUPABASE_PUBLISHABLE_KEY ||
      process.env.SUPABASE_ANON_KEY ||
      ''
    ).trim();

    res.json({
      supabaseUrl,
      supabasePublishableKey,
      supabaseConfigured: Boolean(supabaseUrl && supabasePublishableKey),
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Logbook preview server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

import { env } from './env.js';
import { buildServer } from './server.js';
import { closeDb } from './db/index.js';

async function main(): Promise<void> {
  const app = await buildServer();

  // Last-resort process guards. Log safely (no raw dumps to stdout) and, for
  // truly unexpected faults, exit non-zero so the orchestrator can restart us.
  process.on('unhandledRejection', (reason) => {
    app.log.error(
      { reason: reason instanceof Error ? reason.message : String(reason) },
      'unhandledRejection',
    );
  });
  process.on('uncaughtException', (err) => {
    app.log.error({ err: err.message }, 'uncaughtException — exiting');
    process.exit(1);
  });

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');
    // Enforce a hard timeout so a hung connection can't block container exit.
    const timer = setTimeout(() => {
      app.log.error('graceful shutdown timed out — forcing exit');
      process.exit(1);
    }, env.SHUTDOWN_TIMEOUT_MS);
    timer.unref();
    try {
      await app.close();
      await closeDb();
      process.exit(0);
    } catch (err) {
      app.log.error({ err: (err as Error).message }, 'error during shutdown');
      process.exit(1);
    }
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  try {
    await app.listen({ port: env.PORT, host: env.HOST });
    const scheme = env.HTTPS_CERT && env.HTTPS_KEY ? 'https' : 'http';
    app.log.info(`AgentAuth listening on ${scheme}://${env.HOST}:${env.PORT}`);
  } catch (err) {
    app.log.error({ err: (err as Error).message }, 'failed to start');
    process.exit(1);
  }
}

void main();

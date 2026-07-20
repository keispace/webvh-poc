import { createApp } from './app.js';
import { loadConfig } from './config.js';

const { app } = await createApp(loadConfig());
try {
  const response = await app.inject({ method: 'POST', url: '/api/demo/run' });
  if (response.statusCode !== 200) {
    throw new Error(`Demo failed (${response.statusCode}): ${response.body}`);
  }
  process.stdout.write(`${JSON.stringify(response.json(), null, 2)}\n`);
} finally {
  await app.close();
}

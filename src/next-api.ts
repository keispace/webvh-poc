import type { FastifyInstance } from 'fastify';
import { loadConfig } from './config';
import { createApp } from './webvh-app';

let appPromise: Promise<FastifyInstance> | undefined;

async function getApp(): Promise<FastifyInstance> {
  appPromise ??= createApp(loadConfig(), { includeUi: false }).then(({ app }) => app);
  return appPromise;
}

function requestHeaders(request: Request): Record<string, string> {
  return Object.fromEntries(request.headers.entries());
}

function responseHeaders(headers: Record<string, string | number | string[] | undefined>): Headers {
  const result = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || name.toLowerCase() === 'content-length') continue;
    result.set(name, Array.isArray(value) ? value.join(', ') : String(value));
  }
  return result;
}

export async function dispatchNextRequest(request: Request, path: string): Promise<Response> {
  const app = await getApp();
  const method: 'GET' | 'POST' = request.method === 'POST' ? 'POST' : 'GET';
  const payload = method === 'GET' ? undefined : await request.text();
  const response = await app.inject({
    method,
    url: path,
    headers: requestHeaders(request),
    ...(payload === undefined ? {} : { payload }),
  });

  return new Response(response.body, {
    status: response.statusCode,
    headers: responseHeaders(response.headers),
  });
}

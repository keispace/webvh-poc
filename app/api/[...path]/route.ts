import { dispatchNextRequest } from '../../../src/next-api';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type RouteContext = { params: Promise<{ path: string[] }> };

async function handle(request: Request, context: RouteContext): Promise<Response> {
  const { path } = await context.params;
  const url = new URL(request.url);
  return dispatchNextRequest(request, `/api/${path.join('/')}${url.search}`);
}

export const GET = handle;
export const POST = handle;

import { dispatchNextRequest } from '../../src/next-api';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type RouteContext = { params: Promise<{ path: string[] }> };

export async function GET(request: Request, context: RouteContext): Promise<Response> {
  const { path } = await context.params;
  const url = new URL(request.url);
  return dispatchNextRequest(request, `/${path.join('/')}${url.search}`);
}

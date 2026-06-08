// web-frontend/src/pages/api/sat/issue.ts
export const prerender = false;
import type { APIRoute } from 'astro';

const AUTH_URL = process.env.AUTH_SERVICE_URL ?? 'http://localhost:4000';

export const POST: APIRoute = async ({ request }) => {
  const body = await request.json();
  const cookie = request.headers.get('cookie') ?? '';

  const res = await fetch(`${AUTH_URL}/sat/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Cookie': cookie },
    body: JSON.stringify(body),
  });

  const data = await res.json();
  return new Response(JSON.stringify(data), {
    status: res.status,
    headers: { 'Content-Type': 'application/json' },
  });
};
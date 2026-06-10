// web-frontend/src/pages/api/users/index.ts
export const prerender = false;
import type { APIRoute } from 'astro';

const AUTH_URL = process.env.AUTH_SERVICE_URL ?? 'http://localhost:4000';

export const GET: APIRoute = async ({ request }) => {
  const cookie = request.headers.get('cookie') ?? '';
  const res = await fetch(`${AUTH_URL}/users`, {
    headers: { 'Cookie': cookie },
  });
  const data = await res.json();
  return new Response(JSON.stringify(data), {
    status: res.status,
    headers: { 'Content-Type': 'application/json' },
  });
};

export const POST: APIRoute = async ({ request }) => {
  const cookie = request.headers.get('cookie') ?? '';
  const body = await request.json();
  const res = await fetch(`${AUTH_URL}/users`, {
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
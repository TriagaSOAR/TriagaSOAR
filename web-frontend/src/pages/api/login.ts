// web-frontend/src/pages/api/login.ts
export const prerender = false;

import type { APIRoute } from 'astro';

const AUTH_URL = process.env.AUTH_SERVICE_URL ?? 'http://localhost:4000';

export const POST: APIRoute = async ({ request, cookies }) => {
  const body = await request.json();

  const res = await fetch(`${AUTH_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await res.json();

  // Forward the Set-Cookie header from auth to the browser
  const setCookie = res.headers.get('set-cookie');
  const headers = new Headers({ 'Content-Type': 'application/json' });
  if (setCookie) {
    headers.set('set-cookie', setCookie);
  }

  return new Response(JSON.stringify(data), {
    status: res.status,
    headers,
  });
};
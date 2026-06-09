// web-frontend/src/pages/api/logout.ts
export const prerender = false;
import type { APIRoute } from 'astro';

const AUTH_URL = process.env.AUTH_SERVICE_URL ?? 'http://localhost:4000';

export const POST: APIRoute = async ({ request }) => {
  const cookie = request.headers.get('cookie') ?? '';

  await fetch(`${AUTH_URL}/auth/logout`, {
    method: 'POST',
    headers: { 'Cookie': cookie },
  }).catch(() => {});

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'soc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
    },
  });
};